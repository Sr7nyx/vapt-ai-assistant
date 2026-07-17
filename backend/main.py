"""FastAPI backend for the VAPT assistant (multi-tenant, Postgres + Google auth).

Wraps the framework-agnostic brain modules (gemini_client, scan_import, risk_map,
cve_enrich, exporter) and exposes them as a per-user HTTP API for a Next.js
frontend. Data lives in Supabase Postgres via pg_store; every request is
authenticated with a Google ID token (auth.get_current_user) and every query is
scoped to that user, so accounts are isolated.

Deploy on a PERSISTENT container host (Render/Railway/Fly), not Vercel serverless:
analyze/triage run for minutes and use background threads, which serverless kills.
Put the Next.js app on Vercel and set FRONTEND_ORIGINS to its origin.

Local run:
    pip install -r requirements.txt
    export DATABASE_URL=postgresql://...        # Supabase pooled connection string
    export GOOGLE_CLIENT_ID=...apps.googleusercontent.com
    export VAPT_MAIN_API_KEY=sk-or-...           # or send api_key per request
    export VAPT_AUTH_DISABLED=true               # dev only: bypass Google auth
    uvicorn main:app --reload --port 8000
"""
import os
import uuid
import tempfile
import threading
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

import gemini_client
import scan_import
import risk_map
import qa_utils
import exporter
from collections import Counter
import pg_store as store
from auth import get_current_user, User


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init()
    yield


app = FastAPI(title="VAPT Assistant API", version="2.0.0", lifespan=lifespan)

_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Schemas -----------------------------------------------------------------
class ProjectIn(BaseModel):
    name: str
    client: str = ""
    scope: str = ""
    tester: str = ""
    start_date: str = ""
    end_date: str = ""


class AnalyzeIn(BaseModel):
    analysis_type: str
    raw_input: str
    api_key: Optional[str] = None


class FindingIn(BaseModel):
    data: Dict[str, Any]


class CommitIn(BaseModel):
    candidates: List[Dict[str, Any]]


class RetestIn(BaseModel):
    retest_status: str
    retester: str = ""
    retest_date: str = ""
    retest_evidence: str = ""
    note: str = ""


class TriageIn(BaseModel):
    candidates: List[Dict[str, Any]]
    api_key: Optional[str] = None


class ReportIn(BaseModel):
    fmt: str = "docx"
    exec_summary: str = ""
    methodology: str = ""


# --- Helpers -----------------------------------------------------------------
def _api_key(explicit: Optional[str]) -> str:
    return (explicit or os.environ.get("VAPT_MAIN_API_KEY") or "").strip()


def _require_project(user: User, project_id: int) -> dict:
    project = store.get_project(user.id, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _dupe_key(x: dict):
    return (
        (x.get("title") or "").strip().lower(),
        (x.get("affected_host") or "").strip().lower(),
        (x.get("affected_url") or "").strip().lower(),
        (x.get("parameter") or "").strip().lower(),
    )


# --- In-memory job store -----------------------------------------------------
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _new_job(user_id: str) -> str:
    jid = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[jid] = {
            "id": jid, "user_id": user_id, "status": "running", "progress": 0.0,
            "stage": "Starting", "result": None, "error": None, "done": False,
        }
    return jid


def _job(jid: str) -> Optional[Dict[str, Any]]:
    with _jobs_lock:
        return _jobs.get(jid)


# --- Meta --------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    # Base URL -> interactive API docs (avoids a bare 404 at "/").
    return RedirectResponse(url="/docs")


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email}


@app.get("/usage")
def usage(user: User = Depends(get_current_user)):
    return store.get_usage_summary(user.id)


@app.get("/overview")
def overview(user: User = Depends(get_current_user)):
    """Aggregate dashboard across ALL of the user's projects: severity/status/
    category breakdowns, risk priorities, OWASP 2025 coverage, QA verification
    flags, and usage."""
    projects = store.get_projects(user.id)
    findings = []
    for p in projects:
        findings.extend(store.get_findings_by_project(user.id, p["id"]))

    by_severity = Counter((f.get("severity") or "Unknown") for f in findings)
    by_status = Counter((f.get("status") or "Unknown") for f in findings)
    by_category = Counter((f.get("category") or "Uncategorized") for f in findings)

    risk = Counter()
    owasp = Counter()
    qa_flags = 0
    for f in findings:
        risk[risk_map.compute_risk_priority(f)["priority"]] += 1
        fw = risk_map.map_frameworks(f)
        label = fw["owasp"] if fw.get("mapped") and fw.get("owasp") else "Unmapped (assign manually)"
        owasp[label] += 1
        if qa_utils.summarize_qa(f).get("warnings"):
            qa_flags += 1

    sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev_sorted = sorted(by_severity.items(), key=lambda kv: sev_order.index(kv[0]) if kv[0] in sev_order else 99)

    def rows(items):
        return [{"label": k, "count": v} for k, v in items]

    return {
        "projects": len(projects),
        "findings": len(findings),
        "critical": by_severity.get("Critical", 0),
        "high": by_severity.get("High", 0),
        "by_severity": rows(sev_sorted),
        "by_status": rows(by_status.most_common()),
        "by_category": rows(by_category.most_common()),
        "risk_priorities": {p: risk.get(p, 0) for p in ["Urgent", "High", "Moderate", "Low"]},
        "owasp_coverage": rows(sorted(owasp.items(), key=lambda kv: (kv[0] == "Unmapped (assign manually)", kv[0]))),
        "qa_flags": qa_flags,
        "usage": store.get_usage_summary(user.id),
    }


# --- Projects ----------------------------------------------------------------
@app.get("/projects")
def list_projects(user: User = Depends(get_current_user)):
    return store.get_projects(user.id)


@app.post("/projects")
def create_project(body: ProjectIn, user: User = Depends(get_current_user)):
    pid = store.create_project(
        user.id, body.name, body.client, body.scope, body.tester or user.email,
        body.start_date, body.end_date,
    )
    return store.get_project(user.id, pid)


@app.get("/projects/{project_id}")
def get_project(project_id: int, user: User = Depends(get_current_user)):
    return _require_project(user, project_id)


@app.delete("/projects/{project_id}")
def delete_project(project_id: int, user: User = Depends(get_current_user)):
    _require_project(user, project_id)
    store.delete_project(user.id, project_id)
    return {"ok": True}


# --- Findings ----------------------------------------------------------------
@app.get("/projects/{project_id}/findings")
def list_findings(project_id: int, user: User = Depends(get_current_user)):
    _require_project(user, project_id)
    findings = store.get_findings_by_project(user.id, project_id)
    for f in findings:
        f["_assessment"] = risk_map.assess(f)
    return findings


@app.post("/projects/{project_id}/findings")
def create_finding(project_id: int, body: FindingIn, user: User = Depends(get_current_user)):
    _require_project(user, project_id)
    fid = store.create_finding(user.id, project_id, body.data)
    return {"id": fid}


@app.post("/projects/{project_id}/findings/commit")
def commit_candidates(project_id: int, body: CommitIn, user: User = Depends(get_current_user)):
    """Bulk-commit scanner candidates with asset-aware dedup: skip only true
    duplicates (title + host + url + parameter) already in the project, so the
    same issue on different URLs stays distinct."""
    _require_project(user, project_id)
    existing_keys = {_dupe_key(e) for e in store.get_findings_by_project(user.id, project_id)}
    committed = 0
    skipped = 0
    for c in body.candidates:
        key = _dupe_key(c)
        if key in existing_keys:
            skipped += 1
            continue
        payload = {k: v for k, v in c.items() if k not in ("_uid", "noise", "source", "scanner_confidence", "_risk")}
        store.create_finding(user.id, project_id, payload)
        existing_keys.add(key)
        committed += 1
    return {"committed": committed, "skipped": skipped}


@app.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingIn, user: User = Depends(get_current_user)):
    if not store.update_finding(user.id, finding_id, body.data):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


@app.delete("/findings/{finding_id}")
def delete_finding(finding_id: int, user: User = Depends(get_current_user)):
    if not store.delete_finding(user.id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


@app.post("/findings/{finding_id}/retest")
def retest_finding(finding_id: int, body: RetestIn, user: User = Depends(get_current_user)):
    ok = store.set_retest_result(
        user.id, finding_id, body.retest_status, body.retester,
        body.retest_date, body.retest_evidence, body.note,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


# --- Analyze (background job) ------------------------------------------------
def _run_analyze(jid: str, user_id: str, api_key: str, analysis_type: str, raw_input: str):
    job = _job(jid)
    try:
        usage_records: List[dict] = []

        def cb(fraction, message):
            job["progress"] = max(0.0, min(1.0, float(fraction)))
            job["stage"] = str(message)

        findings = gemini_client.analyze_vapt_data(
            api_key, analysis_type, raw_input, usage_sink=usage_records, progress_cb=cb,
        )
        try:
            store.record_usage_batch(user_id, usage_records)
        except Exception:
            pass
        job["result"] = findings
        job["status"] = "done"
        job["progress"] = 1.0
        job["stage"] = "Complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
    finally:
        job["done"] = True


@app.post("/analyze")
def analyze(body: AnalyzeIn, user: User = Depends(get_current_user)):
    key = _api_key(body.api_key)
    if not key:
        raise HTTPException(status_code=400, detail="No LLM API key configured")
    jid = _new_job(user.id)
    threading.Thread(
        target=_run_analyze, args=(jid, user.id, key, body.analysis_type, body.raw_input), daemon=True,
    ).start()
    return {"job_id": jid}


# --- Scanner import ----------------------------------------------------------
@app.post("/scan/parse")
async def scan_parse(files: List[UploadFile] = File(...), user: User = Depends(get_current_user)):
    all_candidates: List[dict] = []
    per_file: List[dict] = []
    warnings: List[str] = []
    for uf in files:
        data = await uf.read()
        try:
            fmt, cands, warns = scan_import.detect_and_parse(uf.filename, data)
        except Exception as exc:
            fmt, cands, warns = "Error", [], [f"parser error: {exc}"]
        per_file.append({"file": uf.filename, "format": fmt, "count": len(cands)})
        warnings.extend(f"{uf.filename}: {w}" for w in warns)
        all_candidates.extend(cands)

    deduped, removed = scan_import.dedupe(all_candidates)
    deduped = scan_import.sort_candidates(deduped)
    for i, c in enumerate(deduped):
        c["_uid"] = f"scan_{i}"
        c["_risk"] = risk_map.compute_risk_priority(c)["priority"]
    return {
        "candidates": deduped, "removed": removed, "per_file": per_file,
        "warnings": warnings, "summary": scan_import.summarize(deduped),
    }


# --- Triage (background job) -------------------------------------------------
def _run_triage(jid: str, user_id: str, api_key: str, candidates: List[dict]):
    job = _job(jid)
    try:
        usage_records: List[dict] = []

        def cb(fraction, message):
            job["progress"] = max(0.0, min(1.0, float(fraction)))
            job["stage"] = str(message)

        result = gemini_client.triage_findings(api_key, candidates, usage_sink=usage_records, progress_cb=cb)
        try:
            store.record_usage_batch(user_id, usage_records)
        except Exception:
            pass
        job["result"] = result
        job["status"] = "done"
        job["progress"] = 1.0
        job["stage"] = "Complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
    finally:
        job["done"] = True


@app.post("/scan/triage")
def scan_triage(body: TriageIn, user: User = Depends(get_current_user)):
    key = _api_key(body.api_key)
    if not key:
        raise HTTPException(status_code=400, detail="No LLM API key configured")
    jid = _new_job(user.id)
    threading.Thread(target=_run_triage, args=(jid, user.id, key, body.candidates), daemon=True).start()
    return {"job_id": jid}


# --- Job status --------------------------------------------------------------
@app.get("/jobs/{job_id}")
def job_status(job_id: str, user: User = Depends(get_current_user)):
    job = _job(job_id)
    if not job or job.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# --- Report export -----------------------------------------------------------
@app.post("/projects/{project_id}/report")
def export_report(project_id: int, body: ReportIn, user: User = Depends(get_current_user)):
    project = _require_project(user, project_id)
    findings = store.get_findings_by_project(user.id, project_id)

    fmt = (body.fmt or "docx").lower()
    tmp_dir = tempfile.mkdtemp()
    path = os.path.join(tmp_dir, f"report.{fmt}")

    if fmt == "docx":
        exporter.export_to_docx(project, findings, body.exec_summary, body.methodology, path)
        media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif fmt == "pdf":
        exporter.export_to_pdf(project, findings, body.exec_summary, body.methodology, path)
        media = "application/pdf"
    elif fmt == "xlsx":
        exporter.export_to_excel(project, findings, path)
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "json":
        exporter.export_to_json(project, findings, body.exec_summary, body.methodology, path)
        media = "application/json"
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")

    safe_name = (project.get("name") or "report").replace("/", "_").replace("\\", "_")
    return FileResponse(path, media_type=media, filename=f"{safe_name}.{fmt}")
