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

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

import requests
from urllib.parse import urlparse
from openai import OpenAI

import gemini_client
import llm_config
import scan_import
import risk_map
import qa_utils
import verdict_engine
import verifiers
import input_guard
import exporter
import report_html
import finding_identity
from collections import Counter
import pg_store as store
from auth import get_current_user, User


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init()
    # Jobs still marked running are from a process that no longer exists. Left
    # alone they present as a spinner that never resolves.
    store.reap_stale_jobs()
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


class LaneCfgIn(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    models: Optional[List[str]] = None


class ProviderIn(BaseModel):
    base_url: str
    api_key: str
    model: Optional[str] = None
    lane: Optional[str] = None
    lane_config: Optional[Dict[str, "LaneCfgIn"]] = None


class AnalyzeIn(BaseModel):
    analysis_type: str
    raw_input: str
    api_key: Optional[str] = None
    lane_config: Optional[Dict[str, LaneCfgIn]] = None


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
    lane_config: Optional[Dict[str, LaneCfgIn]] = None


class ReportIn(BaseModel):
    fmt: str = "docx"
    exec_summary: str = ""
    methodology: str = ""
    finding_ids: Optional[List[int]] = None


# --- Helpers -----------------------------------------------------------------
def _api_key(explicit: Optional[str]) -> str:
    return (explicit or os.environ.get("VAPT_MAIN_API_KEY") or "").strip()


def _lanes(raw) -> dict:
    """Validate a caller-supplied per-lane provider config (SSRF-checked)."""
    try:
        return llm_config.sanitize_lane_config(
            {k: v.model_dump() for k, v in (raw or {}).items()}
        )
    except llm_config.ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# Demo quota. The shared server key sits on a free provider tier, so a single
# enthusiastic visitor could exhaust it for everyone. Runs that use the shared
# key are capped per user over a rolling window; runs on a user's own key are
# not counted at all, so supplying a key is the way to keep going.
DEMO_LIMIT = int(os.environ.get("VAPT_DEMO_RUN_LIMIT", "5") or 5)
DEMO_WINDOW_HOURS = int(os.environ.get("VAPT_DEMO_WINDOW_HOURS", "24") or 24)


def _uses_server_key(explicit_key: Optional[str], lanes: dict) -> bool:
    """True when this request will be billed to the server's shared key."""
    if (explicit_key or "").strip():
        return False
    for cfg in (lanes or {}).values():
        if (cfg or {}).get("api_key"):
            return False
    return True


def _enforce_demo_limit(user_id: str, kind: str, explicit_key: Optional[str], lanes: dict) -> None:
    """Raise 429 when a user has spent their shared-key allowance."""
    if not _uses_server_key(explicit_key, lanes):
        return
    if DEMO_LIMIT <= 0:
        return
    used = store.count_demo_runs(user_id, DEMO_WINDOW_HOURS)
    if used >= DEMO_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "demo_limit_reached",
                "message": (
                    f"You have used all {DEMO_LIMIT} demo runs for the shared key in the last "
                    f"{DEMO_WINDOW_HOURS} hours. Add your own provider API key in Settings to "
                    "continue with your own quota."
                ),
                "limit": DEMO_LIMIT,
                "used": used,
                "window_hours": DEMO_WINDOW_HOURS,
            },
        )
    store.record_demo_run(user_id, kind)


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
    try:
        store.create_job(jid, user_id, kind="analyze")
    except Exception:
        # A job that cannot be recorded should still run. The in-memory copy is
        # what serves this request; the row is what survives a restart.
        pass
    with _jobs_lock:
        _jobs[jid] = {
            "id": jid, "user_id": user_id, "status": "running", "progress": 0.0,
            "stage": "Starting", "result": None, "error": None, "done": False,
            # Every stage message, in order. The client polls about once a second
            # while stages can pass in milliseconds, so keeping only the latest
            # would drop most of the run. Bounded so a long job cannot grow it
            # without limit.
            "log": [],
        }
    return jid


def _job(jid: str) -> Optional[Dict[str, Any]]:
    with _jobs_lock:
        job = _jobs.get(jid)
    if job is not None:
        return job
    return None


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


# Windows the UI offers, mapped to hours. Bounded on purpose: an arbitrary
# caller-supplied interval is a needless surface on an aggregate query.
USAGE_WINDOWS = {"1h": 1, "24h": 24, "7d": 168, "30d": 720, "all": 0}


@app.get("/usage")
def usage(window: str = "all", user: User = Depends(get_current_user)):
    hours = USAGE_WINDOWS.get((window or "all").lower())
    if hours is None:
        raise HTTPException(
            status_code=400,
            detail=f"window must be one of: {', '.join(USAGE_WINDOWS)}",
        )
    out = store.get_usage_summary(user.id, hours or None)
    out["window"] = (window or "all").lower()
    return out


@app.get("/demo/quota")
def demo_quota(user: User = Depends(get_current_user)):
    """Shared-key allowance for this user. Irrelevant once they supply their own
    key, which the UI uses to decide whether to show the banner at all."""
    used = store.count_demo_runs(user.id, DEMO_WINDOW_HOURS)
    return {
        "limit": DEMO_LIMIT,
        "used": used,
        "remaining": max(0, DEMO_LIMIT - used),
        "window_hours": DEMO_WINDOW_HOURS,
    }


class LanesIn(BaseModel):
    lane_config: Optional[Dict[str, LaneCfgIn]] = None


@app.post("/llm/lanes")
def llm_lanes(body: LanesIn, user: User = Depends(get_current_user)):
    """Which provider and model each lane will actually use for this caller.

    Resolution is delegated to the client module so the reported configuration
    cannot drift from the one the pipeline uses. No key is ever returned, only
    whether one is present and where it came from.
    """
    lanes = _lanes(body.lane_config)
    server_key = os.environ.get("VAPT_MAIN_API_KEY", "")
    with gemini_client.lane_config(lanes):
        resolved = gemini_client.describe_lanes(server_key)
    for name, info in resolved.items():
        supplied = bool((lanes.get(name) or {}).get("api_key"))
        if supplied:
            info["key_source"] = "your key"
        elif info["key_configured"]:
            info["key_source"] = "server key"
        elif not info.get("shares_main_provider", True):
            # A different provider with no key of its own: name the variable that
            # is missing rather than leaving a bare 401 to be decoded later.
            info["key_source"] = f"missing (set VAPT_{name}_API_KEY for {info['provider']})"
        else:
            info["key_source"] = "none"
        info["overridden"] = bool(lanes.get(name))
    return {"lanes": resolved}


@app.get("/llm/providers")
def llm_providers(user: User = Depends(get_current_user)):
    """Provider hosts this server will call. User-supplied base URLs are
    restricted to these to prevent SSRF."""
    return {"allowed_hosts": sorted(llm_config.allowed_hosts())}


@app.post("/llm/models")
def llm_models(body: ProviderIn, user: User = Depends(get_current_user)):
    """List the models a provider exposes, so the UI can offer a real dropdown
    instead of asking the user to type a model id from memory."""
    try:
        base_url = llm_config.validate_base_url(body.base_url)
    except llm_config.ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    key = (body.api_key or "").strip() or os.environ.get("VAPT_MAIN_API_KEY", "")
    if not key:
        raise HTTPException(status_code=400, detail="An API key is required to list models.")
    try:
        resp = requests.get(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=20,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach provider: {exc}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=f"Provider rejected the request: {resp.text[:200]}")
    try:
        payload = resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Provider returned an unreadable response.")
    items = payload.get("data") if isinstance(payload, dict) else payload
    models = []
    for item in items or []:
        name = item.get("id") if isinstance(item, dict) else str(item)
        if name:
            models.append(name)
    return {"models": sorted(set(models))}


@app.post("/llm/test")
def llm_test(body: ProviderIn, user: User = Depends(get_current_user)):
    """Make one tiny completion so configuration errors surface here, in a second,
    instead of three minutes into an analysis job."""
    try:
        base_url = llm_config.validate_base_url(body.base_url)
    except llm_config.ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not body.model:
        raise HTTPException(status_code=400, detail="A model is required to test.")
    # Resolve the key exactly as the pipeline would for this lane. Falling back to
    # the extraction key regardless of lane would test the reviewer's provider with
    # the extraction provider's credential and report a false failure.
    lane = (body.lane or "").strip().upper()
    key = (body.api_key or "").strip()
    if not key and lane in ("MAIN", "REVIEW"):
        defaults = (
            gemini_client.DEFAULT_MAIN_MODELS if lane == "MAIN" else gemini_client.DEFAULT_REVIEW_MODELS
        )
        with gemini_client.lane_config(_lanes(body.lane_config)):
            _, key, _ = gemini_client._lane(lane, defaults, os.environ.get("VAPT_MAIN_API_KEY", ""))
    if not key:
        key = os.environ.get("VAPT_MAIN_API_KEY", "") if lane not in ("MAIN", "REVIEW") else ""
    if not key:
        detail = (
            f"No API key is configured for the {lane.lower()} lane at {urlparse(base_url).hostname}. "
            f"Set VAPT_{lane}_API_KEY, or enter a key in Settings."
            if lane in ("MAIN", "REVIEW")
            else "An API key is required to test."
        )
        raise HTTPException(status_code=400, detail=detail)
    try:
        client = OpenAI(base_url=base_url, api_key=key, timeout=25.0, max_retries=0)
        completion = client.chat.completions.create(
            model=body.model,
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            max_tokens=8,
        )
        reply = (completion.choices[0].message.content or "").strip()
        return {"ok": True, "model": body.model, "reply": reply[:80]}
    except Exception as exc:
        return {"ok": False, "model": body.model, "error": str(exc)[:300]}


@app.get("/overview")
def overview(user: User = Depends(get_current_user)):
    """Aggregate dashboard across ALL of the user's projects: severity/status/
    category breakdowns, risk priorities, OWASP 2025 coverage, QA verification
    flags, and usage."""
    # Two queries, not one per project. The aggregation below costs single-digit
    # milliseconds for hundreds of findings; the round trips were the entire cost.
    projects = store.get_projects(user.id)
    findings = store.get_findings_by_user(user.id)

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


def _actor(user: User) -> str:
    """Who performed an action, for the audit trail. Email is more legible than a
    Google subject id, but the id is the stable identity, so fall back to it."""
    return f"user:{user.email or user.id}"


# Display-only annotations that must never be written to a finding's columns.
_ANNOTATION_KEYS = ("_verdict", "_review", "_verification", "_assessment", "_risk", "_uid",
                    "noise", "source", "scanner_confidence")


def _strip_annotations(candidate: dict) -> dict:
    return {k: v for k, v in candidate.items() if k not in _ANNOTATION_KEYS}


def _engine_note(candidate: dict) -> str:
    """The verdict engine's reasoning, if it set this finding's status.

    Recording it at commit time is the point: the engine's decision is otherwise
    a transient object on a job result, so there would be nothing to answer
    "why is this Confirmed?" once the finding is in the database.
    """
    v = candidate.get("_verdict") or {}
    if not isinstance(v, dict) or not v.get("auto_set"):
        return ""
    if v.get("resolved_status") in ("", "Need Review"):
        return ""
    conf = v.get("confidence_label") or ""
    return f"verdict engine ({conf} confidence): {v.get('rationale', '')}".strip()


def _annotate(findings, set_status=False):
    """Attach risk, framework, and reviewer assessments, and the deterministic
    verdict resolution.

    set_status controls whether the resolver may change the finding's status:
      - True  for fresh analyze/triage output, where the resolved status is the
        engine's proposal and is what gets committed.
      - False when listing findings already stored, where the status is whatever
        was committed or a human later set; here the resolution is shown for
        transparency but must not overwrite the stored value on every fetch.
    """
    for f in findings or []:
        f["_assessment"] = risk_map.assess(f)
        review = qa_utils.review_summary(f)
        f["_review"] = review
        # Re-run the mechanical check on read: it is free, and it means a stored
        # finding shows the same verification a fresh one does, even if the
        # verifiers have improved since it was committed.
        verification = f.get("_verification") or verifiers.verify_finding(f)
        if verification:
            f["_verification"] = verification
        if set_status:
            verdict_engine.apply_resolution(f, review, verification)
        else:
            f["_verdict"] = verdict_engine.resolve_verdict(f, review, verification)
    return findings


# --- Findings ----------------------------------------------------------------
@app.get("/projects/{project_id}/findings")
def list_findings(project_id: int, user: User = Depends(get_current_user)):
    _require_project(user, project_id)
    return _annotate(store.get_findings_by_project(user.id, project_id))


@app.post("/projects/{project_id}/findings")
def create_finding(project_id: int, body: FindingIn, user: User = Depends(get_current_user)):
    _require_project(user, project_id)
    payload = _strip_annotations(body.data)
    fid = store.create_finding(
        user.id, project_id, payload,
        actor=_actor(user), rationale=_engine_note(body.data),
    )
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
        payload = _strip_annotations(c)
        store.create_finding(
            user.id, project_id, payload,
            actor=_actor(user), rationale=_engine_note(c),
        )
        existing_keys.add(key)
        committed += 1
    return {"committed": committed, "skipped": skipped}


@app.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingIn, user: User = Depends(get_current_user)):
    if not store.update_finding(user.id, finding_id, _strip_annotations(body.data), actor=_actor(user)):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


@app.delete("/findings/{finding_id}")
def delete_finding(finding_id: int, user: User = Depends(get_current_user)):
    if not store.delete_finding(user.id, finding_id, actor=_actor(user)):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


class BulkIdsIn(BaseModel):
    ids: List[int]


@app.post("/findings/bulk-delete")
def bulk_delete_findings(body: BulkIdsIn, user: User = Depends(get_current_user)):
    """Delete several findings in one call.

    Each deletion goes through the same owner-scoped, audited path as the single
    delete, so ids belonging to another account are simply not found rather than
    being refused loudly -- there is no oracle here for probing which ids exist.
    """
    deleted, missing = 0, 0
    for fid in body.ids[:500]:
        if store.delete_finding(user.id, int(fid), actor=_actor(user)):
            deleted += 1
        else:
            missing += 1
    return {"deleted": deleted, "missing": missing}


@app.post("/findings/{finding_id}/retest")
def retest_finding(finding_id: int, body: RetestIn, user: User = Depends(get_current_user)):
    ok = store.set_retest_result(
        user.id, finding_id, body.retest_status, body.retester,
        body.retest_date, body.retest_evidence, body.note,
        actor=_actor(user),
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"ok": True}


@app.get("/findings/{finding_id}/events")
def finding_events(finding_id: int, user: User = Depends(get_current_user)):
    """Audit trail for one finding: every recorded change, oldest first.

    Access is authorized through the finding itself, which is already owner-scoped,
    so one account cannot read another's history.
    """
    if not store.get_finding(user.id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    events = store.get_finding_events(user.id, finding_id)
    for e in events:
        at = e.get("created_at")
        e["created_at"] = at.isoformat() if hasattr(at, "isoformat") else str(at or "")
    return events


# --- Analyze (background job) ------------------------------------------------
def _run_analyze(jid: str, user_id: str, api_key: str, analysis_type: str, raw_input: str, lanes: dict):
    job = _job(jid)
    try:
        usage_records: List[dict] = []

        def cb(fraction, message):
            job["progress"] = max(0.0, min(1.0, float(fraction)))
            text = str(message)
            job["stage"] = text
            log = job["log"]
            if not log or log[-1] != text:      # collapse repeats
                log.append(text)
                del log[:-400]
                # Persisted on new lines only. Stage messages can arrive
                # milliseconds apart, and a write per progress tick would cost
                # more than the analysis it is recording.
                store.save_job(job)

        # Lane overrides are thread-local, so this job's provider/model choice
        # cannot bleed into any other user's concurrent job.
        with gemini_client.lane_config(lanes):
            findings = gemini_client.analyze_vapt_data(
                api_key, analysis_type, raw_input, usage_sink=usage_records, progress_cb=cb,
            )
        try:
            store.record_usage_batch(user_id, usage_records)
        except Exception:
            pass
        job["result"] = _annotate(findings, set_status=True)
        job["status"] = "done"
        job["progress"] = 1.0
        job["stage"] = "Complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
    finally:
        job["done"] = True
        # The final write is what makes the run recoverable: without it a restart
        # leaves the row saying "running" forever.
        store.save_job(job)


@app.get("/jobs")
def job_history(user: User = Depends(get_current_user)):
    """Recent runs for this account.

    Persisted state gives the analyses a history, which is the more useful half of
    making them durable: LLM usage was already recorded but could not be attributed
    to a particular run.
    """
    rows = store.list_jobs(user.id)
    for r in rows:
        for key in ("created_at", "finished_at"):
            at = r.get(key)
            r[key] = at.isoformat() if hasattr(at, "isoformat") else (str(at) if at else None)
    return rows


@app.post("/analyze")
def analyze(body: AnalyzeIn, user: User = Depends(get_current_user)):
    key = _api_key(body.api_key)
    if not key:
        raise HTTPException(status_code=400, detail="No LLM API key configured")
    lanes = _lanes(body.lane_config)

    # Checked before the quota is touched, so turning input away costs the user
    # nothing: no model calls, and no demo run consumed.
    verdict = input_guard.assess_input(body.raw_input)
    if not verdict["ok"]:
        raise HTTPException(
            status_code=422,
            detail={"error": "not_security_evidence", "message": verdict["reason"], "chars": verdict["chars"]},
        )

    _enforce_demo_limit(user.id, "analyze", body.api_key, lanes)
    jid = _new_job(user.id)
    threading.Thread(
        target=_run_analyze,
        args=(jid, user.id, key, body.analysis_type, body.raw_input, lanes),
        daemon=True,
    ).start()
    return {"job_id": jid}


# --- Scanner import ----------------------------------------------------------
class GuardIn(BaseModel):
    raw_input: str = ""


@app.post("/llm/precheck")
def precheck(body: GuardIn, user: User = Depends(get_current_user)):
    """Whether input would be accepted for analysis, without running any.

    Free to call: it is pure pattern matching, so the interface can warn before a
    user presses the button rather than after.
    """
    return input_guard.assess_input(body.raw_input)


@app.post("/scan/parse")
async def scan_parse(
    files: List[UploadFile] = File(...),
    project_id: Optional[int] = Form(default=None),
    user: User = Depends(get_current_user),
):
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

    # Compared against what the project already holds. Without this a rescan
    # produces an entirely new set of findings and nobody can answer the questions
    # a programme is actually run on: what is new, what came back, what is finally
    # gone. Identity deliberately ignores severity, so a re-rated finding keeps its
    # history at the moment it gets worse rather than losing it.
    delta = None
    absent = []
    if project_id:
        try:
            _require_project(user, project_id)
            existing = store.get_findings_by_project(user.id, project_id)
            deduped, absent, delta = finding_identity.classify(deduped, existing)
        except HTTPException:
            raise
        except Exception:
            # A comparison failure must not cost the user their parsed scan.
            delta, absent = None, []

    return {
        "candidates": deduped, "removed": removed, "per_file": per_file,
        "warnings": warnings, "summary": scan_import.summarize(deduped),
        "delta": delta,
        # Open findings the scan did not report. Never closed automatically: the
        # scan may simply not have covered them, and a tool that silently marks
        # findings fixed is worse than one that says nothing.
        "absent": [
            {"id": a.get("id"), "title": a.get("title"), "severity": a.get("severity"),
             "status": a.get("status"), "affected_url": a.get("affected_url")}
            for a in absent
        ],
    }


# --- Triage (background job) -------------------------------------------------
def _run_triage(jid: str, user_id: str, api_key: str, candidates: List[dict], lanes: dict):
    job = _job(jid)
    try:
        usage_records: List[dict] = []

        def cb(fraction, message):
            job["progress"] = max(0.0, min(1.0, float(fraction)))
            text = str(message)
            job["stage"] = text
            log = job["log"]
            if not log or log[-1] != text:      # collapse repeats
                log.append(text)
                del log[:-400]
                # Persisted on new lines only. Stage messages can arrive
                # milliseconds apart, and a write per progress tick would cost
                # more than the analysis it is recording.
                store.save_job(job)

        with gemini_client.lane_config(lanes):
            result = gemini_client.triage_findings(api_key, candidates, usage_sink=usage_records, progress_cb=cb)
        try:
            store.record_usage_batch(user_id, usage_records)
        except Exception:
            pass
        job["result"] = _annotate(result, set_status=True) if isinstance(result, list) else result
        job["status"] = "done"
        job["progress"] = 1.0
        job["stage"] = "Complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
    finally:
        job["done"] = True
        # The final write is what makes the run recoverable: without it a restart
        # leaves the row saying "running" forever.
        store.save_job(job)


@app.post("/scan/triage")
def scan_triage(body: TriageIn, user: User = Depends(get_current_user)):
    key = _api_key(body.api_key)
    if not key:
        raise HTTPException(status_code=400, detail="No LLM API key configured")
    lanes = _lanes(body.lane_config)
    _enforce_demo_limit(user.id, "triage", body.api_key, lanes)
    jid = _new_job(user.id)
    threading.Thread(target=_run_triage, args=(jid, user.id, key, body.candidates, lanes), daemon=True).start()
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

    # An explicit subset lets a report cover, say, only confirmed high-severity
    # findings. Ids are intersected with what the project already returned, so a
    # caller cannot pull another project's findings into their report.
    if body.finding_ids:
        wanted = {int(i) for i in body.finding_ids}
        findings = [f for f in findings if int(f.get("id", 0)) in wanted]
        if not findings:
            raise HTTPException(status_code=400, detail="No findings matched the selection.")

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
    elif fmt == "html":
        # Annotated first: the HTML report is the only format that shows the
        # deterministic check, and the annotations are added on read rather than
        # stored.
        report_html.export_to_html(project, _annotate(findings), body.exec_summary, body.methodology, path)
        media = "text/html; charset=utf-8"
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")

    safe_name = (project.get("name") or "report").replace("/", "_").replace("\\", "_")
    return FileResponse(path, media_type=media, filename=f"{safe_name}.{fmt}")
