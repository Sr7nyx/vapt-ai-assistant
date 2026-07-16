"""Multi-tenant Postgres data layer (Supabase) for the VAPT assistant API.

Every project and finding is owned by a user (the Google `sub`), and every query
is scoped to the authenticated user, so no account can read or write another's
data. Finding operations enforce ownership through the parent project, so a user
can only touch findings inside their own projects.

Connection: set DATABASE_URL to your Supabase Postgres connection string. Prefer
the pooled (transaction-mode / pgBouncer, port 6543) URL for a web backend. A
psycopg connection pool is used; call init() once at startup.

The finding shape and the retest lifecycle mirror the original SQLite layer, so
the exporter, risk_map, and qa_utils modules keep working unchanged.
"""
import os
import json
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Pool is created lazily/opened in init() so importing this module never blocks.
_pool = ConnectionPool(
    _DATABASE_URL,
    min_size=1,
    max_size=int(os.environ.get("PG_POOL_MAX", "5")),
    open=False,
    kwargs={"row_factory": dict_row, "prepare_threshold": None},
) if _DATABASE_URL else None


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id         TEXT PRIMARY KEY,
        email      TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        id              BIGSERIAL PRIMARY KEY,
        user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name            TEXT NOT NULL,
        client          TEXT DEFAULT '',
        scope           TEXT DEFAULT '',
        tester          TEXT DEFAULT '',
        start_date      TEXT DEFAULT '',
        end_date        TEXT DEFAULT '',
        report_ref      TEXT DEFAULT 'SECTEST-XXXX',
        reviewer        TEXT DEFAULT '',
        assessment_type TEXT DEFAULT 'VAPT',
        environment     TEXT DEFAULT 'STG',
        created_at      TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id)",
    """
    CREATE TABLE IF NOT EXISTS findings (
        id                 BIGSERIAL PRIMARY KEY,
        project_id         BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        title              TEXT DEFAULT 'Untitled Finding',
        severity           TEXT DEFAULT 'Medium',
        cwe                TEXT DEFAULT '',
        cvss               TEXT DEFAULT '',
        category           TEXT DEFAULT '',
        status             TEXT DEFAULT 'Draft',
        environment        TEXT DEFAULT '',
        affected_host      TEXT DEFAULT '',
        affected_url       TEXT DEFAULT '',
        http_method        TEXT DEFAULT '',
        parameter          TEXT DEFAULT '',
        owner              TEXT DEFAULT '',
        description        TEXT DEFAULT '',
        evidence           TEXT DEFAULT '',
        evidence_files     TEXT DEFAULT '',
        impact             TEXT DEFAULT '',
        scenario           TEXT DEFAULT '',
        steps              TEXT DEFAULT '',
        remediation        TEXT DEFAULT '',
        fp_checks          TEXT DEFAULT '',
        retest_notes       TEXT DEFAULT '',
        additional_remarks TEXT DEFAULT '',
        references_data    TEXT DEFAULT '',
        retest_status      TEXT DEFAULT 'Not Retested',
        retest_round       INTEGER DEFAULT 0,
        retest_date        TEXT DEFAULT '',
        retester           TEXT DEFAULT '',
        retest_evidence    TEXT DEFAULT '',
        retest_history     TEXT DEFAULT '',
        original_severity  TEXT DEFAULT '',
        first_found_date   TEXT DEFAULT '',
        created_at         TEXT DEFAULT '',
        updated_at         TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id)",
    """
    CREATE TABLE IF NOT EXISTS llm_usage (
        id                BIGSERIAL PRIMARY KEY,
        user_id           TEXT DEFAULT '',
        lane              TEXT DEFAULT '',
        model             TEXT DEFAULT '',
        prompt_tokens     INTEGER DEFAULT 0,
        completion_tokens INTEGER DEFAULT 0,
        total_tokens      INTEGER DEFAULT 0,
        created_at        TIMESTAMPTZ DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_usage_user ON llm_usage(user_id)",
]


def init():
    """Open the pool and ensure the schema exists. Call once at app startup."""
    if _pool is None:
        raise RuntimeError("DATABASE_URL is not set")
    if _pool.closed:
        _pool.open()
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            for statement in SCHEMA_STATEMENTS:
                cur.execute(statement)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _all(sql, params=()):
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def _one(sql, params=()):
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def _exec(sql, params=()):
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)


# --- Users -------------------------------------------------------------------
def ensure_user(user_id, email=""):
    _exec(
        """
        INSERT INTO users (id, email) VALUES (%s, %s)
        ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email
        """,
        (user_id, email or ""),
    )


# --- Projects (owner-scoped) -------------------------------------------------
def create_project(user_id, name, client="", scope="", tester="", start_date="", end_date="",
                   report_ref="SECTEST-XXXX", reviewer="", assessment_type="VAPT", environment="STG"):
    ensure_user(user_id)
    row = _one(
        """
        INSERT INTO projects
            (user_id, name, client, scope, tester, start_date, end_date,
             report_ref, reviewer, assessment_type, environment, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (user_id, name, client, scope, tester, start_date, end_date,
         report_ref, reviewer, assessment_type, environment, _now()),
    )
    return row["id"]


def get_projects(user_id):
    return _all("SELECT * FROM projects WHERE user_id = %s ORDER BY id DESC", (user_id,))


def get_project(user_id, project_id):
    return _one("SELECT * FROM projects WHERE id = %s AND user_id = %s", (project_id, user_id))


def update_project(user_id, project_id, **fields):
    allowed = ("name", "client", "scope", "tester", "start_date", "end_date",
               "report_ref", "reviewer", "assessment_type", "environment")
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    columns = ", ".join(f"{k} = %s" for k in sets)
    params = list(sets.values()) + [project_id, user_id]
    _exec(f"UPDATE projects SET {columns} WHERE id = %s AND user_id = %s", params)


def delete_project(user_id, project_id):
    _exec("DELETE FROM projects WHERE id = %s AND user_id = %s", (project_id, user_id))


# --- Findings (scoped through parent project) --------------------------------
def normalize_finding_data(data: dict) -> dict:
    refs = data.get("references_data") or data.get("references") or ""
    now = _now()

    def v(key, default=""):
        value = data.get(key)
        return default if value is None else value

    return {
        "title": v("title", "Untitled Finding"),
        "severity": v("severity", "Medium"),
        "cwe": v("cwe", ""),
        "cvss": v("cvss", ""),
        "category": v("category", "Web Application/API Vulnerability"),
        "status": v("status", "Draft"),
        "environment": v("environment", ""),
        "affected_host": v("affected_host", ""),
        "affected_url": v("affected_url", ""),
        "http_method": v("http_method", ""),
        "parameter": v("parameter", ""),
        "owner": v("owner", ""),
        "description": v("description", ""),
        "evidence": v("evidence", ""),
        "evidence_files": v("evidence_files", ""),
        "impact": v("impact", ""),
        "scenario": v("scenario", ""),
        "steps": v("steps", ""),
        "remediation": v("remediation", ""),
        "fp_checks": v("fp_checks", ""),
        "retest_notes": v("retest_notes", ""),
        "additional_remarks": v("additional_remarks", ""),
        "references_data": str(refs),
        "created_at": v("created_at", now),
        "updated_at": now,
    }


def create_finding(user_id, project_id, data: dict):
    if not get_project(user_id, project_id):
        return None  # not the user's project
    d = normalize_finding_data(data)
    row = _one(
        """
        INSERT INTO findings (
            project_id, title, severity, cwe, cvss, category, status, environment,
            affected_host, affected_url, http_method, parameter, owner,
            description, evidence, evidence_files, impact, scenario, steps,
            remediation, fp_checks, retest_notes, additional_remarks,
            references_data, created_at, updated_at
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (
            project_id, d["title"], d["severity"], d["cwe"], d["cvss"], d["category"], d["status"], d["environment"],
            d["affected_host"], d["affected_url"], d["http_method"], d["parameter"], d["owner"],
            d["description"], d["evidence"], d["evidence_files"], d["impact"], d["scenario"], d["steps"],
            d["remediation"], d["fp_checks"], d["retest_notes"], d["additional_remarks"],
            d["references_data"], d["created_at"], d["updated_at"],
        ),
    )
    return row["id"]


def get_findings_by_project(user_id, project_id):
    if not get_project(user_id, project_id):
        return []
    return _all("SELECT * FROM findings WHERE project_id = %s ORDER BY id DESC", (project_id,))


def get_finding(user_id, finding_id):
    return _one(
        """
        SELECT f.* FROM findings f
        JOIN projects p ON f.project_id = p.id
        WHERE f.id = %s AND p.user_id = %s
        """,
        (finding_id, user_id),
    )


def update_finding(user_id, finding_id, data: dict):
    existing = get_finding(user_id, finding_id)
    if not existing:
        return False
    merged = {**existing, **data}
    d = normalize_finding_data(merged)
    d["created_at"] = existing.get("created_at") or d["created_at"]
    _exec(
        """
        UPDATE findings SET
            title=%s, severity=%s, cwe=%s, cvss=%s, category=%s, status=%s, environment=%s,
            affected_host=%s, affected_url=%s, http_method=%s, parameter=%s, owner=%s,
            description=%s, evidence=%s, evidence_files=%s, impact=%s, scenario=%s, steps=%s,
            remediation=%s, fp_checks=%s, retest_notes=%s, additional_remarks=%s,
            references_data=%s, created_at=%s, updated_at=%s
        WHERE id=%s
        """,
        (
            d["title"], d["severity"], d["cwe"], d["cvss"], d["category"], d["status"], d["environment"],
            d["affected_host"], d["affected_url"], d["http_method"], d["parameter"], d["owner"],
            d["description"], d["evidence"], d["evidence_files"], d["impact"], d["scenario"], d["steps"],
            d["remediation"], d["fp_checks"], d["retest_notes"], d["additional_remarks"],
            d["references_data"], d["created_at"], d["updated_at"], finding_id,
        ),
    )
    return True


def delete_finding(user_id, finding_id):
    existing = get_finding(user_id, finding_id)
    if not existing:
        return False
    _exec("DELETE FROM findings WHERE id = %s", (finding_id,))
    return True


def find_duplicate_finding(user_id, project_id, data: dict, exclude_id=None):
    candidate = normalize_finding_data(data)
    title = candidate["title"].strip().lower()
    cwe = candidate["cwe"].strip().lower()
    category = candidate["category"].strip().lower()
    asset = (candidate["affected_url"] or candidate["affected_host"]).strip().lower()

    duplicates = []
    for existing in get_findings_by_project(user_id, project_id):
        if exclude_id and int(existing["id"]) == int(exclude_id):
            continue
        e_title = (existing.get("title") or "").strip().lower()
        e_cwe = (existing.get("cwe") or "").strip().lower()
        e_category = (existing.get("category") or "").strip().lower()
        e_asset = (existing.get("affected_url") or existing.get("affected_host") or "").strip().lower()
        title_match = title and e_title and title == e_title
        asset_match = asset and e_asset and asset == e_asset
        cwe_match = cwe and e_cwe and cwe == e_cwe
        category_match = category and e_category and category == e_category
        if title_match and (asset_match or cwe_match or category_match):
            duplicates.append(existing)
    return duplicates


# --- Retest workflow (mirrors the SQLite lifecycle) --------------------------
RETEST_OPEN_STATES = ("Open", "Partially Fixed", "Regressed")
_RETEST_STATUS_MAP = {
    "Fixed": "Retest Passed",
    "Open": "Retest Failed",
    "Partially Fixed": "Retest Failed",
    "Regressed": "Retest Failed",
    "Accepted Risk": "Accepted Risk",
}


def set_retest_result(user_id, finding_id, retest_status, retester="", retest_date="",
                      retest_evidence="", note=""):
    existing = get_finding(user_id, finding_id)
    if not existing:
        return False
    try:
        history = json.loads(existing.get("retest_history") or "[]")
        if not isinstance(history, list):
            history = []
    except Exception:
        history = []

    now = _now()
    new_round = int(existing.get("retest_round") or 0) + 1
    rdate = (retest_date or "").strip() or now[:10]
    history.append({
        "round": new_round, "date": rdate, "status": retest_status,
        "retester": (retester or "").strip(), "note": (note or "").strip(),
    })

    original_severity = (existing.get("original_severity") or existing.get("severity") or "").strip()
    first_found = (existing.get("first_found_date") or existing.get("created_at") or now).strip()
    new_status = _RETEST_STATUS_MAP.get(retest_status, existing.get("status") or "Draft")
    stamp = f"[R{new_round} {rdate}] {retest_status}" + (f" - {note.strip()}" if note and note.strip() else "")
    prev_notes = (existing.get("retest_notes") or "").strip()
    new_notes = (prev_notes + "\n" + stamp).strip() if prev_notes else stamp

    _exec(
        """
        UPDATE findings SET
            retest_status=%s, retest_round=%s, retest_date=%s, retester=%s,
            retest_evidence=%s, retest_history=%s, retest_notes=%s,
            original_severity=%s, first_found_date=%s, status=%s, updated_at=%s
        WHERE id=%s
        """,
        (retest_status, new_round, rdate, (retester or "").strip(),
         (retest_evidence or "").strip(), json.dumps(history), new_notes,
         original_severity, first_found, new_status, now, finding_id),
    )
    return True


def get_retest_summary(user_id, project_id):
    findings = get_findings_by_project(user_id, project_id)
    total = len(findings)
    counts, residual = {}, {}
    for f in findings:
        state = f.get("retest_status") or "Not Retested"
        counts[state] = counts.get(state, 0) + 1
        if state in RETEST_OPEN_STATES:
            sev = f.get("original_severity") or f.get("severity") or "Unknown"
            residual[sev] = residual.get(sev, 0) + 1
    fixed = counts.get("Fixed", 0)
    accepted = counts.get("Accepted Risk", 0)
    retested = sum(v for k, v in counts.items() if k != "Not Retested")
    return {
        "total": total,
        "retested": retested,
        "not_retested": counts.get("Not Retested", 0),
        "fixed": fixed,
        "accepted": accepted,
        "open": sum(counts.get(s, 0) for s in RETEST_OPEN_STATES),
        "counts": counts,
        "remediation_rate": (fixed / retested * 100) if retested else 0,
        "residual_by_severity": residual,
    }


# --- Usage -------------------------------------------------------------------
def record_usage_batch(user_id, records):
    if not records:
        return
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            for r in records:
                cur.execute(
                    """
                    INSERT INTO llm_usage (user_id, lane, model, prompt_tokens, completion_tokens, total_tokens)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    (user_id, r.get("lane", ""), r.get("model", ""),
                     int(r.get("prompt_tokens", 0) or 0), int(r.get("completion_tokens", 0) or 0),
                     int(r.get("total_tokens", 0) or 0)),
                )


def get_usage_summary(user_id):
    row = _one(
        """
        SELECT COUNT(*) AS calls,
               COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,
               COALESCE(SUM(completion_tokens),0) AS completion_tokens,
               COALESCE(SUM(total_tokens),0) AS total_tokens
        FROM llm_usage WHERE user_id = %s
        """,
        (user_id,),
    ) or {}
    by_model = _all(
        """
        SELECT model, COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS total_tokens
        FROM llm_usage WHERE user_id = %s GROUP BY model ORDER BY total_tokens DESC
        """,
        (user_id,),
    )
    return {
        "calls": (row.get("calls") or 0),
        "prompt_tokens": (row.get("prompt_tokens") or 0),
        "completion_tokens": (row.get("completion_tokens") or 0),
        "total_tokens": (row.get("total_tokens") or 0),
        "by_model": by_model,
    }


def reset_usage(user_id):
    _exec("DELETE FROM llm_usage WHERE user_id = %s", (user_id,))
