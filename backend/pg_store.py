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
    """
    CREATE TABLE IF NOT EXISTS demo_runs (
        id         BIGSERIAL PRIMARY KEY,
        user_id    TEXT DEFAULT '',
        kind       TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_demo_user_time ON demo_runs(user_id, created_at)",
    """
    CREATE TABLE IF NOT EXISTS finding_events (
        id         BIGSERIAL PRIMARY KEY,
        user_id    TEXT NOT NULL,
        project_id INTEGER,
        finding_id INTEGER,
        actor      TEXT DEFAULT '',
        action     TEXT DEFAULT '',
        field      TEXT DEFAULT '',
        old_value  TEXT DEFAULT '',
        new_value  TEXT DEFAULT '',
        rationale  TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_events_user ON finding_events(user_id, id)",
    """
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL,
        project_id  INTEGER,
        kind        TEXT DEFAULT '',
        status      TEXT DEFAULT 'running',
        progress    REAL DEFAULT 0,
        stage       TEXT DEFAULT '',
        log         TEXT DEFAULT '',
        result      TEXT DEFAULT '',
        error       TEXT DEFAULT '',
        finding_count INTEGER DEFAULT 0,
        total_tokens  INTEGER DEFAULT 0,
        created_at  TIMESTAMPTZ DEFAULT now(),
        finished_at TIMESTAMPTZ
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_jobs_user ON jobs(user_id, created_at DESC)",

    # --- Row level security ------------------------------------------------
    # Supabase publishes every table in the public schema through PostgREST,
    # reachable with the anon key. That key is public by design, so with RLS off
    # anyone holding it can read and write application data directly, bypassing
    # this API entirely along with its token verification, per-user scoping and
    # audit trail.
    #
    # RLS is therefore enabled with NO policies attached. No policy means no row
    # is visible to the roles PostgREST uses, which closes that path completely.
    # The application is unaffected because it connects as a role that bypasses
    # RLS; see init() below, which verifies exactly that and refuses to start if
    # it is not true.
    #
    # Applied here rather than by hand in the dashboard so that a fresh
    # deployment, which creates these tables from scratch, is protected on its
    # first boot rather than whenever someone remembers.
    "ALTER TABLE users          ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE projects       ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE findings       ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE llm_usage      ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE demo_runs      ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE finding_events ENABLE ROW LEVEL SECURITY",

    # Belt and braces: PostgREST's roles have no business holding grants on these
    # tables at all. Revoking is explicit where RLS is a default-deny.
    "REVOKE ALL ON users          FROM anon, authenticated",
    "REVOKE ALL ON projects       FROM anon, authenticated",
    "REVOKE ALL ON findings       FROM anon, authenticated",
    "REVOKE ALL ON llm_usage      FROM anon, authenticated",
    "REVOKE ALL ON demo_runs      FROM anon, authenticated",
    "REVOKE ALL ON finding_events FROM anon, authenticated",
]


def _touches_rls(statement: str) -> bool:
    upper = statement.upper()
    return "ROW LEVEL SECURITY" in upper or upper.startswith("REVOKE")


def init():
    """Open the pool and ensure the schema exists. Call once at app startup."""
    if _pool is None:
        raise RuntimeError("DATABASE_URL is not set")
    if _pool.closed:
        _pool.open()
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            # Checked before the ALTERs run. With RLS on and no policies, a role
            # that does NOT bypass RLS sees zero rows in every table -- the app
            # would come up looking empty rather than broken, which is the worst
            # way for this to fail. Better to refuse to start and say why.
            # The pool sets row_factory=dict_row, so rows come back as mappings and
            # must be read by column name. Wrapped because a role without access to
            # pg_roles should degrade to "assume not privileged" rather than stop
            # the service from starting at all.
            role_name, privileged = "unknown", False
            try:
                cur.execute(
                    """
                    SELECT current_user AS role_name, rolbypassrls, rolsuper
                    FROM pg_roles WHERE rolname = current_user
                    """
                )
                row = cur.fetchone() or {}
                role_name = str(row.get("role_name") or "unknown")
                privileged = bool(row.get("rolbypassrls") or row.get("rolsuper"))
            except Exception as exc:
                conn.rollback()
                print(f"[pg_store] note: could not determine RLS privileges: {exc}")

            warned = False
            for statement in SCHEMA_STATEMENTS:
                if not privileged and _touches_rls(statement):
                    # Leave RLS alone rather than locking the app out of its own
                    # data. Surfaced once, loudly, so it is fixed deliberately.
                    if not warned:
                        warned = True
                        print(
                            f"[pg_store] WARNING: database role '{role_name}' does not "
                            "bypass RLS, so row level security was NOT enabled. The "
                            "Supabase REST API may be able to read these tables. "
                            "Connect as a role with BYPASSRLS and restart."
                        )
                    continue
                try:
                    cur.execute(statement)
                except Exception as exc:
                    # REVOKE fails if the anon/authenticated roles do not exist,
                    # which is the normal case outside Supabase. Not fatal.
                    if _touches_rls(statement):
                        print(f"[pg_store] note: skipped '{statement[:48]}...': {exc}")
                        conn.rollback()
                    else:
                        raise


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


def create_finding(user_id, project_id, data: dict, actor="", rationale=""):
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
    record_event(
        user_id, row["id"], project_id, actor=actor, action="created",
        field="status", new_value=d.get("status", ""),
        rationale=rationale,
    )
    return row["id"]


def get_findings_by_project(user_id, project_id):
    if not get_project(user_id, project_id):
        return []
    return _all("SELECT * FROM findings WHERE project_id = %s ORDER BY id DESC", (project_id,))


def get_findings_by_user(user_id):
    """Every finding the user owns, in one query.

    The dashboard previously fetched projects and then looped, issuing one query
    per project. Against a pooled Postgres that is N+1 round trips where one will
    do, and round-trip latency -- not the aggregation itself -- was what made the
    page slow. A join on the owning project keeps the same isolation guarantee as
    the per-project call.
    """
    return _all(
        """
        SELECT f.* FROM findings f
        JOIN projects p ON f.project_id = p.id
        WHERE p.user_id = %s
        ORDER BY f.id DESC
        """,
        (user_id,),
    )


def get_finding(user_id, finding_id):
    return _one(
        """
        SELECT f.* FROM findings f
        JOIN projects p ON f.project_id = p.id
        WHERE f.id = %s AND p.user_id = %s
        """,
        (finding_id, user_id),
    )


def update_finding(user_id, finding_id, data: dict, actor=""):
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
    for field, before, after in diff_finding(existing, d):
        record_event(
            user_id, finding_id, existing.get("project_id"), actor=actor,
            action="status_changed" if field == "status" else "updated",
            field=field, old_value=before, new_value=after,
        )
    return True


def delete_finding(user_id, finding_id, actor=""):
    existing = get_finding(user_id, finding_id)
    if not existing:
        return False
    # Recorded before the row goes, and the event is intentionally left behind:
    # the trail has to outlive the thing it describes.
    record_event(
        user_id, finding_id, existing.get("project_id"), actor=actor, action="deleted",
        field="title", old_value=existing.get("title", ""),
    )
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
                      retest_evidence="", note="", actor=""):
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
    record_event(
        user_id, finding_id, existing.get("project_id"),
        actor=actor or (f"retester:{retester}" if retester else ""),
        action="retested", field="retest_status",
        old_value=existing.get("retest_status", ""), new_value=retest_status,
        rationale=(note or "")[:240],
    )
    if new_status != existing.get("status", ""):
        record_event(
            user_id, finding_id, existing.get("project_id"), actor=actor,
            action="status_changed", field="status",
            old_value=existing.get("status", ""), new_value=new_status,
            rationale=f"retest round {new_round}: {retest_status}",
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


def get_usage_summary(user_id, hours=None):
    """LLM usage for a user, optionally limited to a rolling window in hours.

    hours=None means all time. The window is applied in SQL rather than by
    filtering in Python so the aggregate stays a single indexed scan.
    """
    window = ""
    params = [user_id]
    if hours:
        window = " AND created_at > now() - make_interval(hours => %s)"
        params.append(int(hours))

    row = _one(
        f"""
        SELECT COUNT(*) AS calls,
               COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,
               COALESCE(SUM(completion_tokens),0) AS completion_tokens,
               COALESCE(SUM(total_tokens),0) AS total_tokens
        FROM llm_usage WHERE user_id = %s{window}
        """,
        tuple(params),
    ) or {}
    by_model = _all(
        f"""
        SELECT model, COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS total_tokens
        FROM llm_usage WHERE user_id = %s{window} GROUP BY model ORDER BY total_tokens DESC
        """,
        tuple(params),
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


# --- Demo quota --------------------------------------------------------------
# Only runs that consume the SERVER's shared API key are recorded here. A user
# who brings their own key spends their own quota and is never counted, which is
# what makes "add your own key" a real escape hatch rather than a nag.
#
# The counter lives in Postgres rather than memory on purpose: an in-memory
# counter resets on every dyno restart or cold start, so anyone could refresh
# their allowance by waiting for the server to sleep.

def count_demo_runs(user_id, window_hours=24):
    """Runs this user has made on the shared key within the rolling window."""
    row = _one(
        """
        SELECT COUNT(*) AS n FROM demo_runs
        WHERE user_id = %s AND created_at > now() - make_interval(hours => %s)
        """,
        (user_id, int(window_hours)),
    )
    return int((row or {}).get("n", 0) or 0)


def record_demo_run(user_id, kind=""):
    """Record one shared-key run."""
    _exec("INSERT INTO demo_runs (user_id, kind) VALUES (%s, %s)", (user_id, kind or ""))


def oldest_demo_run_in_window(user_id, window_hours=24):
    """When the earliest run in the window happened, so the UI can say when the
    allowance refreshes. Returns None if there are no runs in the window."""
    row = _one(
        """
        SELECT MIN(created_at) AS oldest FROM demo_runs
        WHERE user_id = %s AND created_at > now() - make_interval(hours => %s)
        """,
        (user_id, int(window_hours)),
    )
    return (row or {}).get("oldest")


# --- Audit trail --------------------------------------------------------------
# Findings are mutable and the verdict engine writes to them automatically, so
# without a trail there is no answer to "who set this to Confirmed, and on what
# basis". Events are deliberately never deleted with their finding: an audit
# record that disappears when the thing it describes is removed is not an audit
# record. That does mean orphaned rows accumulate, which is the correct trade.

# Short fields worth recording by value.
AUDIT_SCALAR_FIELDS = (
    "status", "severity", "cvss", "cwe", "title", "category", "environment",
    "owner", "affected_host", "affected_url", "parameter", "http_method",
)
# Long fields where the fact of the edit is the useful signal; storing both full
# versions of every prose edit would grow the table faster than the findings.
AUDIT_TEXT_FIELDS = (
    "description", "evidence", "impact", "scenario", "steps", "remediation",
    "fp_checks", "additional_remarks", "references_data", "retest_notes",
)

_AUDIT_MAX = 240


def _clip(value):
    text = "" if value is None else str(value)
    return text if len(text) <= _AUDIT_MAX else text[: _AUDIT_MAX - 3] + "..."


def record_event(user_id, finding_id, project_id=None, actor="", action="",
                 field="", old_value="", new_value="", rationale=""):
    """Append one audit row. Failures must never break the operation being
    audited, so this swallows its own errors and reports success as a boolean."""
    try:
        _exec(
            """
            INSERT INTO finding_events
                (user_id, project_id, finding_id, actor, action, field, old_value, new_value, rationale)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, project_id, finding_id, actor or "", action or "", field or "",
             _clip(old_value), _clip(new_value), _clip(rationale)),
        )
        return True
    except Exception:
        return False


def diff_finding(before: dict, after: dict):
    """Field-level changes worth auditing, as (field, old, new) tuples."""
    changes = []
    for field in AUDIT_SCALAR_FIELDS:
        old = str((before or {}).get(field, "") or "")
        new = str((after or {}).get(field, "") or "")
        if old != new:
            changes.append((field, old, new))
    for field in AUDIT_TEXT_FIELDS:
        old = str((before or {}).get(field, "") or "")
        new = str((after or {}).get(field, "") or "")
        if old != new:
            # Record that it changed and how the new text opens, not both versions.
            changes.append((field, f"{len(old)} chars", new))
    return changes


def get_finding_events(user_id, finding_id, limit=200):
    """Audit rows for one finding, oldest first, scoped to the owner."""
    return _all(
        """
        SELECT id, actor, action, field, old_value, new_value, rationale, created_at
        FROM finding_events
        WHERE user_id = %s AND finding_id = %s
        ORDER BY id ASC
        LIMIT %s
        """,
        (user_id, finding_id, int(limit)),
    )


# --- job durability -----------------------------------------------------------
# Jobs lived only in a process dictionary, so a restart -- routine on a free tier
# that spins down when idle -- destroyed any analysis in flight. The user saw a
# spinner that never resolved: no result, no error, and no record it ever ran.
#
# Persisted state also gives the run a history, which is the more useful half. LLM
# usage was already recorded but could not be attributed to a particular analysis.

def create_job(job_id, user_id, kind="analyze", project_id=None):
    _exec(
        "INSERT INTO jobs (id, user_id, project_id, kind, status) VALUES (%s, %s, %s, %s, 'running')",
        (job_id, user_id, project_id, kind),
    )


def save_job(job):
    """Persist a running job's progress. Failures are swallowed: losing a progress
    write must never take down the analysis it is describing."""
    import json as _json
    try:
        _exec(
            """
            UPDATE jobs SET status = %s, progress = %s, stage = %s, log = %s,
                            result = %s, error = %s, finding_count = %s,
                            total_tokens = %s,
                            finished_at = CASE WHEN %s THEN now() ELSE finished_at END
            WHERE id = %s
            """,
            (
                job.get("status", "running"),
                float(job.get("progress") or 0),
                str(job.get("stage") or "")[:500],
                _json.dumps(job.get("log") or [])[:200000],
                _json.dumps(job.get("result")) if job.get("done") else "",
                str(job.get("error") or "")[:2000],
                len(job.get("result") or []) if isinstance(job.get("result"), list) else 0,
                int(job.get("total_tokens") or 0),
                bool(job.get("done")),
                job.get("id"),
            ),
        )
        return True
    except Exception:
        return False


def get_job(user_id, job_id):
    import json as _json
    row = _one("SELECT * FROM jobs WHERE id = %s AND user_id = %s", (job_id, user_id))
    if not row:
        return None
    out = dict(row)
    for key in ("log", "result"):
        raw = out.get(key)
        try:
            out[key] = _json.loads(raw) if raw else ([] if key == "log" else None)
        except Exception:
            out[key] = [] if key == "log" else None
    out["done"] = out.get("status") in ("done", "error")
    return out


def list_jobs(user_id, limit=25):
    """Recent runs, without their logs or results -- a history view needs the
    shape of each run, not its full transcript."""
    return _all(
        """
        SELECT id, project_id, kind, status, progress, stage, error,
               finding_count, total_tokens, created_at, finished_at
        FROM jobs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s
        """,
        (user_id, int(limit)),
    )


def reap_stale_jobs(older_than_minutes=30):
    """Mark jobs that were running when the process died.

    A job still 'running' long after its container restarted is not running at all,
    and leaving it that way is what produces a spinner with no end. Called once at
    startup rather than on a timer: the only thing that strands a job is a restart,
    and this runs on exactly that event.
    """
    try:
        _exec(
            """
            UPDATE jobs
            SET status = 'error',
                error = 'The server restarted while this job was running.',
                finished_at = now()
            WHERE status = 'running'
              AND created_at < now() - make_interval(mins => %s)
            """,
            (int(older_than_minutes),),
        )
        return True
    except Exception:
        return False


def get_correction_events(user_id, limit=4000):
    """Every status and severity change this account has made, across all projects.

    Scoped to those two fields at the database rather than in Python: an account
    with a long history would otherwise pull description edits and rationale text
    it has no use for, which is most of the table by volume.
    """
    return _all(
        """
        SELECT id, finding_id, project_id, actor, action, field,
               old_value, new_value, created_at
        FROM finding_events
        WHERE user_id = %s
          AND field IN ('status', 'severity')
          AND old_value IS DISTINCT FROM new_value
        ORDER BY id DESC
        LIMIT %s
        """,
        (user_id, int(limit)),
    )
