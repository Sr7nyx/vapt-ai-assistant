# VAPT Console API (FastAPI + Supabase Postgres + Google auth)

The multi-tenant backend for VAPT Console. It wraps the framework-agnostic brain
modules -- the LLM guardrails pipeline, scanner import, risk and framework
mapping, CVE enrichment, the deterministic verdict engine, and report generation
-- and exposes them as a per-user HTTP API. Every request is authenticated with a
Google ID token and every query is scoped to that user, so accounts are fully
isolated.

## Architecture

```
Next.js (Vercel)  --Bearer Google ID token-->  FastAPI (Render / Fly / Railway)  -->  Supabase Postgres
  Auth.js / Google                              verifies token, scopes by user        per-user projects/findings
                                                two-lane LLM -> Groq / Cerebras / ...
```

Deploy the API on a **persistent** container host, not Vercel serverless: analyze
and triage run for minutes in background threads, which serverless kills (Hobby
caps at 10-60s, no background workers).

## Modules

| File | Responsibility |
| --- | --- |
| `main.py` | FastAPI app: routes, background jobs, per-user scoping, demo quota |
| `auth.py` | Google ID-token verification (mandatory audience check) |
| `pg_store.py` | Multi-tenant Postgres data layer (psycopg3, pgBouncer-friendly) |
| `gemini_client.py` | Two-lane LLM client: extraction, deterministic CVSS, evidence grounding, skeptical review, triage |
| `llm_config.py` | Provider allowlist and SSRF validation for user-supplied endpoints |
| `verdict_engine.py` | Deterministic status + confidence from the reviewer's signals |
| `qa_utils.py` | Parses reviewer remarks and QA signals into structured fields |
| `input_guard.py` | Pre-flight check that turns away input which is not security evidence |
| `scan_import.py` | Burp / ZAP / Nessus / Nmap / CSV parsers to normalized candidates |
| `risk_map.py` | CVSS computation, risk priority, OWASP/PCI/CWE/ATT&CK mapping |
| `cve_enrich.py` | EPSS / CISA KEV / NVD enrichment |
| `exporter.py` | DOCX / PDF / XLSX / JSON reports |

## The guardrails pipeline

A first-pass model extracts findings; then each finding is checked before it can
reach a report:

1. **Deterministic CVSS** is computed from the vector in code -- the model does
   not do the math.
2. **Evidence grounding** labels each finding VERIFIED / PARTIAL / UNVERIFIED
   against the source material.
3. **A skeptical reviewer** (a second lane, ideally a stronger reasoning model)
   argues the false-positive case and returns structured signals.
4. **The verdict engine** (`verdict_engine.py`) combines those signals by a fixed
   rule into a status -- Confirmed / False Positive / Need Review -- and a
   confidence score. Confidence is earned by signals agreeing, not by asking the
   model to sound certain. Two asymmetric guardrails hold: a finding with no
   grounding is never auto-confirmed, and a well-evidenced finding is never
   auto-dismissed. Ambiguous findings are held for review.

The `eval/` directory (repo root) scores this engine on a labelled set:
precision, recall, false-positive reduction, and evidence-grounding accuracy,
each with a 95% Wilson interval.

## Turning away non-evidence

Every analysis costs at least two model calls, so `input_guard.py` checks the
submission first and refuses with 422 **before** the demo quota is touched -- a
rejected input costs nothing at all.

The check looks for security-relevant *structure*: protocol shapes, network
identifiers, scanner output, code, configuration, stack traces, payload markers,
and the vocabulary of the field. It deliberately does **not** look for profanity or
"inappropriate" content. Real evidence is full of hostile strings -- an XSS proof of
concept is a rude payload, and log excerpts carry whatever users typed -- so
filtering on tone would reject exactly the material this tool exists to analyse.
`<script>alert('fuck you')</script>` is accepted; `Fuck you` on its own is not.

The gate is intentionally narrow, because a wrongly rejected analysis costs the
user real work while a wrongly accepted one costs a few thousand tokens. It
refuses only text that is short with no signal at all, or long and plainly prose.
`POST /llm/precheck` runs the same check for free so the interface can warn before
the button is pressed rather than after.

## Audit trail

Findings are mutable and the verdict engine writes to them automatically, so every
change is recorded in `finding_events`: the actor (`user:<email>`,
`engine:verdict`, or `retester:<name>`), the action, the field, its old and new
value, and a rationale. Recording lives inside the data layer rather than the
route handlers, so a new caller cannot forget it.

Two deliberate choices:

- **Events outlive their finding.** Deleting a finding records the deletion and
  leaves the history behind. A trail that vanishes with the thing it describes is
  not a trail. Orphaned rows accumulate, which is the correct trade.
- **Prose edits record the change, not both versions.** Risk-bearing fields
  (status, severity, CVSS, CWE, and the asset fields) are stored by value;
  long-form fields record their previous length and the new opening, so a
  description rewrite does not store two copies of the description.

An audit write that fails never breaks the operation it describes: losing a
history row is bad, losing the user's edit is worse.

## 1. Supabase (Postgres)

1. Create a Supabase project.
2. In the SQL editor, run `schema.sql` (the app also ensures the schema on startup).
3. Copy the pooled / transaction-mode connection string (port 6543, pgBouncer)
   and set it as `DATABASE_URL`.

## 2. Google OAuth (identity)

1. In Google Cloud Console, create an OAuth 2.0 Client ID (Web application).
2. Add the frontend origin and the Auth.js callback URI.
3. Set the client ID as `GOOGLE_CLIENT_ID` here (the same client the frontend
   uses). The backend verifies every ID token against this audience.

## 3. Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | Supabase Postgres connection string (pooled) | required |
| `GOOGLE_CLIENT_ID` | OAuth client ID; the audience every ID token is checked against | required |
| `FRONTEND_ORIGINS` | Comma-separated allowed CORS origins | `http://localhost:3000` |
| `VAPT_MAIN_API_KEY` | LLM key; drives both lanes unless a lane sets its own | required |
| `VAPT_MAIN_BASE_URL` / `VAPT_MAIN_MODELS` | Extraction lane endpoint and model chain | Groq / `llama-3.3-70b-versatile` |
| `VAPT_REVIEW_BASE_URL` / `VAPT_REVIEW_API_KEY` / `VAPT_REVIEW_MODELS` | Reviewer lane overrides | inherits main only if same provider |
| `VAPT_SKEPTICAL_REVIEW` | Enable the reviewer pass | on |
| `VAPT_REVIEW_MAX_FINDINGS` | Findings reviewed per analysis | `12` |
| `VAPT_REVIEW_INPUT_CHARS` | Input chars given to the reviewer per finding (`0` = all) | `4000` |
| `VAPT_REVIEW_TEMPERATURE` / `VAPT_REVIEW_JSON_MODE` | Reviewer sampling and JSON-mode toggles | tuned defaults |
| `VAPT_AUTO_STATUS` | Let the verdict engine set a finding's status when confident (`0` disables) | `1` |
| `VAPT_TRIAGE_MAX_FINDINGS` | Candidates triaged per import | `20` |
| `VAPT_DEMO_RUN_LIMIT` / `VAPT_DEMO_WINDOW_HOURS` | Per-user shared-key quota (`0` limit disables) | `5` / `24` |
| `VAPT_ALLOWED_LLM_HOSTS` | Extra provider hosts users may configure | built-in allowlist |
| `VAPT_HTTP_TIMEOUT` | LLM request timeout (seconds) | `60` |
| `VAPT_CVE_ENRICH` / `NVD_API_KEY` | Enable CVE enrichment / NVD key | off / none |
| `PG_POOL_MAX` | Max Postgres pool connections | pooler default |
| `VAPT_AUTH_DISABLED` | Dev only: bypass Google auth, use a fixed dev user | off |

Model chains are comma-separated and tried in order, so a rate-limited or
unavailable model falls through to the next. A key set for the reviewer lane is
used only at the reviewer's provider: a key issued by one provider is not sent to
another (set `VAPT_REVIEW_API_KEY` when the reviewer is on a different host).

## 4. Run locally

```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://...:6543/postgres"
export GOOGLE_CLIENT_ID="...apps.googleusercontent.com"
export VAPT_MAIN_API_KEY="gsk_..."
export VAPT_AUTH_DISABLED=true          # call the API without a token
uvicorn main:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs

Tests: `pip install -r requirements-dev.txt && pytest` (see `tests/README.md`).

## Auth flow

The Next.js app signs the user in with Google (Auth.js), obtains the Google **ID
token**, and sends it on every request as `Authorization: Bearer <id_token>`. The
backend verifies it against Google's public keys, checks the audience, and uses
the `sub` claim as the owner key for all data. (With Auth.js, persist
`account.id_token` in the `jwt` callback so the frontend can forward it.)

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness |
| GET | `/me` | Current user (id, email) |
| GET | `/usage?window=` | LLM usage summary; window is `1h`, `24h`, `7d`, `30d`, or `all` |
| GET | `/overview` | Aggregate dashboard across all projects |
| GET | `/demo/quota` | Remaining shared-key runs for this user |
| GET/POST | `/projects` | List / create projects |
| GET/DELETE | `/projects/{id}` | Get / delete a project |
| GET/POST | `/projects/{id}/findings` | List (with risk, mapping, verdict) / create |
| POST | `/projects/{id}/findings/commit` | Bulk-commit scanner candidates (asset-aware dedup) |
| PATCH/DELETE | `/findings/{id}` | Update / delete a finding |
| POST | `/findings/bulk-delete` | Delete several findings (audited individually) |
| POST | `/findings/{id}/retest` | Record a retest outcome |
| GET | `/findings/{id}/events` | Audit trail for one finding |
| POST | `/analyze` | Start an analysis job -> `{job_id}`; refuses non-evidence with 422 |
| POST | `/llm/precheck` | Whether input would be accepted, without running anything |
| POST | `/scan/parse` | Upload scanner files -> normalized candidates |
| POST | `/scan/triage` | Start an AI-triage job -> `{job_id}` |
| GET | `/jobs/{id}` | Poll a background job (owner-scoped) |
| POST | `/projects/{id}/report` | Export a report (docx / pdf / xlsx / json); optional `finding_ids` narrows the scope |
| GET | `/llm/providers` | Allowlisted provider hosts |
| POST | `/llm/models` | List a provider's models |
| POST | `/llm/lanes` | Resolved provider + model per lane (no keys returned) |
| POST | `/llm/test` | Test a lane's connectivity (resolves that lane's own key) |

Long jobs run in background threads, polled via `/jobs/{id}`, and the frontend
reconnects to a running job across navigation. The in-memory job store is fine on
one instance; to scale out, move jobs to a task queue (Celery/RQ + Redis) -- one
more reason this wants a persistent host, not serverless.

## Security notes

- Per-user data isolation is enforced in every query; finding access is
  authorized through the parent project.
- User-supplied LLM base URLs are allowlisted and rejected if they resolve to
  loopback, private, link-local, or reserved addresses (SSRF protection in
  `llm_config.py`).
- Per-request model configuration is held thread-locally, so one user's provider
  and key can never leak into another's concurrent job.
- Scanner XML is parsed without external entity resolution; scanner and target
  content are treated as untrusted throughout the LLM pipeline.
- Findings and evidence are sent to whichever LLM provider is configured. Free
  provider tiers may train on inputs, so use a paid or private endpoint for
  anything that is not synthetic.
