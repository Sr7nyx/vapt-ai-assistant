# VAPT Assistant API (FastAPI + Supabase Postgres + Google auth)

The multi-tenant backend for the VAPT assistant. It wraps the framework-agnostic
brain modules (LLM guardrails pipeline, scanner import, risk/framework mapping,
CVE enrichment, report generation) and exposes them as a per-user HTTP API for a
Next.js frontend. Every request is authenticated with a Google ID token and every
query is scoped to that user, so accounts are fully isolated.

## Architecture

```
Next.js (Vercel)  --Bearer Google ID token-->  FastAPI (Render/Fly/Railway)  -->  Supabase Postgres
  Auth.js / Google                              verifies token, scopes by user      per-user projects/findings
                                                LLM calls -> OpenRouter/Groq/...
```

Deploy the API on a PERSISTENT container host, NOT Vercel serverless: analyze and
triage run for minutes in background threads, which serverless kills (Hobby caps
at 10-60s, no background workers).

## 1. Supabase (Postgres)

1. Create a Supabase project.
2. In the SQL editor, run `schema.sql` (the app also ensures the schema on startup).
3. Copy the connection string. Use the pooled / transaction-mode URL (port 6543,
   pgBouncer) for a web backend. Set it as `DATABASE_URL`.

## 2. Google OAuth (identity)

1. In Google Cloud Console, create an OAuth 2.0 Client ID (Web application).
2. Add your frontend's origin and redirect URI (the Next.js/Auth.js callback).
3. Set the client ID as `GOOGLE_CLIENT_ID` here (the same client is used by the
   frontend). The backend verifies Google ID tokens against this audience.

## 3. Environment

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Supabase Postgres connection string (pooled) |
| `GOOGLE_CLIENT_ID` | OAuth client ID; ID-token audience |
| `VAPT_MAIN_API_KEY` | LLM key (both lanes); or send `api_key` per request |
| `VAPT_MAIN_MODELS` / `VAPT_REVIEW_MODELS` / `VAPT_*_BASE_URL` | Optional model overrides |
| `VAPT_TRIAGE_MAX_FINDINGS` | Triage cap per run (default 20) |
| `FRONTEND_ORIGINS` | Comma-separated allowed CORS origins (your Vercel URL) |
| `VAPT_AUTH_DISABLED` | Dev only: bypass Google auth, use a fixed dev user |

## 4. Run locally

```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://...:6543/postgres"
export GOOGLE_CLIENT_ID="...apps.googleusercontent.com"
export VAPT_MAIN_API_KEY="sk-or-..."
export VAPT_AUTH_DISABLED=true          # so you can call the API without a token
uvicorn main:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs

## Auth flow (frontend)

The Next.js app signs the user in with Google (Auth.js/NextAuth), obtains the
Google **ID token**, and sends it on every request as `Authorization: Bearer
<id_token>`. The backend verifies it against Google's public keys, checks the
audience, and uses the `sub` claim as the owner key for all data. (With NextAuth,
persist `account.id_token` in the `jwt` callback so the frontend can forward it.)

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/me` | Current user (id, email) |
| GET | `/usage` | LLM usage summary for the user |
| GET/POST | `/projects` | List / create projects |
| GET/DELETE | `/projects/{id}` | Get / delete a project |
| GET/POST | `/projects/{id}/findings` | List (with risk + mapping) / create findings |
| POST | `/projects/{id}/findings/commit` | Bulk-commit scanner candidates (asset-aware dedup) |
| PATCH/DELETE | `/findings/{id}` | Update / delete a finding |
| POST | `/findings/{id}/retest` | Record a retest outcome |
| POST | `/analyze` | Start an analysis job -> `{job_id}` |
| POST | `/scan/parse` | Upload scanner files -> normalized candidates |
| POST | `/scan/triage` | Start an AI-triage job -> `{job_id}` |
| GET | `/jobs/{id}` | Poll a background job (owner-scoped) |
| POST | `/projects/{id}/report` | Export a report (docx/pdf/xlsx/json) |

Long jobs run in background threads, polled via `/jobs/{id}`. On one instance the
in-memory job store is fine; to scale out, move jobs to a task queue (Celery/RQ +
Redis) -- another reason this needs a persistent host, not serverless.

## Next (Phase 4)

The Next.js frontend on Vercel: pages mirroring the workflow, a typed API client,
Auth.js Google login, and job polling / SSE streaming for live analyze + triage
progress.
