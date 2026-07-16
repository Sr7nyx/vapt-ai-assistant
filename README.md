# AI-Assisted VAPT Assistant - full-stack app

A multi-user web app for the vulnerability-assessment and penetration-testing
workflow - scanner import, AI triage, and client-ready reporting - built around
an "AI with guardrails" philosophy (deterministic CVSS, evidence grounding, an
adversarial review pass, and prompt-injection handling on every finding).

```
frontend/   Next.js (App Router) + Auth.js (Google) + Tailwind        -> Vercel
backend/    FastAPI wrapping the guardrails brain, per-user scoped     -> Render/Fly/Railway
            (gemini_client, scan_import, risk_map, cve_enrich, exporter)
            data in Supabase Postgres; LLM via OpenRouter/Groq/...
```

- **Deploy from zero:** see `DEPLOY.md`.
- **Backend details:** `backend/README.md`.
- **Frontend details:** `frontend/README.md`.

Authorized security testing only. Do not send real confidential client data
through free LLM tiers.
