# VAPT Console - Frontend (Next.js)

The React/Next.js frontend for the VAPT assistant. Talks to the FastAPI backend,
authenticates users with Google (Auth.js), and forwards the Google ID token on
every request so the backend can scope data per user.

## Stack
Next.js 14 (App Router) - Auth.js v5 (Google) - Tailwind CSS - TypeScript.

## Local development
```bash
npm install
cp .env.local.example .env.local     # then fill in the values
npm run dev                          # http://localhost:3000
```

For Google login to work locally, add these in the Google Cloud console for your
OAuth client:
- Authorized JavaScript origin: `http://localhost:3000`
- Authorized redirect URI: `http://localhost:3000/api/auth/callback/google`

## Environment (.env.local)
| Var | Purpose |
|---|---|
| `NEXT_PUBLIC_API_URL` | FastAPI backend base URL |
| `AUTH_SECRET` | Auth.js secret (`openssl rand -base64 32`) |
| `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` | Google OAuth client |
| `AUTH_URL` | Canonical app URL (set in production) |

See `../DEPLOY.md` for the full zero-to-production walkthrough.

## Structure
```
src/
  auth.ts                 Auth.js config (Google + ID-token refresh)
  app/                    App Router pages (overview, projects, analyzer,
                          import, findings, reports, settings) + layout
  app/api/auth/[...nextauth]/route.ts   Auth.js route handler
  components/             Nav, AppShell, SignInGate, JobProgress, Severity
  lib/                    api client, types, project context, prefs
  hooks/useJob.ts         background-job polling
```
