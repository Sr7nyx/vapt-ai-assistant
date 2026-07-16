# Deploying the VAPT Assistant - from zero

This walks you from nothing to a live, multi-user web app:

```
Next.js frontend (Vercel)  --Google ID token-->  FastAPI backend (Render)  -->  Supabase Postgres
        Auth.js / Google                          verifies + scopes per user     LLM: OpenRouter (or any OpenAI-compatible)
```

Everything here fits on free tiers. Budget ~30-45 minutes for the first run.

---

## 0. Accounts you'll need (all free)

- **GitHub** - to hold the repo (use a personal account; Vercel Hobby cannot connect to Git *organization* repos).
- **Google Cloud** - for the OAuth login.
- **Supabase** - Postgres database.
- **Render** - hosts the Python backend (a persistent server; do not use Vercel for the backend - its serverless functions time out on the long AI jobs).
- **Vercel** - hosts the Next.js frontend.
- **OpenRouter** (or Groq / GitHub Models / any OpenAI-compatible provider) - the LLM key.

Push this repo to GitHub first (two folders: `backend/` and `frontend/`).

---

## 1. Google OAuth credentials

1. Go to Google Cloud Console -> create/select a project.
2. **APIs & Services -> OAuth consent screen**: choose **External**, fill the app name and your email, add scopes `openid`, `email`, `profile`. While testing you can leave it in "Testing" mode and add your Google account under **Test users** (or publish it).
3. **APIs & Services -> Credentials -> Create credentials -> OAuth client ID -> Web application**.
4. Add (you can add the production URLs now or come back after step 5):
   - **Authorized JavaScript origins**: `http://localhost:3000` and `https://YOUR-APP.vercel.app`
   - **Authorized redirect URIs**: `http://localhost:3000/api/auth/callback/google` and `https://YOUR-APP.vercel.app/api/auth/callback/google`
5. Copy the **Client ID** and **Client secret**.

The same Client ID is used by both the frontend (to log in) and the backend (to verify tokens).

---

## 2. Supabase (Postgres)

1. Create a new Supabase project (pick a strong DB password).
2. Open the **SQL Editor**, paste the contents of `backend/schema.sql`, and run it.
3. **Project Settings -> Database -> Connection string**. Use the **Transaction pooler** (host ends in `pooler.supabase.com`, port **6543**). It looks like:
   ```
   postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
   ```
   This is your `DATABASE_URL`. (The backend already disables prepared statements so it works with the transaction pooler.)

---

## 3. LLM key (OpenRouter)

1. Sign up at openrouter.ai, create an API key.
2. That key is `VAPT_MAIN_API_KEY`. The defaults use free models
   (`meta-llama/llama-3.3-70b-instruct:free` for extraction, `deepseek/deepseek-r1:free` for review/triage).

---

## 4. Deploy the backend (Render)

1. Render -> **New -> Web Service** -> connect your GitHub repo.
2. **Root Directory**: `backend`. **Runtime**: Docker (the `backend/Dockerfile` is detected).
3. Add environment variables:
   | Key | Value |
   |---|---|
   | `DATABASE_URL` | the Supabase pooler URL from step 2 |
   | `GOOGLE_CLIENT_ID` | the Google Client ID from step 1 |
   | `VAPT_MAIN_API_KEY` | your OpenRouter key |
   | `FRONTEND_ORIGINS` | `https://YOUR-APP.vercel.app` (fill after step 5; use `http://localhost:3000` for now) |
4. Deploy. When it's live, note the URL, e.g. `https://vapt-api.onrender.com`.
5. Sanity check: open `https://vapt-api.onrender.com/health` -> `{"status":"ok"}`, and `/docs` for the API explorer.

> Render's free tier sleeps after inactivity, so the first request after idle is slow (cold start). That's expected.

---

## 5. Deploy the frontend (Vercel)

1. Vercel -> **Add New -> Project** -> import the same repo.
2. **Root Directory**: `frontend`. Framework preset: **Next.js** (auto-detected).
3. Environment variables:
   | Key | Value |
   |---|---|
   | `NEXT_PUBLIC_API_URL` | your Render backend URL (step 4) |
   | `AUTH_SECRET` | run `openssl rand -base64 32` and paste the output |
   | `AUTH_GOOGLE_ID` | Google Client ID (step 1) |
   | `AUTH_GOOGLE_SECRET` | Google Client secret (step 1) |
   | `AUTH_URL` | `https://YOUR-APP.vercel.app` (your Vercel URL) |
4. Deploy. Note the app URL, e.g. `https://vapt-console.vercel.app`.

---

## 6. Close the loop (the cross-references)

Now that you know the real URLs, make sure these four line up exactly:

1. **Google console** -> the OAuth client has redirect URI
   `https://YOUR-APP.vercel.app/api/auth/callback/google` and origin `https://YOUR-APP.vercel.app`.
2. **Render** -> `FRONTEND_ORIGINS = https://YOUR-APP.vercel.app` (redeploy the backend if you changed it).
3. **Vercel** -> `NEXT_PUBLIC_API_URL` points at the Render URL, and `AUTH_URL` is the Vercel URL.
4. Redeploy whichever side you changed.

Then open your Vercel URL, click **Sign in with Google**, and you're in. Create a
project, paste evidence into the Analyzer or import a scanner file, run triage,
and export a report.

---

## Local development

**Backend:**
```bash
cd backend
pip install -r requirements.txt
export DATABASE_URL="postgresql://...:6543/postgres"   # Supabase pooler
export GOOGLE_CLIENT_ID="...apps.googleusercontent.com"
export VAPT_MAIN_API_KEY="sk-or-..."
export VAPT_AUTH_DISABLED=true          # optional: skip Google auth while poking /docs
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
cp .env.local.example .env.local        # fill NEXT_PUBLIC_API_URL=http://localhost:8000, AUTH_*
npm run dev                             # http://localhost:3000
```

(For local Google login, add the `localhost:3000` origin and callback in the Google console - step 1.)

---

## Order-of-operations tip

There's a mild chicken-and-egg: you need the Vercel URL for Google + the backend,
but you get it only after deploying the frontend. Easiest path: deploy the
frontend once to obtain the URL, then fill it into Google (step 1) and Render
(`FRONTEND_ORIGINS`), and redeploy. A custom domain avoids this next time.

---

## Troubleshooting

- **`redirect_uri_mismatch`** - the exact callback `https://.../api/auth/callback/google` must be listed in the Google console.
- **401 "Invalid token"** - `GOOGLE_CLIENT_ID` differs between frontend and backend, or the app was left open past token expiry (the frontend refreshes automatically only if Google returned a refresh token - that needs `access_type=offline`, which is already configured; if it still happens, sign out and back in). Check server clock skew.
- **CORS error in the browser console** - `FRONTEND_ORIGINS` on the backend must exactly match the frontend origin (scheme + host, no trailing slash).
- **Supabase connection errors** - use the transaction **pooler** URL (port 6543), not the direct 5432 one, for a web backend.
- **Backend slow on first hit** - Render free tier cold start; wait a few seconds and retry.
- **Uploads or long analyses fail on a serverless host** - don't put the backend on Vercel/serverless; it must be a persistent server (Render/Fly/Railway).

---

## Security & privacy reminders

- The tool is for **authorized** testing only.
- Findings and their evidence are sent to your configured LLM provider. Free
  provider tiers may retain inputs - do not push real confidential client data
  through a free tier; use a paid/private endpoint for engagement data.
- Keep secrets out of git (`.env`, `.env.local`, and `*.db` are gitignored).
