"""Authentication for the VAPT API: verify Google ID tokens sent by the Next.js
frontend (Auth.js/NextAuth with the Google provider).

Flow: the frontend signs the user in with Google, obtains the Google ID token
(a JWT signed by Google), and sends it on every API call as
`Authorization: Bearer <id_token>`. This dependency verifies the token against
Google's public keys, checks the audience against GOOGLE_CLIENT_ID, and returns
the user's stable `sub` and email. That `sub` is the owner key the data layer
scopes every project and finding to.

Environment:
    GOOGLE_CLIENT_ID     the OAuth 2.0 client ID (shared with the frontend)
    VAPT_AUTH_DISABLED   set truthy for local development to bypass auth and use
                         a fixed dev identity (never enable in production)
"""
import os

from fastapi import Header, HTTPException
from pydantic import BaseModel
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
_AUTH_DISABLED = os.environ.get("VAPT_AUTH_DISABLED", "").strip().lower() in ("1", "true", "yes", "on")
_google_request = google_requests.Request()


class User(BaseModel):
    id: str
    email: str


def get_current_user(authorization: str = Header(default="")) -> User:
    if _AUTH_DISABLED:
        return User(id="dev-user", email="dev@example.com")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()

    # Require the client ID so the token audience is always verified. Without it,
    # verify_oauth2_token would skip the audience check and accept an ID token
    # issued for ANY Google OAuth app -- a real authentication bypass.
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Server auth is not configured (GOOGLE_CLIENT_ID is missing).")

    try:
        claims = google_id_token.verify_oauth2_token(token, _google_request, GOOGLE_CLIENT_ID)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Token missing subject")
    return User(id=subject, email=claims.get("email", ""))
