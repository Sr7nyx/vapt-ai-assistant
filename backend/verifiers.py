"""Deterministic verification of finding claims against their evidence.

The skeptical reviewer is a second model auditing the first, which means the
project's central claim -- that a finding is real only when the evidence proves it
-- ultimately rests on an LLM assertion. For a meaningful subset of finding
classes that assertion can be replaced with an actual check: a missing security
header either is or is not absent from the response in the evidence, and no
opinion is required to establish which.

Each verifier answers one question about one class of claim and returns:

    CONFIRMED    the evidence demonstrably supports the claim
    REFUTED      the evidence demonstrably contradicts it
    INSUFFICIENT the evidence does not contain what is needed to decide

REFUTED is the valuable outcome. It is a hallucination caught by code rather than
by a second opinion, and unlike a reviewer's doubt it is reproducible and can be
shown to a client.

Design rules, applied throughout:

  - Silence is not refutation. A single response with no Set-Cookie header does not
    disprove a cookie finding; the evidence simply may not include the response
    that set it. Verifiers return INSUFFICIENT unless the evidence positively
    settles the question, which is why the anchor checks below are strict.
  - Verifiers never invent severity, never rewrite a finding, and never delete
    anything. They attach a result. The verdict engine decides what it means.
  - Every verifier is pure: text in, result out. No network, no model, no state.
"""
import re

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
INSUFFICIENT = "INSUFFICIENT"

# Header names carry their canonical spelling for messages; matching is
# case-insensitive, as HTTP requires.
SECURITY_HEADERS = {
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
}

_HEADER_LINE = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9-]{1,40})[ \t]*:[ \t]*(.*)$", re.M)
_STATUS_LINE = re.compile(r"^\s*HTTP/\d(?:\.\d)?\s+(\d{3})", re.M | re.I)
_MISSING_WORDS = re.compile(r"\b(missing|absent|not\s+set|not\s+present|no\b|lacks?|without|fails?\s+to\s+set)\b", re.I)


def _text(finding, raw_input=""):
    """Everything the finding rests on: its own evidence first, then the original
    input, since a finding's evidence field is often an excerpt of it."""
    parts = [
        str((finding or {}).get("evidence", "") or ""),
        str((finding or {}).get("steps", "") or ""),
        str(raw_input or ""),
    ]
    return "\n".join(p for p in parts if p.strip())


def _headers(text):
    """Header names present anywhere in the text, lowercased.

    Deliberately loose about which response a header belongs to: the question
    these verifiers answer is whether the evidence shows the header at all.
    """
    found = {}
    for name, value in _HEADER_LINE.findall(text):
        found.setdefault(name.lower(), []).append(value.strip())
    return found


def _looks_like_http_response(text):
    """Whether the evidence contains something recognisable as a response.

    Without this, every verifier would 'refute' claims by reading silence as
    absence, which is the one mistake that would make this layer worse than
    nothing.
    """
    return bool(_STATUS_LINE.search(text)) or len(_headers(text)) >= 2


def _result(status, verifier, detail, evidence=""):
    return {"status": status, "verifier": verifier, "detail": detail, "evidence": evidence[:300]}


# --- individual verifiers ----------------------------------------------------

def verify_missing_header(finding, raw_input=""):
    """A claim that a security header is missing, checked against the response."""
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    target = next((k for k in SECURITY_HEADERS if k in title.replace(" ", "-")), None)
    if not target:
        return None                      # not a claim this verifier handles
    if not _MISSING_WORDS.search(title):
        return None                      # a claim ABOUT the header, not that it is absent

    text = _text(finding, raw_input)
    if not _looks_like_http_response(text):
        return _result(INSUFFICIENT, "missing_header",
                       f"No HTTP response in the evidence, so the absence of {SECURITY_HEADERS[target]} cannot be established.")

    present = _headers(text)
    if target in present:
        return _result(REFUTED, "missing_header",
                       f"{SECURITY_HEADERS[target]} is claimed missing but appears in the response.",
                       f"{SECURITY_HEADERS[target]}: {present[target][0]}")
    return _result(CONFIRMED, "missing_header",
                   f"{SECURITY_HEADERS[target]} does not appear in the response headers in the evidence.")


def verify_cookie_flags(finding, raw_input=""):
    """A claim that a cookie lacks Secure, HttpOnly or SameSite."""
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if "cookie" not in title:
        return None
    flags = [f for f in ("secure", "httponly", "samesite") if f in title.replace("-", "")]
    if not flags or not _MISSING_WORDS.search(title):
        return None

    text = _text(finding, raw_input)
    cookies = [v for k, vals in _headers(text).items() if k == "set-cookie" for v in vals]
    if not cookies:
        return _result(INSUFFICIENT, "cookie_flags",
                       "No Set-Cookie header in the evidence, so the cookie's attributes cannot be checked.")

    for flag in flags:
        # A claim is refuted only if EVERY cookie carries the flag; one hardened
        # cookie does not clear a set that also contains a bare one.
        if all(re.search(rf"\b{flag}\b", c, re.I) for c in cookies):
            return _result(REFUTED, "cookie_flags",
                           f"The cookie is claimed to lack {flag}, but every Set-Cookie in the evidence sets it.",
                           cookies[0])
    missing = [f for f in flags if not any(re.search(rf"\b{f}\b", c, re.I) for c in cookies)]
    if missing:
        return _result(CONFIRMED, "cookie_flags",
                       f"No Set-Cookie in the evidence sets {', '.join(missing)}.", cookies[0])
    return _result(INSUFFICIENT, "cookie_flags", "Some cookies set the attribute and some do not.")


def verify_cors(finding, raw_input=""):
    """A claim of a permissive CORS policy: wildcard origin with credentials."""
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if "cors" not in title and "access-control" not in title and "cross-origin" not in title:
        return None

    text = _text(finding, raw_input)
    h = _headers(text)
    origin = h.get("access-control-allow-origin", [])
    creds = h.get("access-control-allow-credentials", [])
    if not origin:
        return _result(INSUFFICIENT, "cors",
                       "No Access-Control-Allow-Origin header in the evidence.")

    wildcard = any(v.strip() == "*" for v in origin)
    creds_true = any(v.strip().lower() == "true" for v in creds)

    if wildcard and creds_true:
        # Worth stating plainly: browsers reject this combination outright, so the
        # real risk is a server that reflects the request origin instead.
        return _result(CONFIRMED, "cors",
                       "Access-Control-Allow-Origin is * with credentials enabled. Note that browsers "
                       "refuse this combination, so the exploitable form is origin reflection rather than "
                       "a literal wildcard.",
                       f"{origin[0]} / credentials: {creds[0]}")
    if wildcard:
        return _result(CONFIRMED, "cors", "Access-Control-Allow-Origin is a wildcard.", origin[0])
    if creds_true and "reflect" in title:
        return _result(CONFIRMED, "cors",
                       "Credentials are allowed and the origin is not a wildcard, consistent with reflection.",
                       f"{origin[0]} / credentials: {creds[0]}")
    if not wildcard and not creds_true and ("wildcard" in title or "credential" in title):
        return _result(REFUTED, "cors",
                       "A permissive CORS policy is claimed, but the evidence shows neither a wildcard "
                       "origin nor credentials enabled.",
                       origin[0])
    return _result(INSUFFICIENT, "cors", "CORS headers are present but do not settle the claim.")


def verify_reflection(finding, raw_input=""):
    """A reflected-input claim: the payload must actually appear in the response.

    This is the check that catches the most common fabrication -- a reflected XSS
    reported when nothing was ever echoed back.
    """
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if not re.search(r"\b(reflect\w*|xss|cross[- ]site scripting)\b", title):
        return None

    text = _text(finding, raw_input)
    if not _looks_like_http_response(text):
        return _result(INSUFFICIENT, "reflection", "No HTTP response in the evidence to check for reflection.")

    payloads = re.findall(r"(<script[^>]*>.*?</script>|<img[^>]+onerror\s*=[^>]*>|<svg[^>]+on\w+\s*=[^>]*>|javascript:[^\s\"'<>]+)", text, re.I | re.S)
    if not payloads:
        return _result(INSUFFICIENT, "reflection",
                       "No recognisable payload in the evidence, so reflection cannot be verified.")

    # Split at the response boundary and ask whether the payload survives into it.
    m = _STATUS_LINE.search(text)
    body = text[m.start():] if m else text
    for p in payloads:
        occurrences = len(re.findall(re.escape(p), body, re.I))
        if occurrences:
            encoded = re.search(re.escape(p.replace("<", "&lt;").replace(">", "&gt;")), body, re.I)
            if encoded:
                return _result(INSUFFICIENT, "reflection",
                               "The payload appears both raw and HTML-encoded; which one the response "
                               "returned cannot be determined from this excerpt.", p[:120])
            return _result(CONFIRMED, "reflection",
                           "The payload appears unencoded in the response.", p[:120])

    # Not reflected raw. Encoding the payload is what a page that correctly handles
    # the input does, so finding the encoded form in the RESPONSE refutes the claim.
    # Checked against the body rather than the whole text: the request naturally
    # contains the raw payload, and matching there would prove nothing.
    for p in payloads:
        encoded = (p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
                   p.replace("<", "%3C").replace(">", "%3E"),
                   p.replace("<", "\\u003c").replace(">", "\\u003e"))
        for form in encoded:
            if form != p and re.search(re.escape(form), body, re.I):
                return _result(REFUTED, "reflection",
                               "The payload appears in the response HTML-encoded rather than raw, which is "
                               "the behaviour of a page that handles the input correctly.", form[:120])
    return _result(INSUFFICIENT, "reflection", "A payload was submitted but does not appear in the response excerpt.")


def verify_tls_version(finding, raw_input=""):
    """A claim about a deprecated TLS or SSL version being enabled."""
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if not re.search(r"\b(tls|ssl)\b", title):
        return None
    claimed = re.search(r"\b(ssl\s*[23]|tls\s*1\.[01])\b", title)
    if not claimed:
        return None

    version = claimed.group(1).replace(" ", "").upper()
    text = _text(finding, raw_input)
    if not re.search(r"\b(tls|ssl)\w*\s*1?\.?\d", text, re.I):
        return _result(INSUFFICIENT, "tls_version", "The evidence does not name any negotiated protocol version.")

    pattern = version.replace(".", r"\.?").replace("TLS", r"TLSv?").replace("SSL", r"SSLv?")
    if re.search(pattern, text, re.I):
        return _result(CONFIRMED, "tls_version", f"{version} appears in the evidence as supported.")
    return _result(INSUFFICIENT, "tls_version",
                   f"{version} is claimed but does not appear in the evidence; a scan output naming the "
                   "enabled protocols is needed.")


def verify_status_code(finding, raw_input=""):
    """An access-control claim asserting a successful response.

    A finding that says an unauthorized request succeeded, sitting on evidence
    whose only response is a 401 or 403, is contradicting itself.
    """
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if not re.search(r"\b(idor|bola|broken (object|function) level|unauthori[sz]ed access|access control|privilege escalation|authenticat\w* bypass)\b", title):
        return None

    text = _text(finding, raw_input)
    codes = [int(c) for c in _STATUS_LINE.findall(text)]
    if not codes:
        return _result(INSUFFICIENT, "status_code", "No HTTP status line in the evidence.")

    if any(200 <= c < 300 for c in codes):
        return _result(CONFIRMED, "status_code",
                       f"The evidence contains a successful response ({', '.join(str(c) for c in codes if 200 <= c < 300)}), "
                       "consistent with access having been granted.")
    if all(c in (401, 403) for c in codes):
        return _result(REFUTED, "status_code",
                       f"The claim is that access succeeded, but every response in the evidence is "
                       f"{', '.join(str(c) for c in sorted(set(codes)))}.")
    return _result(INSUFFICIENT, "status_code",
                   f"Responses present ({', '.join(str(c) for c in sorted(set(codes)))}) do not settle the claim.")


def verify_directory_listing(finding, raw_input=""):
    """A directory-listing claim: the response should show an actual index."""
    title = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if "directory listing" not in title and "autoindex" not in title and "index of" not in title:
        return None

    text = _text(finding, raw_input)
    if not _looks_like_http_response(text):
        return _result(INSUFFICIENT, "directory_listing", "No HTTP response in the evidence.")
    if re.search(r"<title>\s*Index of|<h1>\s*Index of|Directory listing for", text, re.I):
        entries = len(re.findall(r'<a\s+href="[^"]+"', text, re.I))
        if entries <= 1:
            return _result(CONFIRMED, "directory_listing",
                           "An index page is present, but it lists no files. Listing an empty directory "
                           "discloses nothing, which bears on severity.")
        return _result(CONFIRMED, "directory_listing", f"An index page listing {entries} entries is present.")
    return _result(INSUFFICIENT, "directory_listing",
                   "The evidence does not contain an index page, so the listing cannot be confirmed.")


VERIFIERS = (
    verify_missing_header,
    verify_cookie_flags,
    verify_cors,
    verify_reflection,
    verify_tls_version,
    verify_status_code,
    verify_directory_listing,
)


def verify_finding(finding, raw_input=""):
    """Run every applicable verifier over one finding.

    Returns None when no verifier claims the finding, which is the common case and
    is not a failure: most classes cannot be settled from text alone, and saying so
    is more useful than guessing.
    """
    results = []
    for fn in VERIFIERS:
        try:
            r = fn(finding or {}, raw_input)
        except Exception as exc:                      # a broken verifier must never
            r = _result(INSUFFICIENT, fn.__name__,    # break an analysis
                        f"Verifier error: {exc}")
        if r:
            results.append(r)
    if not results:
        return None

    if any(r["status"] == REFUTED for r in results):
        overall = REFUTED
    elif any(r["status"] == CONFIRMED for r in results):
        overall = CONFIRMED
    else:
        overall = INSUFFICIENT

    return {
        "status": overall,
        "checks": results,
        "summary": "; ".join(r["detail"] for r in results),
    }
