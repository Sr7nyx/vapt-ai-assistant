"""Deterministic verification of a finding's claim against its own evidence.

Every check runs against ONE exchange, chosen by evidence_model.bind() from the
finding's own URL, parameter and method. That scoping is the substance of this
module, not a detail of it: the previous version searched the whole submission, so
a header present on /login refuted a finding about /admin, a 200 belonging to the
authorised baseline "confirmed" an IDOR, and a payload from a later request
appeared to be reflected by an earlier one. Those were false CONFIRMATIONS and
false REFUTATIONS from the component the verdict engine weights above the
reviewer, which is worse than having no verifier at all.

Three answers, and the third is the important one:

    CONFIRMED     the bound exchange demonstrably supports the claim
    REFUTED       the bound exchange demonstrably contradicts it
    INSUFFICIENT  the evidence does not settle it -- including when the finding
                  cannot be tied to a specific exchange

Refusing to decide is a feature. A verifier that guesses which exchange a finding
meant has reintroduced the bug this scoping removes.
"""
import re

import evidence_model as em

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
INSUFFICIENT = "INSUFFICIENT"

# Findings say "CSP" and "HSTS" far more often than the full header name, so the
# abbreviations have to resolve or the check silently never fires.
HEADER_ALIASES = {
    "csp": "content-security-policy",
    "hsts": "strict-transport-security",
    "xfo": "x-frame-options",
    "x-frame options": "x-frame-options",
    "nosniff": "x-content-type-options",
    "content type options": "x-content-type-options",
    "referrer policy": "referrer-policy",
    "permissions policy": "permissions-policy",
    "content security policy": "content-security-policy",
    "strict transport security": "strict-transport-security",
}

SECURITY_HEADERS = {
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

_MISSING_WORDS = re.compile(
    r"\b(missing|absent|not\s+set|not\s+present|no\b|lacks?|without|fails?\s+to\s+set)\b", re.I
)


def _result(status, verifier, detail, exchange=None, evidence=""):
    return {
        "status": status,
        "verifier": verifier,
        "detail": detail,
        "exchange_id": (exchange or {}).get("id", ""),
        "evidence": evidence[:300],
    }


def _title(finding):
    return f"{(finding or {}).get('title','')} {(finding or {}).get('description','')}".lower()


# --- individual verifiers, each scoped to one exchange ------------------------

def _named_header(title):
    hyphenated = title.replace(" ", "-")
    for key in SECURITY_HEADERS:
        if key in hyphenated:
            return key
    for alias, key in HEADER_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", title):
            return key
    return None


def verify_missing_header(finding, ex):
    title = _title(finding)
    target = _named_header(title)
    if not target or not _MISSING_WORDS.search(title):
        return None
    if not (ex.get("response") or {}):
        return _result(INSUFFICIENT, "missing_header",
                       "The bound exchange has no response, so header absence cannot be established.", ex)

    values = em.header(ex, target)
    name = SECURITY_HEADERS[target]
    if values:
        return _result(REFUTED, "missing_header",
                       f"{name} is claimed missing but is present on this response.",
                       ex, f"{name}: {values[0]}")
    return _result(CONFIRMED, "missing_header",
                   f"{name} is absent from this response.", ex)


def verify_cookie_flags(finding, ex):
    title = _title(finding)
    if "cookie" not in title or not _MISSING_WORDS.search(title):
        return None
    flags = [f for f in ("secure", "httponly", "samesite") if f in title.replace("-", "")]
    if not flags:
        return None

    cookies = em.header(ex, "set-cookie")
    if not cookies:
        return _result(INSUFFICIENT, "cookie_flags",
                       "This response sets no cookie, so its attributes cannot be checked.", ex)

    for flag in flags:
        if all(re.search(rf"\b{flag}\b", c, re.I) for c in cookies):
            return _result(REFUTED, "cookie_flags",
                           f"The cookie is claimed to lack {flag}, but every cookie set here has it.",
                           ex, cookies[0])
    missing = [f for f in flags if not any(re.search(rf"\b{f}\b", c, re.I) for c in cookies)]
    if missing:
        return _result(CONFIRMED, "cookie_flags",
                       f"No cookie set by this response carries {', '.join(missing)}.", ex, cookies[0])
    return _result(INSUFFICIENT, "cookie_flags",
                   "Some cookies here set the attribute and some do not.", ex)


def verify_cors(finding, ex):
    title = _title(finding)
    if not any(k in title for k in ("cors", "access-control", "cross-origin")):
        return None

    origin = em.header(ex, "access-control-allow-origin")
    creds = em.header(ex, "access-control-allow-credentials")
    if not origin:
        return _result(INSUFFICIENT, "cors",
                       "This response sets no Access-Control-Allow-Origin.", ex)

    wildcard = any(v.strip() == "*" for v in origin)
    creds_true = any(v.strip().lower() == "true" for v in creds)
    sent = em.request_header(ex, "origin")
    reflected = bool(sent) and any(v.strip() == sent[0].strip() for v in origin)

    if wildcard and creds_true:
        return _result(CONFIRMED, "cors",
                       "Wildcard origin with credentials enabled. Browsers refuse this combination, "
                       "so the exploitable form is origin reflection rather than a literal wildcard.",
                       ex, f"{origin[0]} / credentials: {creds[0]}")
    if reflected:
        # The strong case, and only checkable now that the REQUEST is available.
        detail = "The request's Origin is echoed back in Access-Control-Allow-Origin"
        detail += " with credentials enabled." if creds_true else ", though credentials are not enabled."
        return _result(CONFIRMED if creds_true else INSUFFICIENT, "cors", detail,
                       ex, f"Origin: {sent[0]} -> {origin[0]}")
    if wildcard:
        return _result(CONFIRMED, "cors", "Access-Control-Allow-Origin is a wildcard.", ex, origin[0])
    if "wildcard" in title or "arbitrary" in title or "any origin" in title:
        return _result(REFUTED, "cors",
                       "A permissive policy is claimed, but this response neither uses a wildcard nor "
                       "reflects the requesting origin.", ex, origin[0])
    return _result(INSUFFICIENT, "cors", "CORS headers present but they do not settle the claim.", ex)


# Where a payload lands decides whether reflection is exploitable at all.
_CTX_SCRIPT = "inside a script block"
_CTX_ATTR = "inside an HTML attribute"
_CTX_HTML = "in the HTML body"
_CTX_TEXT = "in a non-HTML response"

_PAYLOAD = re.compile(
    r"(<script[^>]*>.*?</script>|<img[^>]+on\w+\s*=[^>]*>|<svg[^>]+on\w+\s*=[^>]*>|javascript:[^\s\"'<>]+|['\"][^'\"]*\balert\s*\()",
    re.I | re.S,
)


def _context_of(body, payload):
    """Where in the response the payload landed."""
    idx = body.lower().find(payload.lower())
    if idx < 0:
        return None
    before = body[:idx]
    open_script = before.lower().rfind("<script")
    close_script = before.lower().rfind("</script>")
    if open_script > close_script:
        return _CTX_SCRIPT
    tag_open = before.rfind("<")
    tag_close = before.rfind(">")
    if tag_open > tag_close:
        return _CTX_ATTR
    return _CTX_HTML


def verify_reflection(finding, ex):
    title = _title(finding)
    if not re.search(r"\b(reflect\w*|xss|cross[- ]site scripting)\b", title):
        return None

    req = ex.get("request") or {}
    resp = ex.get("response") or {}
    if not resp:
        return _result(INSUFFICIENT, "reflection", "The bound exchange has no response.", ex)

    body = resp.get("body") or ""
    # Only payloads submitted in THIS request count. The previous version searched
    # the whole submission, so a payload from a later request looked reflected here.
    submitted = " ".join(
        [req.get("target", ""), req.get("body", "")]
        + [v for vs in (req.get("params") or {}).values() for v in vs]
    )
    payloads = _PAYLOAD.findall(submitted)
    if not payloads:
        return _result(INSUFFICIENT, "reflection",
                       "This request submits no recognisable payload, so reflection cannot be checked.", ex)

    for p in payloads:
        ctx = _context_of(body, p)
        if ctx:
            executable = ctx in (_CTX_SCRIPT, _CTX_ATTR) or p.lower().startswith("<script")
            if not (resp.get("headers") or {}).get("content-type"):
                ctype = ""
            else:
                ctype = (resp["headers"]["content-type"][0] or "").lower()
            if ctype and "html" not in ctype:
                return _result(INSUFFICIENT, "reflection",
                               f"The payload is returned verbatim, but the response is {ctype.split(';')[0]}, "
                               "so it is reflection without an executable context.", ex, p[:120])
            if executable:
                return _result(CONFIRMED, "reflection",
                               f"The payload is returned unencoded {ctx}, which is an executable context.",
                               ex, p[:120])
            return _result(INSUFFICIENT, "reflection",
                           f"The payload is returned unencoded {ctx}. Reflection is demonstrated; "
                           "execution in a browser is not, and needs a proof of concept.", ex, p[:120])

    for p in payloads:
        for form in (
            p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
            p.replace("<", "%3C").replace(">", "%3E"),
            p.replace("<", "\\u003c").replace(">", "\\u003e"),
        ):
            if form != p and form.lower() in body.lower():
                return _result(REFUTED, "reflection",
                               "The payload is returned encoded rather than raw, which is what a response "
                               "that handles the input correctly does.", ex, form[:120])
    return _result(INSUFFICIENT, "reflection",
                   "A payload was submitted but does not appear in this response.", ex)


def _principal(ex):
    """Whatever identifies the caller. Not authentication -- just enough to tell
    two requests apart, which is all the access-control check needs."""
    for name in ("authorization", "cookie", "x-api-key"):
        vals = em.request_header(ex, name)
        if vals:
            return f"{name}:{vals[0][:60]}"
    return ""


def _object_ref(ex):
    """The object being addressed: an id-like parameter, or the path itself."""
    req = ex.get("request") or {}
    for key, vals in (req.get("params") or {}).items():
        if re.search(r"(^|_)(id|uid|user|account|order|doc|file|obj)", key, re.I) and vals:
            return f"{key}={vals[0]}"
    m = re.search(r"/(\d{1,12})(?:/|$)", req.get("path") or "")
    return f"path:{m.group(1)}" if m else ""


def verify_access_control(finding, exchanges):
    """An access-control claim is about a RELATIONSHIP between exchanges.

    This one deliberately does not take a bound exchange. Headers and reflection are
    properties of a single response, so binding to one is right; "principal A
    reached principal B's object" is a property of a SET, and asking which single
    exchange it belongs to has no answer -- both of them, or neither.

    A 200 proves nothing alone. It may be the authorised baseline, a login page, an
    error rendered with status 200, a public object, or the same caller fetching
    their own record. What the claim needs is: one caller, two different objects,
    both retrieved, different content back.
    """
    title = _title(finding)
    if not re.search(
        r"\b(idor|bola|broken (object|function) level|unauthori[sz]ed access|access control|"
        r"privilege escalation|authenticat\w* bypass)\b", title):
        return None

    usable = [e for e in exchanges if (e.get("request") and e.get("response"))]
    if not usable:
        return _result(INSUFFICIENT, "access_control",
                       "The evidence contains no complete request/response pair.")

    # Group by caller, then look for one caller touching two distinct objects.
    by_principal = {}
    for e in usable:
        by_principal.setdefault(_principal(e), []).append(e)

    denied = []
    for principal, group in by_principal.items():
        if not principal:
            continue
        seen = {}
        for e in group:
            obj = _object_ref(e)
            status = (e["response"] or {}).get("status", 0)
            if not obj:
                continue
            if 200 <= status < 300:
                seen[obj] = e
            elif status in (401, 403):
                denied.append((obj, status))

        if len(seen) >= 2:
            objs = list(seen.items())
            for i in range(len(objs)):
                for j in range(i + 1, len(objs)):
                    (oa, ea), (ob, eb) = objs[i], objs[j]
                    ba = ((ea["response"] or {}).get("body") or "").strip()
                    bb = ((eb["response"] or {}).get("body") or "").strip()
                    if ba and bb and ba != bb:
                        return _result(CONFIRMED, "access_control",
                                       f"One caller retrieved two different objects ({oa} and {ob}) and "
                                       "received different content for each, which is the pattern this "
                                       "finding claims.", ea, f"{oa} vs {ob}")
            return _result(INSUFFICIENT, "access_control",
                           "The same caller retrieved several objects, but the responses are identical, "
                           "so no protected content belonging to another principal is shown.", None)

    # Every cross-object attempt was refused: the claim is contradicted.
    successes = [e for e in usable if 200 <= (e["response"] or {}).get("status", 0) < 300]
    if denied and len(successes) <= 1:
        codes = ", ".join(str(c) for _, c in denied)
        return _result(REFUTED, "access_control",
                       f"The claim is that access succeeded, but every request for another object was "
                       f"refused ({codes}). The successful response is the caller's own baseline.")

    if successes:
        return _result(INSUFFICIENT, "access_control",
                       "A successful response alone does not establish an access-control failure: it may be "
                       "the authorised baseline, a public object, or the caller's own record. Evidence needs "
                       "one caller retrieving another principal's object.")

    return _result(INSUFFICIENT, "access_control",
                   "No successful response, so unauthorised access is not demonstrated.")


def verify_directory_listing(finding, ex):
    title = _title(finding)
    if not any(k in title for k in ("directory listing", "autoindex", "index of")):
        return None
    body = ((ex.get("response") or {}).get("body")) or ""
    if not body:
        return _result(INSUFFICIENT, "directory_listing", "The bound exchange has no response body.", ex)
    if re.search(r"<title>\s*Index of|<h1>\s*Index of|Directory listing for", body, re.I):
        entries = len(re.findall(r'<a\s+href="[^"]+"', body, re.I))
        if entries <= 1:
            return _result(CONFIRMED, "directory_listing",
                           "An index page is present but lists no files, which bears on severity.", ex)
        return _result(CONFIRMED, "directory_listing", f"An index page listing {entries} entries.", ex)
    return _result(INSUFFICIENT, "directory_listing", "No index page in this response.", ex)



# --- classes the structured evidence model made possible ----------------------
#
# Each of these needs something the old text-search could not reach: the request
# that produced a response, or the relationship between two exchanges. They are
# short because the parsing is done; that is the point of having done it.


def verify_open_redirect(finding, ex):
    """A redirect claim: the Location must actually be attacker-controlled.

    Needs the request, not just the response -- the question is whether a value the
    caller supplied ended up in Location, and a response alone cannot answer that.
    """
    title = _title(finding)
    if not re.search(r"\b(open redirect|unvalidated redirect|url redirection)\b", title):
        return None

    resp = ex.get("response") or {}
    status = resp.get("status", 0)
    location = em.header(ex, "location")
    if not location:
        return _result(INSUFFICIENT, "open_redirect",
                       "This response sets no Location header.", ex)
    if not (300 <= status < 400):
        return _result(INSUFFICIENT, "open_redirect",
                       f"Location is present but the status is {status}, so no redirect was issued.", ex)

    target = location[0].strip()
    req = ex.get("request") or {}
    supplied = [v for vs in (req.get("params") or {}).values() for v in vs]
    supplied += re.findall(r"=([^&\s]+)", req.get("body") or "")

    external = re.match(r"^(https?:)?//", target) or target.startswith("http")
    controlled = any(
        val and (val in target or _unquote(val) in target)
        for val in supplied
        if len(val) > 3
    )

    if external and controlled:
        return _result(CONFIRMED, "open_redirect",
                       "A caller-supplied value appears in a Location pointing off-site.",
                       ex, f"{status} -> {target[:120]}")
    if external and not controlled:
        return _result(INSUFFICIENT, "open_redirect",
                       "The redirect leaves the site, but no request parameter matches the target, so "
                       "caller control is not shown.", ex, target[:120])
    if controlled and not external:
        return _result(REFUTED, "open_redirect",
                       "The redirect target is caller-influenced but stays on this host, which is not an "
                       "open redirect.", ex, target[:120])
    return _result(REFUTED, "open_redirect",
                   "The redirect is to a fixed same-site location.", ex, target[:120])


def _unquote(v):
    from urllib.parse import unquote
    try:
        return unquote(v)
    except Exception:
        return v


def verify_jwt_alg_none(finding, ex):
    """A JWT algorithm claim, checked by decoding the token's own header."""
    title = _title(finding)
    if not re.search(r"\bjwt\b|json web token|\balg\b", title):
        return None

    blob = " ".join(
        [ex.get("raw", "")]
    )
    tokens = re.findall(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_-]*", blob)
    if not tokens:
        return _result(INSUFFICIENT, "jwt_alg", "No JWT appears in this exchange.", ex)

    import base64
    import json as _json

    for tok in tokens:
        head_b64 = tok.split(".")[0]
        try:
            pad = head_b64 + "=" * (-len(head_b64) % 4)
            header = _json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", "replace"))
        except Exception:
            continue
        alg = str(header.get("alg", "")).lower()
        if not alg:
            continue
        if alg == "none":
            return _result(CONFIRMED, "jwt_alg",
                           "The token's own header declares alg: none, so its signature is not checked.",
                           ex, f"header: {header}")
        if "none" in title or "unsigned" in title:
            return _result(REFUTED, "jwt_alg",
                           f"The claim is that the token is unsigned, but its header declares alg: {header.get('alg')}.",
                           ex, f"header: {header}")
        return _result(INSUFFICIENT, "jwt_alg",
                       f"The token declares alg: {header.get('alg')}. Whether it is verified cannot be "
                       "determined from the token alone.", ex, f"header: {header}")
    return _result(INSUFFICIENT, "jwt_alg", "A JWT-shaped string is present but its header could not be decoded.", ex)


def verify_cacheable_sensitive(finding, ex):
    """A response carrying a session may not be cached. Needs both directions."""
    title = _title(finding)
    if not re.search(r"\bcache\w*|cacheable\b", title):
        return None

    resp = ex.get("response") or {}
    if not resp:
        return _result(INSUFFICIENT, "cacheable", "The bound exchange has no response.", ex)

    cache = " ".join(em.header(ex, "cache-control")).lower()
    pragma = " ".join(em.header(ex, "pragma")).lower()
    prevented = any(d in cache for d in ("no-store", "private")) or "no-cache" in pragma or "no-cache" in cache

    authenticated = bool(em.request_header(ex, "authorization") or em.request_header(ex, "cookie"))
    sets_session = any(
        re.search(r"\b(session|sid|jsessionid|phpsessid|auth|token)\b", c, re.I)
        for c in em.header(ex, "set-cookie")
    )

    if prevented:
        return _result(REFUTED, "cacheable",
                       f"The response prevents caching ({cache or pragma}).", ex)
    if authenticated or sets_session:
        return _result(CONFIRMED, "cacheable",
                       "The response carries authenticated content and sets no directive preventing "
                       "storage, so a shared cache may retain it.", ex,
                       f"cache-control: {cache or 'absent'}")
    return _result(INSUFFICIENT, "cacheable",
                   "No caching directive, but nothing shows the content is user-specific, so this may be "
                   "correctly cacheable.", ex)


_STACK_MARKERS = re.compile(
    r"(Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+:\d+\)|"
    r"\w+Exception\b|\w+Error:\s|Warning: \w+\(\)|"
    r"ORA-\d{5}|SQLSTATE\[|You have an error in your SQL syntax|"
    r"System\.\w+Exception|org\.springframework|java\.lang\.|"
    r"in /\w[\w/]*\.php on line \d+)",
)


def verify_error_disclosure(finding, ex):
    """A verbose-error claim: the response body must actually contain one."""
    title = _title(finding)
    if not re.search(r"\b(stack trace|error (message|disclosure)|verbose error|debug (output|information)|"
                     r"information disclosure)\b", title):
        return None

    body = ((ex.get("response") or {}).get("body")) or ""
    if not body.strip():
        return _result(INSUFFICIENT, "error_disclosure", "The bound exchange has no response body.", ex)

    m = _STACK_MARKERS.search(body)
    if m:
        return _result(CONFIRMED, "error_disclosure",
                       "The response body contains an interpreter or framework error trace.",
                       ex, m.group(0)[:120])
    status = (ex.get("response") or {}).get("status", 0)
    if status >= 500:
        return _result(INSUFFICIENT, "error_disclosure",
                       f"The response is a {status} but its body carries no recognisable trace, so nothing "
                       "is shown to be disclosed.", ex)
    return _result(REFUTED, "error_disclosure",
                   "The response body contains no error trace or diagnostic output.", ex)


def verify_session_fixation(finding, exchanges):
    """Set-level: the session identifier must CHANGE across authentication.

    Cannot be answered by one exchange. The claim is about what happened between
    two of them, which is only checkable now that they are ordered and parsed.
    """
    title = _title(finding)
    if not re.search(r"session fixation|session (id|identifier) (not )?(re)?generat", title):
        return None

    def session_of(e):
        for c in em.header(e, "set-cookie"):
            m = re.match(r"\s*([\w.-]*(?:session|sid|jsessionid|phpsessid)[\w.-]*)\s*=\s*([^;]+)", c, re.I)
            if m:
                return m.group(1), m.group(2).strip()
        return None, None

    def is_login(e):
        req = e.get("request") or {}
        path = (req.get("path") or "").lower()
        body = (req.get("body") or "").lower()
        return "login" in path or "signin" in path or "auth" in path or "password=" in body

    issued = [(i, *session_of(e), e) for i, e in enumerate(exchanges)]
    issued = [t for t in issued if t[1]]
    if len(issued) < 2:
        return _result(INSUFFICIENT, "session_fixation",
                       "Fewer than two session cookies were issued in this evidence, so a change across "
                       "authentication cannot be observed.")

    login_idx = next((i for i, e in enumerate(exchanges) if is_login(e)), None)
    if login_idx is None:
        return _result(INSUFFICIENT, "session_fixation",
                       "No authentication request is present, so there is nothing to compare across.")

    before = [t for t in issued if t[0] < login_idx]
    after = [t for t in issued if t[0] >= login_idx]
    if not before or not after:
        return _result(INSUFFICIENT, "session_fixation",
                       "The evidence does not contain a session cookie both before and after the "
                       "authentication request.")

    if before[-1][2] == after[0][2]:
        return _result(CONFIRMED, "session_fixation",
                       f"The {before[-1][1]} value is unchanged across authentication, so a session fixed "
                       "before login remains valid after it.", after[0][3], before[-1][2][:60])
    return _result(REFUTED, "session_fixation",
                   f"The {before[-1][1]} value is regenerated at authentication, which is the correct "
                   "behaviour.", after[0][3])


def verify_rate_limiting(finding, exchanges):
    """Set-level: repeated identical requests must eventually be refused."""
    title = _title(finding)
    if not re.search(r"rate limit|brute[- ]force|account lockout|throttl", title):
        return None

    usable = [e for e in exchanges if e.get("request") and e.get("response")]
    if len(usable) < 3:
        return _result(INSUFFICIENT, "rate_limiting",
                       f"Only {len(usable)} exchange(s) present. Absence of rate limiting is shown by "
                       "repetition, so several identical attempts are needed.")

    groups = {}
    for e in usable:
        req = e["request"]
        groups.setdefault((req["method"], req["path"]), []).append(e)

    for (method, path), group in groups.items():
        if len(group) < 3:
            continue
        codes = [(g["response"] or {}).get("status", 0) for g in group]
        if any(c == 429 for c in codes):
            return _result(REFUTED, "rate_limiting",
                           f"{method} {path} was repeated {len(group)} times and answered 429, so requests "
                           "are being throttled.", group[0], f"statuses: {codes}")
        if all(200 <= c < 400 for c in codes):
            return _result(CONFIRMED, "rate_limiting",
                           f"{method} {path} was repeated {len(group)} times and every attempt was accepted "
                           f"({', '.join(str(c) for c in codes)}), with no throttling response.",
                           group[0], f"statuses: {codes}")
    return _result(INSUFFICIENT, "rate_limiting",
                   "No single endpoint is repeated enough times in this evidence to show whether attempts "
                   "are limited.")


SET_VERIFIERS = (verify_access_control, verify_session_fixation, verify_rate_limiting)

SINGLE_EXCHANGE_VERIFIERS = (
    verify_missing_header,
    verify_cookie_flags,
    verify_cors,
    verify_reflection,
    verify_directory_listing,
    verify_open_redirect,
    verify_jwt_alg_none,
    verify_cacheable_sensitive,
    verify_error_disclosure,
)


def verify_finding(finding, raw_input=""):
    """Check a finding against the exchange it is about.

    Returns None when no verifier handles this class of claim -- the common case,
    and not a failure. Most finding classes cannot be settled from text, and saying
    so is more useful than guessing.
    """
    finding = finding or {}
    text = "\n\n".join(
        t for t in (str(finding.get("evidence") or ""), str(raw_input or "")) if t.strip()
    )
    exchanges = em.parse_exchanges(text)
    if not exchanges:
        return None

    ex, why = em.bind(finding, exchanges)

    # Does any verifier even claim this finding? Checked before reporting a binding
    # failure, so an unrelated finding is not told the evidence was ambiguous.
    results = []

    # Set-level claims first: they describe a relationship between exchanges, so
    # they run whether or not a single exchange could be identified.
    for fn in SET_VERIFIERS:
        try:
            r = fn(finding, exchanges)
        except Exception as exc:
            r = _result(INSUFFICIENT, fn.__name__, f"Verifier error: {exc}")
        if r:
            results.append(r)

    probe = ex or exchanges[0]

    def _claims(fn):
        """Whether a verifier handles this finding. Guarded: this runs before the
        main loop, so an exception here would escape the loop's own protection."""
        try:
            return fn(finding, probe) is not None
        except Exception:
            return True     # it claimed the finding and then failed; report that

    per_exchange_claims = any(_claims(fn) for fn in SINGLE_EXCHANGE_VERIFIERS)

    if not results and not per_exchange_claims:
        return None

    if per_exchange_claims:
        if ex is None:
            results.append(_result(INSUFFICIENT, "binding", why))
        else:
            for fn in SINGLE_EXCHANGE_VERIFIERS:
                try:
                    r = fn(finding, ex)
                except Exception as exc:
                    r = _result(INSUFFICIENT, fn.__name__, f"Verifier error: {exc}", ex)
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
        "exchange_id": (ex or {}).get("id", ""),
        "exchange_count": len(exchanges),
    }
