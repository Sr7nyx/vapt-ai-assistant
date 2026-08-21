"""Finding-specific retest guidance: the commands a tester actually runs.

Recording a retest outcome already existed (retest.py, the RetestModal). What did
not was the step *before* the outcome: working out how to reproduce this specific
finding again. A tester re-verifying a remediation round was reconstructing the
same nmap line or curl by hand, per finding, every round -- slow, and inconsistent
between testers.

This module produces that guidance. Three principles shape it, and they are the
same ones the rest of this codebase is built on:

DERIVED, NOT STORED.
    A guide is computed from the finding on demand, exactly as a retest campaign is
    derived from the findings rather than kept as a second source of truth. So
    every finding -- including ones committed long before this feature existed --
    has a guide the moment it is asked for, and there is no column to migrate and
    nothing that can drift out of step with the finding it describes.

DETERMINISTIC FIRST, VALUES EXTRACTED NOT INVENTED.
    The class of a finding (a TLS problem, weak SSH algorithms, a missing header)
    selects a template. The template's blanks are filled from fields the finding
    already carries -- affected_host, affected_url, http_method, parameter -- and
    from its evidence, parsed into HTTP exchanges by evidence_model. A value that
    is genuinely absent becomes a labelled placeholder (<TARGET_HOST>), never a
    guess. Nothing here fabricates a host, port, endpoint, parameter or result.

SECRETS NEVER LEAVE.
    Any text drawn from raw evidence is passed through the existing redaction pass
    first, so a reproduction command built from a captured request cannot carry a
    session cookie or bearer token into the guide. Structural fields (host, path,
    method) are not secrets and are used directly.

The AI layer is optional and additive (enrich()). The deterministic guide is
complete on its own; enrichment only rewrites prose notes under the same
no-fabrication constraint, and any failure falls back to the deterministic guide.
"""
from urllib.parse import urlparse

import evidence_model
import redaction
import risk_map

PLACEHOLDER_HOST = "<TARGET_HOST>"
PLACEHOLDER_PORT = "<PORT>"
PLACEHOLDER_URL = "<TARGET_URL>"
PLACEHOLDER_PARAM = "<PARAMETER>"


# ---------------------------------------------------------------------------
# Target extraction -- structural facts only, from fields the finding carries.
# ---------------------------------------------------------------------------
def _first_nonempty(*values):
    for v in values:
        s = str(v or "").strip()
        if s:
            return s
    return ""


def _host_from_url(url):
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
    return parsed.hostname or ""


def _scheme_of(url):
    if not url:
        return ""
    return urlparse(url).scheme.lower()


def _port_of(url, scheme):
    """Explicit port from the URL, else the scheme default, else empty.

    Never guessed: an https URL with no port implies 443, but a bare hostname with
    no scheme implies nothing, and gets the placeholder.
    """
    if url:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
        if parsed.port:
            return str(parsed.port)
    if scheme == "https":
        return "443"
    if scheme == "http":
        return "80"
    return ""


def extract_target(finding):
    """The structural target of a finding: host, port, scheme, url, path, method,
    parameter. Missing values are returned empty; the caller substitutes labelled
    placeholders so a tester sees exactly what to fill in.
    """
    finding = finding or {}
    url = _first_nonempty(finding.get("affected_url"))
    host_field = _first_nonempty(finding.get("affected_host"))

    # affected_host may itself be "host:port" or a URL; normalise both.
    host = _host_from_url(host_field) or host_field
    if "://" in host_field or host_field.startswith("//"):
        host = _host_from_url(host_field)
    host = host or _host_from_url(url)

    scheme = _scheme_of(url)
    port = _port_of(url, scheme)
    # A port pinned to affected_host ("example.com:8443") wins -- it is explicit.
    if ":" in host_field and not host_field.startswith(("http", "//")):
        maybe_host, _, maybe_port = host_field.partition(":")
        if maybe_port.isdigit():
            host = host or maybe_host
            port = maybe_port

    path = ""
    if url:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
        path = parsed.path or ""

    return {
        "host": host,
        "port": port,
        "scheme": scheme,
        "url": url,
        "path": path,
        "method": _first_nonempty(finding.get("http_method")).upper(),
        "parameter": _first_nonempty(finding.get("parameter")),
    }


def _bound_exchange(finding):
    """The single HTTP exchange this finding is about, via the existing binder, or
    None when the evidence has no exchange or the binding is ambiguous. Redaction
    is applied to the raw text the caller reads back out."""
    evidence = str((finding or {}).get("evidence") or "")
    if not evidence.strip():
        return None
    exchanges = evidence_model.parse_exchanges(evidence)
    if not exchanges:
        return None
    bound, _reason = evidence_model.bind(finding, exchanges)
    return bound


def _redacted_request_body(finding, exchange):
    """The request body from the bound exchange, redacted. Empty when there is no
    body or no exchange."""
    if not exchange:
        return ""
    req = exchange.get("request") or {}
    body = str(req.get("body") or "").strip()
    if not body:
        return ""
    safe, _ = redaction.redact(body, finding)
    return safe


# ---------------------------------------------------------------------------
# Small builders
# ---------------------------------------------------------------------------
def _cmd(label, command, note=""):
    return {"label": label, "command": command, "note": note}


def _host_or_ph(t):
    return t["host"] or PLACEHOLDER_HOST


def _port_or_ph(t, default=""):
    return t["port"] or default or PLACEHOLDER_PORT


def _url_or_ph(t):
    if t["url"]:
        return t["url"]
    if t["host"]:
        scheme = t["scheme"] or "https"
        return f"{scheme}://{t['host']}{t['path'] or ''}"
    return PLACEHOLDER_URL


# Every placeholder this module can emit, and what the tester must substitute.
# Includes the ones templates introduce directly (a token supplied at test time),
# not just the ones derived from missing finding fields.
_PLACEHOLDER_MEANINGS = [
    (PLACEHOLDER_HOST, "the target hostname or IP"),
    (PLACEHOLDER_PORT, "the service port"),
    (PLACEHOLDER_URL, "the affected URL"),
    (PLACEHOLDER_PARAM, "the affected parameter"),
    ("<TOKEN_B>", "a session token for the lower-privileged test principal"),
    ("<SESSION_COOKIE>", "a valid session cookie, supplied at test time"),
]


def _placeholders_in(guide):
    """Which placeholders the rendered guide actually contains.

    Derived from the finished commands rather than from which finding fields were
    empty, because a template may legitimately fill a blank itself -- the SSH
    template supplies port 22 when none was recorded -- and telling a tester to
    replace <PORT> in a command that already says 22 is worse than saying nothing.
    Scanning the output means the list can never disagree with the commands.
    """
    haystack = "\n".join(
        f"{c.get('command', '')}\n{c.get('note', '')}" for c in guide.get("commands", [])
    )
    return [
        {"placeholder": ph, "means": means}
        for ph, means in _PLACEHOLDER_MEANINGS
        if ph in haystack
    ]


def _placeholders_used(t, *keys):
    """Retained for template call sites; the authoritative list is computed from
    the rendered commands by _placeholders_in()."""
    return []


# ---------------------------------------------------------------------------
# Templates, keyed by weakness class from risk_map.infer_class.
# Each returns a full guide dict. Every command is syntactically valid and uses
# non-destructive verification suitable for authorised retesting.
# ---------------------------------------------------------------------------
def _tls_cert(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t, "443")
    return {
        "objective": "Confirm whether the TLS certificate the finding reported is still "
                     "served -- expired, self-signed, host-mismatched, or issued by an "
                     "untrusted CA.",
        "prerequisites": ["Network reachability to the host on the TLS port."],
        "commands": [
            _cmd("Read the served certificate (OpenSSL)",
                 f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null "
                 f"| openssl x509 -noout -subject -issuer -dates -ext subjectAltName",
                 "Shows validity window (notBefore/notAfter), issuer, and SANs in one line."),
            _cmd("Certificate + cipher detail (Nmap)",
                 f"nmap -Pn -p {port} --script ssl-cert,ssl-enum-ciphers {host}",
                 "ssl-cert prints validity and issuer; ssl-enum-ciphers is included so a "
                 "cipher/protocol retest can run in the same pass."),
            _cmd("Full TLS posture (testssl.sh)",
                 f"testssl.sh --severity LOW {host}:{port}",
                 "Optional deep check if testssl.sh is available."),
        ],
        "expected_vulnerable": [
            "notAfter earlier than today (expired), or notBefore in the future.",
            "Issuer is self-referential (subject == issuer) or a CA the client's trust "
            "store does not include.",
            "subjectAltName does not contain the hostname being tested.",
        ],
        "expected_remediated": [
            "notAfter is comfortably in the future and notBefore is in the past.",
            "Issuer is a trusted public or enterprise CA.",
            "subjectAltName includes the exact hostname; no name-mismatch warning.",
        ],
        "pass_fail": "PASS when the served certificate is valid, in date, hostname-matched, "
                     "and chains to a trusted CA. FAIL if any condition from the original "
                     "finding still holds.",
        "evidence_to_capture": [
            "The openssl x509 output showing subject, issuer and dates.",
            "The date the retest was run, next to the notAfter value.",
        ],
    }


def _tls_protocol_cipher(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t, "443")
    return {
        "objective": "Confirm whether the weak TLS protocol version(s) or cipher suite(s) "
                     "named in the finding are still offered by the service.",
        "prerequisites": ["Network reachability to the host on the TLS port."],
        "commands": [
            _cmd("Enumerate protocols and ciphers (Nmap)",
                 f"nmap -Pn -p {port} --script ssl-enum-ciphers {host}",
                 "Groups offered ciphers by TLS version, each with a strength grade."),
            _cmd("Probe a specific weak protocol (OpenSSL)",
                 f"openssl s_client -connect {host}:{port} -tls1_1 2>&1 | head -n 20",
                 "Swap -tls1_1 for -tls1 / -tls1_2 as needed. A successful handshake means "
                 "that version is still accepted; 'no protocols available' / 'alert' means "
                 "it is refused."),
            _cmd("Full protocol/cipher grading (testssl.sh)",
                 f"testssl.sh --protocols --ciphers {host}:{port}",
                 "Optional, if available."),
        ],
        "expected_vulnerable": [
            "ssl-enum-ciphers still lists the flagged protocol (e.g. TLSv1.0/1.1) or the "
            "flagged cipher suites (RC4, 3DES, CBC, EXPORT, NULL).",
            "The targeted openssl s_client handshake succeeds for a weak protocol.",
        ],
        "expected_remediated": [
            "Only TLSv1.2 and TLSv1.3 are offered; the flagged protocols are absent.",
            "Only strong AEAD cipher suites remain; the flagged suites no longer appear.",
        ],
        "pass_fail": "PASS only when none of the protocols or cipher suites named in the "
                     "original finding are still offered. Any one still present is a FAIL.",
        "evidence_to_capture": [
            "The ssl-enum-ciphers output block for the tested port.",
            "A note mapping each originally-flagged protocol/cipher to present or absent.",
        ],
    }


def _weak_ssh(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t, "22")
    return {
        "objective": "Confirm whether the weak SSH algorithms named in the finding "
                     "(key exchange, cipher, MAC, or host-key type) are still offered "
                     "by the service.",
        "prerequisites": ["Network reachability to the host on the SSH port."],
        "commands": [
            _cmd("Enumerate offered SSH algorithms (Nmap)",
                 f"nmap -Pn -p {port} --script ssh2-enum-algos {host}",
                 "Lists kex_algorithms, server_host_key_algorithms, encryption, mac and "
                 "compression the server advertises."),
            _cmd("Cross-check with the SSH client",
                 f"ssh -vv -p {port} -o BatchMode=yes -o StrictHostKeyChecking=no "
                 f"{host} exit 2>&1 | grep -iE 'kex:|cipher:|mac:'",
                 "The negotiated kex/cipher/mac lines confirm what a real client settles on. "
                 "BatchMode avoids a password prompt; the connection need not authenticate."),
        ],
        "expected_vulnerable": [
            "ssh2-enum-algos still lists the flagged algorithms -- e.g. "
            "diffie-hellman-group1-sha1 or group14-sha1 (kex), 3des-cbc / arcfour / "
            "*-cbc (encryption), hmac-md5 / hmac-sha1-96 (mac), or ssh-rsa/ssh-dss host keys.",
        ],
        "expected_remediated": [
            "Only strong algorithms remain: curve25519 / group-exchange-sha256 kex, "
            "aes*-gcm or chacha20-poly1305 ciphers, hmac-sha2-* (or ETM) MACs, and "
            "ssh-ed25519 / rsa-sha2-* host keys.",
            "None of the algorithms named in the original finding appear in the output.",
        ],
        "pass_fail": "The retest passes only when the specific algorithms called out in the "
                     "original finding are no longer offered. Other algorithms changing is "
                     "irrelevant; the finding is about those named entries.",
        "evidence_to_capture": [
            "The full ssh2-enum-algos output.",
            "A line-by-line note marking each originally-flagged algorithm present or absent.",
        ],
    }


def _missing_headers(finding, t):
    url = _url_or_ph(t)
    return {
        "objective": "Confirm whether the security response header(s) named in the finding "
                     "are still missing (or misconfigured) on the affected response.",
        "prerequisites": [],
        "commands": [
            _cmd("Fetch response headers (curl)",
                 f"curl -sSI -o /dev/null -D - {url}",
                 "-I requests headers only; -D - prints the full response header block. "
                 "Add -k only if the target legitimately uses an untrusted cert in test."),
            _cmd("Check one header directly",
                 f"curl -sSI {url} | grep -iE "
                 f"'strict-transport-security|content-security-policy|x-frame-options|"
                 f"x-content-type-options|referrer-policy|permissions-policy'",
                 "Narrows the output to the security headers; an empty result means none "
                 "of them are present."),
        ],
        "expected_vulnerable": [
            "The header named in the finding is absent from the response, or present with "
            "a weak value (e.g. a permissive CSP, or HSTS with a very short max-age).",
        ],
        "expected_remediated": [
            "Each header the finding flagged is present with a hardening value: HSTS with "
            "a long max-age (and preferably includeSubDomains), a restrictive CSP, "
            "X-Content-Type-Options: nosniff, and a framing control (X-Frame-Options: "
            "DENY or CSP frame-ancestors).",
        ],
        "pass_fail": "PASS when every header named in the finding is present with an "
                     "acceptable value on the affected response. Any still-missing or "
                     "still-weak header is a FAIL.",
        "evidence_to_capture": [
            "The full response header block from curl -D -.",
            "The affected URL and the date of the retest.",
        ],
    }


def _reflected_xss(finding, t):
    url = _url_or_ph(t)
    param = t["parameter"] or PLACEHOLDER_PARAM
    method = t["method"] or "GET"
    marker = "rt5PROBE"  # benign, unique, non-executing probe string
    body = _redacted_request_body(finding, _bound_exchange(finding))
    curl_lines = [
        _cmd("Send a benign, uniquely-marked probe (curl)",
             (f"curl -sS -G '{url}' --data-urlencode '{param}={marker}<x>' | grep -n '{marker}'"
              if method == "GET" else
              f"curl -sS -X {method} '{url}' --data-urlencode '{param}={marker}<x>' | grep -n '{marker}'"),
             "Uses an inert marker (rt5PROBE<x>) rather than an executing payload: the "
             "retest only needs to see whether input is reflected without encoding. "
             "grep shows the reflected context."),
    ]
    if body:
        curl_lines.append(
            _cmd("Reproduce the original request body (redacted)",
                 f"# Body captured from evidence, secrets already masked:\n{body}",
                 "Re-send this via Burp Repeater or curl -d, replacing the probe value into "
                 f"the '{param}' field.")
        )
    return {
        "objective": "Confirm whether user input in the affected parameter is still "
                     "reflected into the response without output encoding (reflected XSS).",
        "prerequisites": ["Any authentication the endpoint requires (see the finding's "
                          "auth context)."],
        "commands": curl_lines + [
            _cmd("Burp Suite reproduction",
                 f"Send the affected request to Repeater. Set {param} to {marker}<x>\"'>. "
                 "Send, then search the response for the marker.",
                 "Burp is clearer than curl when the injection point is in a header, a "
                 "multipart body, or behind a login flow."),
        ],
        "expected_vulnerable": [
            f"The marker {marker} appears in the response with its angle brackets intact "
            "(reflected as <x> rather than &lt;x&gt;), i.e. inside an HTML/JS context "
            "without encoding.",
        ],
        "expected_remediated": [
            "The marker is either absent, or present but HTML-entity-encoded "
            "(&lt;x&gt;), or the response carries a Content-Type/CSP that neutralises "
            "execution. Input is no longer reflected raw into an executable context.",
        ],
        "pass_fail": "PASS when the probe is not reflected into an executable context "
                     "(encoded, stripped, or blocked). FAIL if the raw marker still lands "
                     "unencoded in HTML or script.",
        "evidence_to_capture": [
            "The request sent (with the benign marker) and the relevant response snippet.",
            "The reflection context -- HTML body, attribute, or script.",
        ],
    }


def _sql_injection(finding, t):
    url = _url_or_ph(t)
    param = t["parameter"] or PLACEHOLDER_PARAM
    return {
        "objective": "Confirm whether the affected parameter is still injectable, using a "
                     "safe, non-destructive differential test rather than data extraction.",
        "prerequisites": ["Any authentication the endpoint requires."],
        "commands": [
            _cmd("Boolean/behaviour differential (curl)",
                 f"curl -sS -G '{url}' --data-urlencode \"{param}=1' AND '1'='1\" -o /tmp/true.html -w '%{{http_code}} %{{size_download}}\\n'\n"
                 f"curl -sS -G '{url}' --data-urlencode \"{param}=1' AND '1'='2\" -o /tmp/false.html -w '%{{http_code}} %{{size_download}}\\n'\n"
                 f"diff /tmp/true.html /tmp/false.html && echo 'IDENTICAL (no differential)'",
                 "Compares a logically-true vs logically-false condition. A consistent "
                 "difference in response between the two suggests the input reaches the "
                 "query. Non-destructive: it never writes or drops data."),
            _cmd("Error-based probe (curl)",
                 f"curl -sS -G '{url}' --data-urlencode \"{param}=1'\" | grep -iE 'sql|syntax|odbc|pdo|sqlstate'",
                 "A single quote that provokes a database error string is a strong signal. "
                 "Absence of an error is not proof of a fix on its own."),
            _cmd("Burp Suite reproduction",
                 f"Send the request to Repeater, inject into {param}, and compare responses "
                 "for the true/false pair above. Burp Comparer highlights the delta.",
                 "Do not run automated sqlmap exploitation against production during a "
                 "retest; the differential above is enough to confirm or clear the finding."),
        ],
        "expected_vulnerable": [
            "The true vs false conditions return materially different responses, or the "
            "single-quote probe returns a database error.",
        ],
        "expected_remediated": [
            "True and false conditions return identical responses and no database error "
            "surfaces -- consistent with parameterised queries handling the input as data.",
        ],
        "pass_fail": "PASS when the differential disappears and no DB error is provoked. "
                     "FAIL if either signal from the original finding persists.",
        "evidence_to_capture": [
            "The two response codes/sizes for the true/false pair.",
            "Any database error string (redact connection details before storing).",
        ],
    }


def _access_control(finding, t):
    url = _url_or_ph(t)
    method = t["method"] or "GET"
    return {
        "objective": "Confirm whether the object/function is still reachable by a principal "
                     "who should not have access (IDOR / BOLA / broken function-level auth).",
        "prerequisites": [
            "Two test principals: the legitimate owner (A) and a lower-privileged or "
            "unrelated account (B).",
            "A valid session/token for each -- supply them at test time; never reuse "
            "credentials pulled from raw evidence.",
        ],
        "commands": [
            _cmd("Request B's session against A's object (curl)",
                 f"curl -sS -X {method} '{url}' -H 'Authorization: Bearer <TOKEN_B>' -w '\\n%{{http_code}}\\n'",
                 "Replace <TOKEN_B> with the lower-privileged principal's token and the "
                 "object id in the URL with one owned by A. A 200 with A's data is the "
                 "vulnerability."),
            _cmd("Baseline: no credentials",
                 f"curl -sS -X {method} '{url}' -w '\\n%{{http_code}}\\n'",
                 "Establishes what an unauthenticated request returns, for comparison."),
            _cmd("Burp Suite (Autorize)",
                 "Replay A's request with B's session using the Autorize extension; it "
                 "flags responses that should have been denied.",
                 "Autorize is the fastest way to retest access control across many "
                 "endpoints at once."),
        ],
        "expected_vulnerable": [
            "Principal B receives A's object (HTTP 200 with A's data), or an "
            "unauthenticated request succeeds where it should be denied.",
        ],
        "expected_remediated": [
            "B's request is rejected with 401/403 (or 404 if the app hides existence), "
            "and only A's own session can reach A's object.",
        ],
        "pass_fail": "PASS when every unauthorised principal is denied on the affected "
                     "object/function. FAIL if any cross-account or unauthenticated access "
                     "still returns protected data.",
        "evidence_to_capture": [
            "The request line (with the token value redacted) and the response status.",
            "A short note of which principal was used and what object id was targeted.",
        ],
    }


def _csrf(finding, t):
    url = _url_or_ph(t)
    method = t["method"] or "POST"
    return {
        "objective": "Confirm whether the state-changing request still succeeds without a "
                     "valid anti-CSRF token (or with SameSite protections absent).",
        "prerequisites": ["An authenticated session for the target account."],
        "commands": [
            _cmd("Replay without the CSRF token (curl)",
                 f"curl -sS -X {method} '{url}' -H 'Cookie: <SESSION_COOKIE>' -w '\\n%{{http_code}}\\n'",
                 "Send the state-changing request omitting the anti-CSRF token/header. "
                 "Supply the session cookie at test time; do not reuse one from evidence."),
            _cmd("Check cookie SameSite attribute (curl)",
                 f"curl -sSI '{url}' | grep -i 'set-cookie'",
                 "SameSite=Lax or Strict on the session cookie is a compensating control; "
                 "SameSite=None (or absent) leaves the request cross-site forgeable."),
        ],
        "expected_vulnerable": [
            "The request succeeds (2xx and the state change takes effect) with no valid "
            "CSRF token, and the session cookie lacks a SameSite restriction.",
        ],
        "expected_remediated": [
            "The request is rejected without a valid, per-session CSRF token, or the "
            "session cookie is SameSite=Lax/Strict such that a cross-site request cannot "
            "carry it.",
        ],
        "pass_fail": "PASS when the action cannot be performed cross-site without a valid "
                     "token. FAIL if the tokenless request still changes state.",
        "evidence_to_capture": [
            "The tokenless request and its response status.",
            "The Set-Cookie line showing the SameSite attribute.",
        ],
    }


def _cors(finding, t):
    url = _url_or_ph(t)
    return {
        "objective": "Confirm whether the endpoint still reflects an arbitrary Origin and "
                     "allows credentialed cross-origin reads.",
        "prerequisites": [],
        "commands": [
            _cmd("Probe with an attacker Origin (curl)",
                 f"curl -sSI '{url}' -H 'Origin: https://evil.example' "
                 f"| grep -i 'access-control-allow-'",
                 "Look at Access-Control-Allow-Origin and -Allow-Credentials in the "
                 "response."),
            _cmd("Preflight probe (curl)",
                 f"curl -sSI -X OPTIONS '{url}' -H 'Origin: https://evil.example' "
                 f"-H 'Access-Control-Request-Method: GET' | grep -i 'access-control-'",
                 "Shows how the server answers a CORS preflight for a foreign origin."),
        ],
        "expected_vulnerable": [
            "Access-Control-Allow-Origin echoes https://evil.example (or is *), AND "
            "Access-Control-Allow-Credentials: true -- credentialed cross-origin reads "
            "are permitted from any site.",
        ],
        "expected_remediated": [
            "The foreign Origin is not reflected: ACAO is absent, or restricted to an "
            "explicit allow-list, and credentials are not combined with a wildcard.",
        ],
        "pass_fail": "PASS when an arbitrary Origin is not reflected with credentials "
                     "allowed. FAIL if the attacker origin is still echoed back.",
        "evidence_to_capture": [
            "The Access-Control-Allow-Origin / -Allow-Credentials response headers for "
            "the attacker Origin.",
        ],
    }


def _open_ports(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t)
    return {
        "objective": "Confirm whether the port/service the finding flagged is still exposed "
                     "and reachable.",
        "prerequisites": ["Network path to the host from the test vantage point."],
        "commands": [
            _cmd("Service + version scan (Nmap)",
                 f"nmap -Pn -sV -p {port} {host}",
                 "-sV fingerprints the listening service so the retest confirms not just an "
                 "open port but which service answers."),
            _cmd("Quick reachability (Nmap)",
                 f"nmap -Pn -p {port} {host}",
                 "State 'open' vs 'filtered'/'closed' is the headline result."),
        ],
        "expected_vulnerable": [
            "The port reports state 'open' and the flagged service answers.",
        ],
        "expected_remediated": [
            "The port is 'filtered' or 'closed' from the untrusted vantage point, or the "
            "service is no longer exposed to that network.",
        ],
        "pass_fail": "PASS when the port is no longer reachable/exposed as described. FAIL "
                     "while it remains open to the network it should not be.",
        "evidence_to_capture": [
            "The nmap output line for the port, showing state and service.",
            "The source network/vantage point the scan ran from.",
        ],
    }


def _smb_exposure(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t, "445")
    return {
        "objective": "Confirm whether SMB is still exposed, and whether anonymous/guest "
                     "access to shares remains possible.",
        "prerequisites": ["Network path to the host on the SMB port."],
        "commands": [
            _cmd("SMB posture and dialects (Nmap)",
                 f"nmap -Pn -p {port} --script smb-protocols,smb-security-mode {host}",
                 "smb-protocols shows whether SMBv1 is still offered; smb-security-mode "
                 "reports signing and guest settings."),
            _cmd("Attempt anonymous share listing (smbclient)",
                 f"smbclient -L //{host}/ -N",
                 "-N attempts a null session. A share list without credentials is the "
                 "exposure. Non-destructive: it only lists."),
        ],
        "expected_vulnerable": [
            "SMBv1 is offered, or signing is not required, or a null/guest session lists "
            "shares without authentication.",
        ],
        "expected_remediated": [
            "SMBv1 is disabled, signing is required, and anonymous session attempts are "
            "refused (NT_STATUS_ACCESS_DENIED).",
        ],
        "pass_fail": "PASS when SMB no longer offers SMBv1, enforces signing, and denies "
                     "anonymous access. FAIL if any of those conditions from the finding "
                     "persist.",
        "evidence_to_capture": [
            "The smb-protocols / smb-security-mode script output.",
            "The result of the null-session listing attempt.",
        ],
    }


def _info_disclosure(finding, t):
    url = _url_or_ph(t)
    return {
        "objective": "Confirm whether the sensitive information the finding reported is "
                     "still returned by the affected response.",
        "prerequisites": [],
        "commands": [
            _cmd("Fetch the affected response (curl)",
                 f"curl -sS -D - '{url}' | head -n 60",
                 "Prints headers and the start of the body. Compare against the specific "
                 "disclosure the finding named (a stack trace, a version banner, an "
                 "internal path, a verbose error)."),
            _cmd("Grep for the disclosed indicator (curl)",
                 f"curl -sS '{url}' | grep -iE 'exception|stack trace|root:|/var/|version'",
                 "Adjust the pattern to the exact indicator from the finding rather than "
                 "this generic set."),
        ],
        "expected_vulnerable": [
            "The response still contains the sensitive detail the finding named "
            "(version banner, internal path, stack trace, verbose error, PII).",
        ],
        "expected_remediated": [
            "The response no longer exposes that detail: a generic error page, no version "
            "banner, no internal paths.",
        ],
        "pass_fail": "PASS when the specific disclosed indicator is gone. FAIL while it is "
                     "still returned.",
        "evidence_to_capture": [
            "The response snippet that did or did not contain the indicator.",
        ],
    }


def _generic_web(finding, t):
    url = _url_or_ph(t)
    method = t["method"] or "GET"
    return {
        "objective": "Reproduce the affected request and compare the response against the "
                     "behaviour the original finding recorded.",
        "prerequisites": ["Any authentication the endpoint requires."],
        "commands": [
            _cmd("Reproduce the affected request (curl)",
                 f"curl -sS -X {method} -D - '{url}' -o /tmp/response.txt -w '\\n%{{http_code}}\\n'",
                 "Sends the request and captures headers plus body. Compare the result "
                 "against the finding's evidence."),
            _cmd("Burp Suite reproduction",
                 "Send the affected request to Repeater, apply the condition described in "
                 "the finding, and compare the response to the recorded evidence.",
                 "Use Burp when the request needs a session, custom headers, or a body "
                 "that curl makes awkward."),
        ],
        "expected_vulnerable": [
            "The response reproduces the behaviour recorded in the finding's evidence.",
        ],
        "expected_remediated": [
            "The behaviour is gone: the response no longer matches the vulnerable pattern "
            "the finding recorded.",
        ],
        "pass_fail": "PASS when the recorded vulnerable behaviour can no longer be "
                     "reproduced. FAIL if it still occurs.",
        "evidence_to_capture": [
            "The reproduced request and response.",
            "A note comparing it to the original evidence.",
        ],
    }


def _generic_network(finding, t):
    host, port = _host_or_ph(t), _port_or_ph(t)
    return {
        "objective": "Re-probe the affected host/service and compare against the "
                     "condition the original finding recorded.",
        "prerequisites": ["Network path to the host."],
        "commands": [
            _cmd("Service + version scan (Nmap)",
                 f"nmap -Pn -sV -p {port} {host}",
                 "Confirms the service and version still present the reported condition."),
            _cmd("Default NSE scripts for the port (Nmap)",
                 f"nmap -Pn -sC -p {port} {host}",
                 "-sC runs the default script set, a reasonable general retest when no "
                 "single targeted script applies."),
        ],
        "expected_vulnerable": [
            "The scan reproduces the condition named in the finding.",
        ],
        "expected_remediated": [
            "The condition is no longer present in the scan output.",
        ],
        "pass_fail": "PASS when the reported condition is gone from the scan. FAIL while it "
                     "persists.",
        "evidence_to_capture": [
            "The relevant nmap output lines.",
        ],
    }


def _finding_text(finding):
    return " ".join(
        str((finding or {}).get(f, "") or "")
        for f in ("title", "description", "category", "cwe")
    ).lower()


# Retest-specific network signals that risk_map's class vocabulary does not carry
# (it has no ssh/smb entries, by design -- those are not web weakness classes).
# Checked before falling back to infer_class so a "Weak SSH Algorithms" finding
# with no CWE still reaches the right template rather than the generic one. These
# are only ever *added* here; risk_map is left untouched so its framework and
# ATT&CK mappings and their tests are unaffected.
def _network_signal(finding):
    text = _finding_text(finding)
    if any(w in text for w in ("ssh", "sshd", " kex", "host key", "host-key",
                               "ssh2", "openssh")):
        return "ssh"
    if any(w in text for w in ("smb", "netbios", "server message block", "samba",
                               "cifs")):
        return "smb"
    if any(w in text for w in ("open port", "exposed port", "exposed service",
                               "port is open", "unnecessary service")):
        return "open_ports"
    return None


# class key -> (builder, placeholder fields to report, kind)
def _dispatch(finding, klass, t):
    """Pick a template.

    Retest-specific network signals (ssh/smb/open ports) are resolved first, then
    the weakness classes risk_map provides. crypto and misconfig split further on
    sub-type read from the finding text, because 'crypto' covers both certificate
    and protocol/cipher findings and 'misconfig' covers headers, CORS and cookies.
    """
    text = _finding_text(finding)
    web_fields = ("host", "url", "parameter")
    net_fields = ("host", "port")

    signal = _network_signal(finding)
    if signal == "ssh":
        return _weak_ssh(finding, t), _placeholders_used(t, "host", "port"), "network"
    if signal == "smb":
        return _smb_exposure(finding, t), _placeholders_used(t, "host", "port"), "network"
    if signal == "open_ports":
        return _open_ports(finding, t), _placeholders_used(t, "host", "port"), "network"

    if klass == "crypto":
        if any(w in text for w in ("ssh", "kex", "host key", "host-key")):
            return _weak_ssh(finding, t), _placeholders_used(t, "host", "port"), "network"
        if any(w in text for w in ("certificate", "cert ", "expired", "self-signed",
                                   "self signed", "untrusted", "hostname mismatch",
                                   "name mismatch", "chain")):
            return _tls_cert(finding, t), _placeholders_used(t, "host", "port"), "network"
        # TLS protocol/cipher is the remaining crypto-over-the-wire case.
        return _tls_protocol_cipher(finding, t), _placeholders_used(t, "host", "port"), "network"

    if klass == "misconfig":
        if any(w in text for w in ("cors", "cross-origin", "access-control-allow")):
            return _cors(finding, t), _placeholders_used(t, "url"), "web"
        if any(w in text for w in ("header", "hsts", "csp", "content security",
                                   "x-frame", "clickjack", "cookie", "samesite",
                                   "httponly", "secure flag")):
            return _missing_headers(finding, t), _placeholders_used(t, "url"), "web"
        # Bare misconfiguration with a URL is web-shaped; otherwise network.
        if t["url"] or t["parameter"]:
            return _missing_headers(finding, t), _placeholders_used(t, "url"), "web"
        return _generic_network(finding, t), _placeholders_used(t, "host", "port"), "network"

    builders = {
        "xss": (_reflected_xss, web_fields, "web"),
        "injection": (_sql_injection, web_fields, "web"),
        "access_control": (_access_control, web_fields, "web"),
        "csrf": (_csrf, web_fields, "web"),
        "info_disclosure": (_info_disclosure, ("url",), "web"),
        "error_handling": (_info_disclosure, ("url",), "web"),
        "open_redirect": (_generic_web, web_fields, "web"),
        "ssrf": (_generic_web, web_fields, "web"),
        "path_traversal": (_generic_web, web_fields, "web"),
        "auth": (_generic_web, web_fields, "web"),
        "components": (_generic_network, net_fields, "network"),
        "integrity": (_generic_web, web_fields, "web"),
        "misconfig_xxe": (_generic_web, web_fields, "web"),
        "logging": (_generic_web, ("url",), "web"),
    }
    if klass in builders:
        builder, fields, kind = builders[klass]
        return builder(finding, t), _placeholders_used(t, *fields), kind

    # No class resolved: choose web vs network by what the finding carries, and use
    # the generic reproducer. Never fabricate a specialised command for an unknown
    # class.
    category = str((finding or {}).get("category") or "").lower()
    if "network" in category or (t["host"] and not t["url"] and not t["parameter"]):
        return _generic_network(finding, t), _placeholders_used(t, "host", "port"), "network"
    return _generic_web(finding, t), _placeholders_used(t, "url"), "web"


def build_guide(finding):
    """The deterministic retest guide for one finding.

    Always returns a complete, structured guide. Values are taken from the finding
    and its (redacted) evidence; anything genuinely missing appears as a labelled
    placeholder listed under `placeholders`.
    """
    finding = finding or {}
    t = extract_target(finding)
    klass, basis = risk_map.infer_class(finding)
    guide, placeholders, kind = _dispatch(finding, klass, t)

    # Label: a retest-specific network signal (ssh/smb/open ports) names the guide
    # more usefully than an unresolved risk_map class would.
    signal = _network_signal(finding)
    label = klass or signal or "unclassified"
    if signal and not klass:
        basis = f"retest signal: {signal}"

    # Authoritative: what the rendered commands actually still ask the tester to
    # fill in. `placeholders` from the dispatch is unused for this reason.
    del placeholders

    built = {
        "generated": "deterministic",
        "kind": kind,                       # "web" or "network"
        "class": label,
        "class_basis": basis,
        "target": {
            "host": t["host"],
            "port": t["port"],
            "url": t["url"],
            "method": t["method"],
            "parameter": t["parameter"],
        },
        "objective": guide["objective"],
        "prerequisites": guide.get("prerequisites", []),
        "commands": guide["commands"],
        "expected_vulnerable": guide["expected_vulnerable"],
        "expected_remediated": guide["expected_remediated"],
        "pass_fail": guide["pass_fail"],
        "evidence_to_capture": guide["evidence_to_capture"],
    }
    built["placeholders"] = _placeholders_in(built)
    return built


def copy_all_text(guide):
    """A single plain-text rendering of the whole guide, for the 'Copy all' button.
    Built server-side so the copied text matches what the tester sees."""
    g = guide or {}
    lines = []
    tgt = g.get("target", {})
    lines.append(f"RETEST GUIDE — {g.get('class', '')} ({g.get('kind', '')})")
    if tgt.get("host") or tgt.get("url"):
        loc = tgt.get("url") or tgt.get("host")
        if tgt.get("port") and not tgt.get("url"):
            loc = f"{loc}:{tgt['port']}"
        lines.append(f"Target: {loc}")
    lines.append("")
    lines.append(f"Objective: {g.get('objective', '')}")
    if g.get("prerequisites"):
        lines.append("")
        lines.append("Prerequisites:")
        lines += [f"  - {p}" for p in g["prerequisites"]]
    lines.append("")
    lines.append("Commands:")
    for c in g.get("commands", []):
        lines.append(f"# {c['label']}")
        lines.append(c["command"])
        if c.get("note"):
            lines.append(f"# note: {c['note']}")
        lines.append("")
    lines.append("Expected result if STILL VULNERABLE:")
    lines += [f"  - {x}" for x in g.get("expected_vulnerable", [])]
    lines.append("")
    lines.append("Expected result if REMEDIATED:")
    lines += [f"  - {x}" for x in g.get("expected_remediated", [])]
    lines.append("")
    lines.append(f"Pass/Fail: {g.get('pass_fail', '')}")
    lines.append("")
    lines.append("Evidence to capture:")
    lines += [f"  - {x}" for x in g.get("evidence_to_capture", [])]
    if g.get("placeholders"):
        lines.append("")
        lines.append("Replace these placeholders before running:")
        lines += [f"  - {p['placeholder']}: {p['means']}" for p in g["placeholders"]]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Optional AI enrichment. Additive only: it may refine the prose `objective` and
# per-command `note`s given the structured guide and the REDACTED evidence, under
# a strict no-fabrication instruction. It must never introduce a host, port,
# endpoint, parameter or command that the deterministic guide did not already
# contain. Any failure returns the deterministic guide unchanged.
# ---------------------------------------------------------------------------
def _enrichment_prompt(finding, guide, redacted_evidence):
    import json

    payload = {
        "finding": {
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "cwe": finding.get("cwe", ""),
            "category": finding.get("category", ""),
            "affected_host": finding.get("affected_host", ""),
            "affected_url": finding.get("affected_url", ""),
            "http_method": finding.get("http_method", ""),
            "parameter": finding.get("parameter", ""),
        },
        "redacted_evidence": redacted_evidence[:4000],
        "deterministic_guide": {
            "objective": guide["objective"],
            "commands": [{"label": c["label"], "note": c.get("note", "")} for c in guide["commands"]],
        },
    }
    return (
        "You are refining a security retest guide for an authorised VAPT retest.\n"
        "You are given structured finding data, redacted evidence, and a deterministic "
        "guide that is already correct.\n\n"
        "STRICT RULES:\n"
        "- Do NOT invent or alter any hostname, IP, port, URL, endpoint, parameter, "
        "credential, or command. The commands are fixed.\n"
        "- You may only improve the wording of the 'objective' and each command 'note' "
        "to be more specific to THIS finding, using only facts present in the input.\n"
        "- If the evidence does not support a more specific note, keep it unchanged.\n"
        "- Never include secrets. The evidence is already redacted; do not reconstruct.\n\n"
        "Return ONLY JSON: {\"objective\": str, \"notes\": [str, ...]} where notes[i] "
        "corresponds to command i. No markdown, no prose outside the JSON.\n\n"
        f"INPUT:\n{json.dumps(payload, ensure_ascii=False)}"
    )


def enrich(finding, guide, api_key, *, usage_sink=None):
    """Return an AI-refined copy of `guide`, or `guide` unchanged on any problem.

    Only `objective` and command `note`s may change. Structure, targets and commands
    are preserved exactly.
    """
    try:
        import json
        import gemini_client

        evidence = str((finding or {}).get("evidence") or "")
        redacted_evidence, _ = redaction.redact(evidence, finding)
        prompt = _enrichment_prompt(finding, guide, redacted_evidence)

        base_url, key, models = gemini_client._lane(
            "REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, api_key or ""
        )
        if not key:
            return guide
        client = gemini_client._client(base_url, key)
        messages = [{"role": "user", "content": prompt}]

        def parser(response):
            text = gemini_client._response_text(response)
            text = gemini_client._strip_code_fences(gemini_client._strip_reasoning(text))
            return json.loads(text)

        data = gemini_client._run_with_fallback(
            client, messages, models, parser,
            json_mode=True, temperature=0.0, lane="review", usage_sink=usage_sink,
        )
        if not isinstance(data, dict):
            return guide

        out = dict(guide)
        new_obj = data.get("objective")
        if isinstance(new_obj, str) and new_obj.strip():
            out["objective"] = new_obj.strip()
        notes = data.get("notes")
        if isinstance(notes, list):
            cmds = [dict(c) for c in guide["commands"]]
            for i, note in enumerate(notes):
                if i < len(cmds) and isinstance(note, str) and note.strip():
                    cmds[i]["note"] = note.strip()
            out["commands"] = cmds
        out["generated"] = "ai-enriched"
        return out
    except Exception:
        # Enrichment is a nicety; the deterministic guide is the product.
        return guide
