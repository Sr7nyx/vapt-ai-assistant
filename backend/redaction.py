"""Strip credentials and PII before evidence leaves for a third-party model.

Evidence went to the provider verbatim. A pasted request carries whatever was in
it -- session cookies, bearer tokens, API keys, sometimes a client's personal data
-- and for a tool aimed at people handling other organisations' traffic, that is
the first objection a security-conscious user raises.

Three decisions shape this:

STRUCTURE IS PRESERVED, VALUES ARE NOT.
    Authorization: Bearer eyJhbGciOi...  ->  Authorization: Bearer [REDACTED:jwt]
    The model still sees that the header was present, which is what it needs to
    reason about authentication. It does not see the credential. Deleting the line
    would change the meaning of the evidence; masking the value does not.

THE VERIFIERS SEE THE ORIGINAL.
    Redaction applies only on the path to the provider. Deterministic checks run
    locally against unredacted text, so nothing is lost -- a cookie-flag check
    still reads the real Set-Cookie, and reflection still matches the real payload.

PAYLOADS ARE NOT CREDENTIALS.
    A finding about a token IS the token. `alg: none` in a JWT is the evidence, and
    masking it would destroy the finding being reported. Tokens carried in a
    request the tester constructed are left alone; only values arriving from the
    application are masked. Where that cannot be told apart, the value is masked
    and the reason is recorded, because a lost finding is recoverable and a leaked
    credential is not.
"""
import re

PLACEHOLDER = "[REDACTED:{kind}]"

# Header values that are credentials by definition. Matched on the header name so
# a token is masked regardless of its shape.
CREDENTIAL_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-session-token", "authentication",
}

# Cookie names worth keeping visible: their PRESENCE is often the finding, and a
# name is not a secret. Only the value is masked.
_COOKIE_PAIR = re.compile(r"([A-Za-z0-9_.\-]+)\s*=\s*([^;,\s]+)")

_PATTERNS = [
    # Order matters: the most specific shapes first, so a JWT is not caught by the
    # generic long-token rule and mislabelled.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b")),
    ("gcp-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Long opaque strings in an obviously secret-named field.
    ("secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9+/_\-.]{12,})[\"']?")),
]

# A finding about one of these IS about the credential, so masking it would
# destroy the evidence being reported.
_TOKEN_FINDING = re.compile(
    r"\b(jwt|json web token|\balg\b|session (fixation|token)|hardcoded (secret|credential|key)|"
    r"exposed (api )?key|credential (leak|disclosure|exposure))\b", re.I
)


def _luhn(digits):
    """Card numbers are the one pattern with a checksum, so use it. Without this,
    any 16-digit id -- an order number, a timestamp pair -- would be masked."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, alt = 0, False
    for n in reversed(nums):
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[a-z-]+\]")


def _mask_header_line(line, counts):
    """A header whose value is a credential by definition."""
    m = re.match(r"^([ \t]*)([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,60})([ \t]*:[ \t]*)(.*)$", line)
    if not m:
        return line, False
    indent, name, sep, value = m.groups()
    if name.lower() not in CREDENTIAL_HEADERS or not value.strip():
        return line, False
    # Already masked by an earlier pass. Counting it again would report values
    # that were placeholders, not secrets.
    if _PLACEHOLDER_RE.search(value):
        return line, False

    lower = name.lower()
    if lower in ("cookie", "set-cookie"):
        # Names stay: which cookie is set is often the finding, and a name is not
        # a secret. Attributes stay too -- Secure and HttpOnly are what the
        # cookie-flag verifier and the reviewer both reason about.
        def sub(pair):
            counts["cookie"] = counts.get("cookie", 0) + 1
            return f"{pair.group(1)}={PLACEHOLDER.format(kind='cookie')}"
        return f"{indent}{name}{sep}{_COOKIE_PAIR.sub(sub, value, count=1)}", True

    # Authorization: Bearer <token> -- keep the scheme, mask the credential.
    scheme = re.match(r"^(Bearer|Basic|Digest|Negotiate|Token)\s+(.+)$", value.strip(), re.I)
    if scheme:
        counts["auth"] = counts.get("auth", 0) + 1
        return f"{indent}{name}{sep}{scheme.group(1)} {PLACEHOLDER.format(kind='auth')}", True

    counts["auth"] = counts.get("auth", 0) + 1
    return f"{indent}{name}{sep}{PLACEHOLDER.format(kind='auth')}", True


def redact(text, finding=None):
    """Return (redacted_text, report).

    `finding` is optional context: when the finding is ABOUT a token, JWTs are left
    intact because the token is the evidence. Everything else is still masked.
    """
    text = text or ""
    if not text.strip():
        return text, {"redacted": False, "counts": {}, "kept": []}

    counts = {}
    kept = []

    about_tokens = bool(finding and _TOKEN_FINDING.search(
        f"{finding.get('title', '')} {finding.get('description', '')}"
    ))

    # Headers first: a line-level rule is more precise than a pattern, and it keeps
    # the scheme and cookie names the model legitimately needs.
    #
    # An Authorization header is skipped when the finding is about the token
    # itself. A JWT lives in that header far more often than in a body, so masking
    # it there would destroy the evidence for exactly the findings that need it --
    # alg:none is visible only in the token.
    out_lines = []
    for line in text.split("\n"):
        if about_tokens and re.match(r"^[ \t]*authorization[ \t]*:", line, re.I):
            out_lines.append(line)
            continue
        masked, _ = _mask_header_line(line, counts)
        out_lines.append(masked)
    text = "\n".join(out_lines)

    # Then value patterns over what remains.
    for kind, pattern in _PATTERNS:
        if kind == "jwt" and about_tokens:
            kept.append("jwt")
            continue

        def sub(m, kind=kind):
            raw = m.group(0)
            if kind == "card" and not _luhn(raw):
                return raw
            if kind == "secret":
                # Keep the field name so the model still sees WHAT was set.
                head = raw[: raw.index(m.group(1))]
                counts[kind] = counts.get(kind, 0) + 1
                return head + PLACEHOLDER.format(kind=kind)
            counts[kind] = counts.get(kind, 0) + 1
            return PLACEHOLDER.format(kind=kind)

        text = pattern.sub(sub, text)

    return text, {
        "redacted": bool(counts),
        "counts": counts,
        "kept": kept,
        "total": sum(counts.values()),
    }


def summarise(report):
    """One line for the audit remark, or empty when nothing was masked."""
    if not report or not report.get("redacted"):
        return ""
    parts = ", ".join(f"{n} {k}" for k, n in sorted(report["counts"].items()))
    line = f"- Redaction: {report['total']} value(s) masked before the model saw this ({parts})."
    if report.get("kept"):
        line += (f" Kept intact because the finding is about them: {', '.join(report['kept'])}.")
    return line
