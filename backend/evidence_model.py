"""Structured evidence: turn a wall of pasted text into addressable exchanges.

The verifiers used to search the whole submission for a header, a payload or a
status code. That is only sound when the evidence contains exactly one exchange.
With several, the layer produces confident nonsense:

  - a header present on /login refutes a finding about /admin
  - a 200 belonging to the authorised baseline "confirms" an IDOR
  - a payload from a later request appears to be reflected by an earlier one

Those are not near-misses. They are false CONFIRMATIONS and false REFUTATIONS from
the one component the verdict engine trusts above the reviewer, which makes them
worse than having no verifier at all.

So evidence is parsed into discrete HTTP exchanges, and a finding is bound to the
exchange it is actually about before anything is checked.

A note on binding, because it is the part that decides whether this works:

The obvious design is to have the model emit an exchange id per claim. That moves
the hard problem onto the model and asks it to be reliable about exactly the kind
of bookkeeping it is worst at -- and this layer exists precisely because model
output is not trusted. So binding is done HERE, deterministically, from fields the
finding already carries: the affected URL, the parameter, the method.

When binding is ambiguous -- several exchanges match equally well, or none does --
the answer is INSUFFICIENT. Refusing to decide is the whole point; a verifier that
guesses which exchange a finding meant has reintroduced the bug it was built to
remove.
"""
import hashlib
import re
from urllib.parse import urlparse, parse_qs

# A request line: METHOD SP target SP HTTP/x
_REQUEST_LINE = re.compile(
    r"^[ \t]*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)[ \t]+(\S+)[ \t]+HTTP/(\d(?:\.\d)?)[ \t]*$",
    re.I | re.M,
)
_STATUS_LINE = re.compile(r"^[ \t]*HTTP/(\d(?:\.\d)?)[ \t]+(\d{3})", re.I | re.M)
_HEADER_LINE = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,60})[ \t]*:[ \t]*(.*)$")


def _parse_headers(block):
    """Header lines until the first blank line. Repeated names are kept as a list,
    because Set-Cookie legitimately repeats and collapsing it loses cookies."""
    headers = {}
    consumed = 0
    for line in block.splitlines(keepends=True):
        consumed += len(line)
        stripped = line.strip()
        if not stripped:
            break
        m = _HEADER_LINE.match(line)
        if not m:
            # Not a header: the block has run into a body without a blank line.
            consumed -= len(line)
            break
        headers.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    return headers, consumed


def _split_target(target, host=""):
    """Path and query parameters from a request target, absolute or origin-form."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.path or "/", parse_qs(parsed.query, keep_blank_values=True), parsed.netloc
    parsed = urlparse(target)
    return parsed.path or "/", parse_qs(parsed.query, keep_blank_values=True), host


def parse_exchanges(text):
    """Split raw evidence into ordered HTTP exchanges.

    Deliberately tolerant: pasted evidence is rarely well-formed. A request with no
    response, or a response with no request, is still recorded -- callers decide
    whether that is enough to check a given claim.
    """
    text = text or ""
    starts = [(m.start(), m) for m in _REQUEST_LINE.finditer(text)]

    exchanges = []
    if not starts:
        # Responses pasted on their own are common and still checkable.
        for i, m in enumerate(_STATUS_LINE.finditer(text)):
            end = len(text)
            nxt = _STATUS_LINE.search(text, m.end())
            if nxt:
                end = nxt.start()
            exchanges.append(_build(None, text[m.start():end], i, text, m.start(), end))
        return exchanges

    for i, (pos, m) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        chunk = text[pos:end]
        resp_m = _STATUS_LINE.search(chunk)
        req_part = chunk[: resp_m.start()] if resp_m else chunk
        resp_part = chunk[resp_m.start():] if resp_m else ""
        exchanges.append(_build(req_part, resp_part, i, text, pos, end))
    return exchanges


def _after_line(text, pos):
    """Everything past the end of the line containing `pos`.

    The request and status line regexes stop at the last field they capture, not at
    the newline -- a status line leaves the reason phrase behind. Feeding that to
    the header parser makes it stop on the first line, which silently produced
    exchanges with zero headers.
    """
    nl = text.find("\n", pos)
    return text[nl + 1:] if nl != -1 else ""


def _build(req_part, resp_part, index, whole, start, end):
    request = None
    if req_part:
        m = _REQUEST_LINE.search(req_part)
        if m:
            after = _after_line(req_part, m.end())
            headers, consumed = _parse_headers(after)
            body = after[consumed:].strip()
            host = (headers.get("host") or [""])[0]
            path, params, netloc = _split_target(m.group(2), host)
            request = {
                "method": m.group(1).upper(),
                "target": m.group(2),
                "path": path,
                "params": params,
                "host": netloc or host,
                "headers": headers,
                "body": body,
            }

    response = None
    if resp_part:
        m = _STATUS_LINE.search(resp_part)
        if m:
            after = _after_line(resp_part, m.end())
            headers, consumed = _parse_headers(after)
            response = {
                "status": int(m.group(2)),
                "headers": headers,
                "body": after[consumed:],
            }

    raw = whole[start:end]
    return {
        "id": f"exchange-{index + 1}",
        "sequence": index,
        "request": request,
        "response": response,
        "raw": raw,
        "sha256": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16],
    }


def header(exchange, name):
    """All values of a response header, lowercased name. Empty list if absent."""
    resp = (exchange or {}).get("response") or {}
    return (resp.get("headers") or {}).get(name.lower(), [])


def request_header(exchange, name):
    req = (exchange or {}).get("request") or {}
    return (req.get("headers") or {}).get(name.lower(), [])


# --- binding ------------------------------------------------------------------

def _finding_path(finding):
    raw = str((finding or {}).get("affected_url") or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return urlparse(raw).path or "/"
    if raw.startswith("/"):
        return urlparse(raw).path or "/"
    return ""


def score_exchange(finding, exchange):
    """How well an exchange matches a finding. Higher is better; 0 is no match.

    Only signals the finding itself carries are used -- the URL, the parameter, the
    method. Nothing here consults the model's prose, which would reintroduce the
    guesswork this module exists to remove.
    """
    req = (exchange or {}).get("request") or {}
    if not req:
        return 0

    score = 0
    want_path = _finding_path(finding)
    if want_path:
        have = req.get("path") or ""
        if have == want_path:
            score += 10
        elif have and (have.rstrip("/") == want_path.rstrip("/")):
            score += 9
        else:
            # A finding that names a different path is not about this exchange.
            return 0

    param = str((finding or {}).get("parameter") or "").strip()
    if param:
        in_query = param in (req.get("params") or {})
        in_body = bool(re.search(rf"\b{re.escape(param)}\s*=", req.get("body") or ""))
        in_header = param.lower() in (req.get("headers") or {})
        if in_query or in_body or in_header:
            score += 5
        elif want_path:
            # Right path, but the named parameter is not in this request.
            score += 1

    method = str((finding or {}).get("http_method") or "").strip().upper()
    if method and req.get("method"):
        score += 2 if method == req["method"] else 0

    return score


def bind(finding, exchanges):
    """The exchange a finding is about.

    Returns (exchange, reason). `exchange` is None when the choice is not clear,
    and `reason` explains which -- callers turn that into INSUFFICIENT rather than
    checking an arbitrary exchange.
    """
    usable = [e for e in exchanges if e.get("request") or e.get("response")]
    if not usable:
        return None, "The evidence contains no recognisable HTTP exchange."

    if len(usable) == 1:
        return usable[0], ""

    scored = sorted(((score_exchange(finding, e), e) for e in usable), key=lambda t: -t[0])
    best, top = scored[0][0], scored[0][1]

    if best == 0:
        return None, (
            f"The evidence contains {len(usable)} exchanges and the finding does not identify "
            "which one it refers to, so no check was run against a possibly unrelated response."
        )

    runners_up = [s for s, _ in scored[1:] if s == best]
    if runners_up:
        return None, (
            f"{len(runners_up) + 1} of the {len(usable)} exchanges match this finding equally well, "
            "so the correct one cannot be determined from the evidence."
        )

    return top, ""
