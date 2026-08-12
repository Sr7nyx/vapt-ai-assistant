"""Recognising the same finding across scans.

Without this, importing the same scan next month produces an entirely new set of
findings and nobody can answer the questions a vulnerability programme is actually
run on: what is new, what regressed, what is finally fixed, and how long things
sit before anyone deals with them.

The whole thing turns on identity, so that is deliberate:

  Severity is NOT part of it. scan_import.dedupe() includes severity, which is
  right for collapsing duplicates inside one import but wrong across scans -- a
  finding whose severity is re-rated from High to Critical is the SAME finding, and
  treating it as new would erase its history at the exact moment it got worse.

  The URL is normalised. Scanners emit the same issue with a session id, a cache
  buster or a rotating parameter value in the query, and comparing raw URLs makes
  every rescan look like a fresh set of findings.

  CWE is used only when both sides have one. Falling back to the title alone is
  weaker but honest; inventing a match on a missing field is not.
"""
import re
from urllib.parse import urlparse, parse_qsl, urlencode

# Query parameters that are session or cache machinery rather than part of the
# finding. Dropped entirely, not placeholdered: a scan that happens to append a
# session id would otherwise look like a different URL, which is the exact failure
# this normalisation exists to prevent.
_VOLATILE_PARAMS = {
    "session", "sessionid", "sid", "jsessionid", "phpsessid", "token", "csrf",
    "csrftoken", "_", "cachebuster", "cb", "ts", "timestamp", "nonce", "rand",
    "random", "v", "version",
}

# Path segments that are identifiers rather than structure.
_NUMERIC_SEGMENT = re.compile(r"^\d{1,12}$")
_UUID_SEGMENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HASH_SEGMENT = re.compile(r"^[0-9a-f]{16,}$", re.I)


def normalise_url(raw):
    """A URL reduced to what makes a finding distinct.

    Identifier-shaped path segments become placeholders, volatile query parameters
    keep their name but lose their value, and the rest is sorted so parameter
    ordering cannot change identity.
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "//" in raw else f"//{raw}", scheme="https")
    except ValueError:
        return raw.lower()

    segments = []
    for seg in (parsed.path or "").split("/"):
        if not seg:
            continue
        if _NUMERIC_SEGMENT.match(seg):
            segments.append("{id}")
        elif _UUID_SEGMENT.match(seg) or _HASH_SEGMENT.match(seg):
            segments.append("{uuid}")
        else:
            segments.append(seg.lower())
    path = "/" + "/".join(segments)

    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        low = key.lower()
        if low in _VOLATILE_PARAMS:
            continue
        # The NAME of a parameter is part of the finding; an id-shaped VALUE is
        # not, since the same issue is reported against every object.
        if _NUMERIC_SEGMENT.match(value) or _UUID_SEGMENT.match(value) or _HASH_SEGMENT.match(value):
            pairs.append((low, "{v}"))
        else:
            pairs.append((low, value.lower()))
    pairs.sort()

    host = (parsed.netloc or "").lower()
    query = urlencode(pairs) if pairs else ""
    return f"{host}{path}" + (f"?{query}" if query else "")


def _normalise_title(title):
    """Titles vary in punctuation and casing between scanner versions."""
    t = (title or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^a-z0-9 ]+", "", t)
    return t


def fingerprint(finding):
    """A stable identity for one finding, comparable across scans.

    Severity and status are excluded on purpose: both change over a finding's life
    without making it a different finding.
    """
    f = finding or {}
    url = normalise_url(f.get("affected_url") or "")
    host = (f.get("affected_host") or "").strip().lower()
    cwe = re.sub(r"[^0-9]", "", str(f.get("cwe") or ""))
    return "|".join([
        _normalise_title(f.get("title")),
        cwe,
        url or host,
        (f.get("parameter") or "").strip().lower(),
        (f.get("http_method") or "").strip().upper(),
    ])


# Statuses meaning "this was dealt with". A finding in one of these that appears
# in a new scan has come back, which is the most important outcome to surface.
CLOSED_STATUSES = {"fixed", "retest passed", "false positive", "accepted risk"}


def classify(candidates, existing):
    """Compare an incoming scan against what the project already holds.

    Returns candidates annotated with `_delta`, plus the set of stored findings
    that did NOT reappear, which is how "fixed" is inferred.

        new         not seen before
        regressed   present, but had been closed -- the important one
        unchanged   present and still open, same severity
        reappraised present and still open, but the severity moved
    """
    by_print = {}
    for e in existing or []:
        by_print.setdefault(fingerprint(e), []).append(e)

    seen = set()
    summary = {"new": 0, "regressed": 0, "unchanged": 0, "reappraised": 0}
    out = []

    for c in candidates or []:
        fp = fingerprint(c)
        seen.add(fp)
        matches = by_print.get(fp)
        annotated = dict(c)

        if not matches:
            annotated["_delta"] = {"state": "new", "fingerprint": fp}
            summary["new"] += 1
            out.append(annotated)
            continue

        prior = matches[0]
        prior_status = str(prior.get("status") or "").strip().lower()
        prior_sev = str(prior.get("severity") or "")
        now_sev = str(c.get("severity") or "")

        if prior_status in CLOSED_STATUSES:
            state = "regressed"
        elif prior_sev and now_sev and prior_sev != now_sev:
            state = "reappraised"
        else:
            state = "unchanged"

        summary[state] += 1
        annotated["_delta"] = {
            "state": state,
            "fingerprint": fp,
            "existing_id": prior.get("id"),
            "previous_status": prior.get("status"),
            "previous_severity": prior_sev or None,
            "first_found": prior.get("first_found_date") or prior.get("created_at"),
        }
        out.append(annotated)

    # Open findings the scan no longer reports. Not proof of a fix -- the scan may
    # simply not have covered them -- so they are surfaced for a human, never
    # closed automatically.
    absent = [
        e for e in (existing or [])
        if fingerprint(e) not in seen
        and str(e.get("status") or "").strip().lower() not in CLOSED_STATUSES
    ]
    summary["absent"] = len(absent)

    return out, absent, summary
