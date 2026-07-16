"""CVE prioritization enrichment: EPSS, CISA KEV, and NVD.

When a finding references a CVE, this adds real-world prioritization intel that
CVSS alone cannot give:
  - EPSS  (FIRST.org): probability the CVE is exploited in the next 30 days.
  - CISA KEV: whether it is *known to be actively exploited in the wild*.
  - NVD: the canonical CVSS base score/severity (authoritative cross-check).

Pure stdlib (urllib) so it adds no dependencies. Every network call is wrapped
with a timeout and degrades gracefully: if an API is unreachable, the finding is
returned unchanged apart from a soft "check unavailable" note. Results are
cached per process to respect API rate limits (NVD especially).

Toggle with VAPT_CVE_ENRICH (default on). Optional NVD_API_KEY raises NVD's
rate limit.
"""
import os
import re
import json
import time
import urllib.request

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_HTTP_TIMEOUT = 8
_MAX_CVES_PER_FINDING = 6
_KEV_TTL_SECONDS = 6 * 3600
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

_epss_cache = {}
_nvd_cache = {}
_kev_cache = {"ts": 0.0, "ids": None}


def enrichment_enabled():
    value = (os.environ.get("VAPT_CVE_ENRICH") or "1").strip().lower()
    return value not in ("0", "false", "no", "off")


def _http_get_json(url, headers=None, timeout=_HTTP_TIMEOUT):
    request = urllib.request.Request(url, headers=headers or {"User-Agent": "vapt-assistant/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def extract_cves(finding):
    """Return unique CVE IDs referenced anywhere in the finding's text fields."""
    fields = (
        "title", "description", "evidence", "references", "references_data",
        "cwe", "impact", "remediation",
    )
    text = "\n".join(str((finding or {}).get(k, "") or "") for k in fields)
    seen, out = set(), []
    for match in CVE_RE.findall(text):
        cve = match.upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
            if len(out) >= _MAX_CVES_PER_FINDING:
                break
    return out


def fetch_epss(cve):
    """Return {'epss': float, 'percentile': float} or None."""
    if cve in _epss_cache:
        return _epss_cache[cve]
    result = None
    try:
        data = _http_get_json(_EPSS_URL.format(cve=cve))
        rows = data.get("data") or []
        if rows:
            result = {
                "epss": float(rows[0].get("epss")),
                "percentile": float(rows[0].get("percentile")),
            }
    except Exception:
        result = None
    _epss_cache[cve] = result
    return result


def load_kev_ids():
    """Return a set of CVE IDs in the CISA KEV catalog, or None if unavailable.
    Cached with a TTL so the catalog is fetched at most a few times a day."""
    now = time.time()
    if _kev_cache["ids"] is not None and (now - _kev_cache["ts"]) < _KEV_TTL_SECONDS:
        return _kev_cache["ids"]
    try:
        data = _http_get_json(_KEV_URL, timeout=15)
        ids = {str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities", [])}
        ids.discard("")
        _kev_cache["ids"] = ids
        _kev_cache["ts"] = now
        return ids
    except Exception:
        return None


def is_in_kev(cve):
    """True (listed) / False (not listed) / None (catalog unavailable)."""
    ids = load_kev_ids()
    if ids is None:
        return None
    return cve.upper() in ids


def fetch_nvd(cve):
    """Return {'base': float|None, 'severity': str, 'vector': str} or None."""
    if cve in _nvd_cache:
        return _nvd_cache[cve]
    headers = {"User-Agent": "vapt-assistant/1.0"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    result = None
    try:
        data = _http_get_json(_NVD_URL.format(cve=cve), headers=headers)
        vulns = data.get("vulnerabilities") or []
        if vulns:
            metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30"):
                arr = metrics.get(key) or []
                if arr:
                    cvss = arr[0].get("cvssData") or {}
                    result = {
                        "base": cvss.get("baseScore"),
                        "severity": cvss.get("baseSeverity", ""),
                        "vector": cvss.get("vectorString", ""),
                    }
                    break
    except Exception:
        result = None
    _nvd_cache[cve] = result
    return result


def enrich_finding(finding):
    """Append an EXPLOITATION INTEL block to the finding's additional_remarks for
    any CVEs it references. Returns the finding unchanged if it references none
    or if enrichment is disabled. Never raises."""
    try:
        if not enrichment_enabled():
            return finding
        cves = extract_cves(finding)
        if not cves:
            return finding

        lines = ["[EXPLOITATION INTEL - machine-generated, verify before sign-off]"]
        kev_any = False
        for cve in cves:
            parts = []

            epss = fetch_epss(cve)
            if epss is not None:
                parts.append(f"EPSS {epss['epss']:.3f} ({epss['percentile'] * 100:.1f}th pct)")

            kev = is_in_kev(cve)
            if kev is True:
                parts.append("CISA KEV: LISTED (actively exploited)")
                kev_any = True
            elif kev is False:
                parts.append("CISA KEV: not listed")
            else:
                parts.append("CISA KEV: check unavailable")

            nvd = fetch_nvd(cve)
            if nvd and nvd.get("base") is not None:
                parts.append(f"NVD base {nvd['base']} {nvd.get('severity', '')}".strip())

            lines.append(f"- {cve}: " + " | ".join(parts))

        if kev_any:
            lines.append(
                "- ACTIVELY EXPLOITED IN THE WILD (CISA KEV): prioritize remediation regardless of CVSS."
            )

        block = "\n".join(lines)
        existing = str(finding.get("additional_remarks", "") or "").rstrip()
        finding["additional_remarks"] = (existing + "\n" + block).strip() if existing else block
        return finding
    except Exception as exc:
        finding["additional_remarks"] = (
            str(finding.get("additional_remarks", "") or "").rstrip()
            + f"\n- CVE enrichment: skipped due to an internal error ({exc})."
        ).strip()
        return finding
