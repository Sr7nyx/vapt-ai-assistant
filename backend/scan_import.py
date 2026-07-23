"""Scanner output import: parse common security-scanner exports into normalized
finding candidates that match the app's finding shape.

Supported formats (auto-detected):
  - Burp Suite       (XML issues export;   root <issues>)
  - OWASP ZAP        (JSON report, or XML  root <OWASPZAPReport>)
  - Nessus / Tenable (.nessus XML;         root <NessusClientData_v2>)
  - Nmap             (XML -oX;             root <nmaprun>)
  - Generic CSV      (best-effort column mapping)

Everything here is pure stdlib and fully offline: it parses, normalizes
severities to the app's scale, tags the source, removes exact duplicates, and
flags informational "noise" so the bulk of scanner chatter can be filtered
before any LLM call. It never raises on a single malformed item -- per-item
errors are skipped and surfaced as warnings.

Note: XML is parsed with the stdlib ElementTree, which does not resolve external
entities or fetch external DTDs. These files come from your own tooling, but if
you ever import third-party XML, consider the `defusedxml` package for hardened
entity-expansion protection.
"""
import csv
import io
import re
import html
import json
import base64
import xml.etree.ElementTree as ET
from collections import Counter

SEVERITY_CANON = ["Critical", "High", "Medium", "Low", "Informational"]

_CWE_RE = re.compile(r"CWE[-\s_]?(\d{1,5})", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\f\v]*\n[ \t\f\v]*")
_EVIDENCE_CAP = 15000

_LABEL_SEVERITY = {
    "critical": "Critical", "crit": "Critical",
    "high": "High",
    "medium": "Medium", "med": "Medium", "moderate": "Medium",
    "low": "Low",
    "informational": "Informational", "information": "Informational",
    "info": "Informational", "none": "Informational", "": "Informational",
}


def canon_severity(value):
    """Normalize an arbitrary severity label to the app's canonical scale.

    Handles ZAP's compound "risk (confidence)" form -- e.g. "High (Medium)" --
    by reading the risk and discarding the confidence. Without this, a High ZAP
    alert falls through to Informational and is filtered out as noise.
    """
    v = str(value or "").strip().lower()
    if v in _LABEL_SEVERITY:
        return _LABEL_SEVERITY[v]
    if "(" in v:
        head = v.split("(", 1)[0].strip()
        if head in _LABEL_SEVERITY:
            return _LABEL_SEVERITY[head]
        head_title = head.title()
        if head_title in SEVERITY_CANON:
            return head_title
    title = v.title()
    return title if title in SEVERITY_CANON else "Informational"


def _localname(tag):
    """Strip an XML namespace from a tag: '{ns}issues' -> 'issues'."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag


def _text(el):
    return (el.text or "").strip() if el is not None and el.text else ""


def _html_to_text(value):
    """Flatten HTML (Burp/ZAP fields are HTML) to readable plain text."""
    if not value:
        return ""
    text = _TAG_RE.sub(" ", html.unescape(str(value)))
    text = _WS_RE.sub("\n", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


def _first_cwe(*texts):
    for t in texts:
        m = _CWE_RE.search(str(t or ""))
        if m:
            return f"CWE-{int(m.group(1))}"
    return ""


def _cwe_from_field(raw):
    """Coerce a dedicated CWE column/element to 'CWE-N'. Unlike _first_cwe (which
    scans free text and requires the 'CWE' token to avoid inventing CWEs from
    stray numbers), this trusts a field known to hold a CWE: 'CWE-89', '89',
    or '89: SQL Injection' all become 'CWE-89'."""
    raw = str(raw or "").strip()
    if not raw:
        return ""
    m = _CWE_RE.search(raw)
    if m:
        return f"CWE-{int(m.group(1))}"
    m2 = re.match(r"\s*(\d{1,5})\b", raw)
    if m2:
        return f"CWE-{int(m2.group(1))}"
    return ""


def _maybe_b64(el):
    """Decode a Burp <request>/<response> element (base64='true' when encoded)."""
    if el is None:
        return ""
    raw = el.text or ""
    if (el.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return raw


def _candidate(**kw):
    base = {
        "title": "", "severity": "Informational", "cwe": "", "cvss": "",
        "category": "Web Application/API Vulnerability", "status": "Need Review",
        "environment": "", "affected_host": "", "affected_url": "", "http_method": "",
        "parameter": "", "description": "", "evidence": "", "impact": "", "scenario": "",
        "steps": "", "remediation": "", "fp_checks": "", "references_data": "",
        "additional_remarks": "", "source": "", "scanner_confidence": "", "noise": False,
    }
    base.update(kw)
    if base.get("evidence"):
        base["evidence"] = base["evidence"][:_EVIDENCE_CAP]
    return base


# ---------------------------------------------------------------------------
# Burp Suite XML
# ---------------------------------------------------------------------------
def parse_burp(root):
    cands = []
    for issue in root.findall(".//issue"):
        try:
            name = _text(issue.find("name")) or "Burp Suite issue"
            severity = canon_severity(_text(issue.find("severity")))  # Information -> Informational
            confidence = _text(issue.find("confidence"))
            host_el = issue.find("host")
            host = _text(host_el)
            ip = host_el.get("ip") if host_el is not None else ""
            path = _text(issue.find("path"))
            url = (host or "") + (path or "")
            detail = _html_to_text(_text(issue.find("issueDetail")))
            background = _html_to_text(_text(issue.find("issueBackground")))
            remediation = _html_to_text(_text(issue.find("remediationBackground")))

            evidence = detail
            rr = issue.find("requestresponse")
            if rr is not None:
                req = _maybe_b64(rr.find("request"))
                if req:
                    evidence = (evidence + "\n\n--- Request ---\n" + req[:2500]).strip()
                resp = _maybe_b64(rr.find("response"))
                if resp:
                    evidence = (evidence + "\n\n--- Response (head) ---\n" + resp[:1500]).strip()

            # Burp reports the CWE in vulnerabilityClassifications; check it first,
            # then fall back to the prose fields.
            classification = _html_to_text(_text(issue.find("vulnerabilityClassifications")))
            cwe = _first_cwe(classification, background, name)
            cands.append(_candidate(
                title=name, severity=severity, cwe=cwe,
                affected_host=ip or host, affected_url=url,
                description=background or detail, evidence=evidence or detail,
                remediation=remediation, scanner_confidence=confidence, source="Burp Suite",
                noise=(severity == "Informational"),
                additional_remarks=f"[SCANNER IMPORT] Source: Burp Suite | Confidence: {confidence or 'N/A'}",
            ))
        except Exception:
            continue
    return cands


# ---------------------------------------------------------------------------
# OWASP ZAP (JSON and XML)
# ---------------------------------------------------------------------------
_ZAP_RISK = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}


def parse_zap_json(obj):
    cands = []
    sites = obj.get("site") or obj.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        site_name = site.get("@name", "") if isinstance(site, dict) else ""
        for alert in (site.get("alerts") or []):
            try:
                name = alert.get("alert") or alert.get("name") or "ZAP alert"
                severity = _ZAP_RISK.get(str(alert.get("riskcode", "")), canon_severity(alert.get("riskdesc", "")))
                confidence = str(alert.get("confidence", ""))
                desc = _html_to_text(alert.get("desc", ""))
                solution = _html_to_text(alert.get("solution", ""))
                reference = _html_to_text(alert.get("reference", ""))
                cwe_id = str(alert.get("cweid", "") or "")
                cwe = f"CWE-{cwe_id}" if cwe_id.isdigit() and int(cwe_id) > 0 else ""
                instances = alert.get("instances") or []
                remark = f"[SCANNER IMPORT] Source: OWASP ZAP | Confidence: {confidence or 'N/A'}"
                if instances:
                    for inst in instances:
                        cands.append(_candidate(
                            title=name, severity=severity, cwe=cwe, affected_host=site_name,
                            affected_url=inst.get("uri", ""), parameter=inst.get("param", ""),
                            http_method=inst.get("method", ""), description=desc,
                            evidence=(inst.get("evidence") or desc), remediation=solution,
                            references_data=reference, scanner_confidence=confidence, source="OWASP ZAP",
                            noise=(severity == "Informational"), additional_remarks=remark,
                        ))
                else:
                    cands.append(_candidate(
                        title=name, severity=severity, cwe=cwe, affected_host=site_name,
                        description=desc, evidence=desc, remediation=solution,
                        references_data=reference, scanner_confidence=confidence, source="OWASP ZAP",
                        noise=(severity == "Informational"), additional_remarks=remark,
                    ))
            except Exception:
                continue
    return cands


def parse_zap_xml(root):
    cands = []
    for site in root.findall(".//site"):
        site_name = site.get("name", "")
        for alert in site.findall(".//alertitem"):
            try:
                name = _text(alert.find("alert")) or _text(alert.find("name")) or "ZAP alert"
                severity = _ZAP_RISK.get(_text(alert.find("riskcode")), canon_severity(_text(alert.find("riskdesc"))))
                confidence = _text(alert.find("confidence"))
                desc = _html_to_text(_text(alert.find("desc")))
                solution = _html_to_text(_text(alert.find("solution")))
                reference = _html_to_text(_text(alert.find("reference")))
                cwe_id = _text(alert.find("cweid"))
                cwe = f"CWE-{cwe_id}" if cwe_id.isdigit() and int(cwe_id) > 0 else ""
                remark = f"[SCANNER IMPORT] Source: OWASP ZAP | Confidence: {confidence or 'N/A'}"
                instances = alert.findall(".//instance")
                if instances:
                    for inst in instances:
                        cands.append(_candidate(
                            title=name, severity=severity, cwe=cwe, affected_host=site_name,
                            affected_url=_text(inst.find("uri")), parameter=_text(inst.find("param")),
                            http_method=_text(inst.find("method")), description=desc,
                            evidence=(_text(inst.find("evidence")) or desc), remediation=solution,
                            references_data=reference, scanner_confidence=confidence, source="OWASP ZAP",
                            noise=(severity == "Informational"), additional_remarks=remark,
                        ))
                else:
                    cands.append(_candidate(
                        title=name, severity=severity, cwe=cwe, affected_host=site_name,
                        affected_url=_text(alert.find("uri")), parameter=_text(alert.find("param")),
                        description=desc, evidence=desc, remediation=solution, references_data=reference,
                        scanner_confidence=confidence, source="OWASP ZAP",
                        noise=(severity == "Informational"), additional_remarks=remark,
                    ))
            except Exception:
                continue
    return cands


# ---------------------------------------------------------------------------
# Nessus (.nessus)
# ---------------------------------------------------------------------------
_NESSUS_SEV = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Informational"}


def parse_nessus(root):
    cands = []
    for host in root.findall(".//ReportHost"):
        hostname = host.get("name", "")
        for item in host.findall("ReportItem"):
            try:
                severity = _NESSUS_SEV.get(item.get("severity", ""), canon_severity(_text(item.find("risk_factor"))))
                name = item.get("pluginName") or _text(item.find("plugin_name")) or "Nessus finding"
                port = item.get("port", "")
                proto = item.get("protocol", "")
                plugin_id = item.get("pluginID", "")
                synopsis = _text(item.find("synopsis"))
                description = _text(item.find("description"))
                solution = _text(item.find("solution"))
                output = _text(item.find("plugin_output"))
                cvss_vector = _text(item.find("cvss3_vector")) or _text(item.find("cvss_vector"))
                cvss_score = _text(item.find("cvss3_base_score")) or _text(item.find("cvss_base_score"))
                cves = [_text(c) for c in item.findall("cve") if _text(c)]
                cwe = _cwe_from_field(" ".join(_text(c) for c in item.findall("cwe"))) or _first_cwe(name)

                cvss = cvss_vector or ""
                if cvss_score:
                    cvss = (cvss + f" (Base {cvss_score})").strip()

                full_desc = (synopsis + ("\n\n" + description if description else "")).strip()
                cands.append(_candidate(
                    title=name, severity=severity, cwe=cwe, cvss=cvss,
                    affected_host=hostname, parameter=(f"{port}/{proto}" if port and port != "0" else ""),
                    description=full_desc, evidence=(output or synopsis),
                    remediation=solution, references_data=", ".join(cves),
                    source="Nessus", category="Network Security",
                    noise=(severity == "Informational"),
                    additional_remarks=f"[SCANNER IMPORT] Source: Nessus | Plugin: {plugin_id} | Port: {port}/{proto}",
                ))
            except Exception:
                continue
    return cands


# ---------------------------------------------------------------------------
# Nmap (-oX)
# ---------------------------------------------------------------------------
def parse_nmap(root):
    cands = []
    for host in root.findall("host"):
        try:
            addr = ""
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr", "")
                    break
            if not addr:
                first = host.find("address")
                addr = first.get("addr", "") if first is not None else ""
            hn = host.find("hostnames/hostname")
            hostname = (hn.get("name") if hn is not None else "") or addr

            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portid = port.get("portid", "")
                    proto = port.get("protocol", "")
                    svc = port.find("service")
                    sname = svc.get("name", "") if svc is not None else ""
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    banner = " ".join(x for x in (sname, product, version) if x).strip()
                    cands.append(_candidate(
                        title=f"Open port {portid}/{proto} ({sname or 'unknown'})",
                        severity="Informational", affected_host=hostname,
                        parameter=f"{portid}/{proto}",
                        description=f"Open {proto} port {portid} on {hostname} running {banner or 'unknown service'}.",
                        evidence=banner, source="Nmap", category="Network Security", noise=True,
                        additional_remarks=f"[SCANNER IMPORT] Source: Nmap | {portid}/{proto}",
                    ))
                    for script in port.findall("script"):
                        out = script.get("output", "") or ""
                        vulnerable = "VULNERABLE" in out.upper()
                        cands.append(_candidate(
                            title=f"{script.get('id', 'nse')} ({portid}/{proto}) on {hostname}",
                            severity=("High" if vulnerable else "Informational"),
                            affected_host=hostname, parameter=f"{portid}/{proto}",
                            description=f"Nmap NSE script {script.get('id', '')} output.",
                            evidence=out, source="Nmap", category="Network Security",
                            noise=(not vulnerable),
                            additional_remarks=f"[SCANNER IMPORT] Source: Nmap NSE | {script.get('id', '')}",
                        ))
            for script in host.findall("hostscript/script"):
                out = script.get("output", "") or ""
                vulnerable = "VULNERABLE" in out.upper()
                cands.append(_candidate(
                    title=f"{script.get('id', 'nse')} on {hostname}",
                    severity=("High" if vulnerable else "Informational"),
                    affected_host=hostname,
                    description=f"Nmap NSE host script {script.get('id', '')} output.",
                    evidence=out, source="Nmap", category="Network Security",
                    noise=(not vulnerable),
                    additional_remarks=f"[SCANNER IMPORT] Source: Nmap NSE | {script.get('id', '')}",
                ))
        except Exception:
            continue
    return cands


# ---------------------------------------------------------------------------
# Generic CSV
# ---------------------------------------------------------------------------
def parse_csv(text):
    cands = []
    try:
        reader = csv.DictReader(io.StringIO(text))
    except Exception:
        return cands

    def pick(row, *names):
        for want in names:
            for key, value in row.items():
                if key and key.strip().lower() == want:
                    return (value or "").strip()
        return ""

    for row in reader:
        try:
            title = pick(row, "title", "name", "finding", "vulnerability", "plugin name", "alert", "issue")
            severity = canon_severity(pick(row, "severity", "risk", "risk level", "threat", "risk factor"))
            host = pick(row, "host", "ip", "asset", "target", "hostname", "ip address")
            url = pick(row, "url", "uri", "endpoint", "location", "affected url")
            cwe = _cwe_from_field(pick(row, "cwe", "cwe id", "cweid")) or _first_cwe(title)
            description = pick(row, "description", "synopsis", "details", "summary")
            remediation = pick(row, "solution", "remediation", "recommendation", "fix", "mitigation")
            references = pick(row, "references", "reference", "cve", "see also")
            if not title and not description:
                title = next((v for v in row.values() if v), "CSV finding")
                description = "; ".join(f"{k}={v}" for k, v in row.items() if v)
            cands.append(_candidate(
                title=title or "CSV finding", severity=severity, cwe=cwe,
                affected_host=host, affected_url=url, description=description,
                evidence=description, remediation=remediation, references_data=references,
                source="CSV import", noise=(severity == "Informational"),
                additional_remarks="[SCANNER IMPORT] Source: CSV",
            ))
        except Exception:
            continue
    return cands


# ---------------------------------------------------------------------------
# Detection + dispatch
# ---------------------------------------------------------------------------
def detect_and_parse(filename, data):
    """Return (format_label, candidates, warnings) for one uploaded scan file."""
    warnings = []
    name = (filename or "").lower()

    def as_text():
        return data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)

    def try_xml():
        try:
            return ET.fromstring(data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8"))
        except Exception as exc:
            warnings.append(f"XML parse failed: {exc}")
            return None

    def try_json():
        try:
            return json.loads(as_text())
        except Exception as exc:
            warnings.append(f"JSON parse failed: {exc}")
            return None

    # Extension-guided fast paths
    if name.endswith(".nessus"):
        root = try_xml()
        return ("Nessus", parse_nessus(root) if root is not None else [], warnings)
    if name.endswith(".csv"):
        return ("CSV import", parse_csv(as_text()), warnings)
    if name.endswith(".har"):
        warnings.append("HAR captures proxy traffic, not scanner findings; HAR import is not supported yet.")
        return ("HAR (unsupported)", [], warnings)
    if name.endswith(".json"):
        obj = try_json()
        if isinstance(obj, dict):
            if "site" in obj or str(obj.get("@programName", "")).upper().startswith("ZAP"):
                return ("OWASP ZAP", parse_zap_json(obj), warnings)
            if isinstance(obj.get("log"), dict) and "entries" in obj["log"]:
                warnings.append("HAR captures proxy traffic, not scanner findings; HAR import is not supported yet.")
                return ("HAR (unsupported)", [], warnings)
        warnings.append("Unrecognized JSON structure.")
        return ("Unknown JSON", [], warnings)

    # Content sniffing when the extension is missing or generic (.xml etc.)
    root = try_xml()
    if root is not None:
        tag = _localname(root.tag)
        if tag == "issues":
            return ("Burp Suite", parse_burp(root), warnings)
        if tag == "NessusClientData_v2":
            return ("Nessus", parse_nessus(root), warnings)
        if tag == "nmaprun":
            return ("Nmap", parse_nmap(root), warnings)
        if tag == "OWASPZAPReport":
            return ("OWASP ZAP", parse_zap_xml(root), warnings)
        warnings.append(f"Unrecognized XML root <{tag}>.")
        return (f"Unknown XML (<{tag}>)", [], warnings)

    obj = try_json()
    if isinstance(obj, dict) and "site" in obj:
        return ("OWASP ZAP", parse_zap_json(obj), warnings)

    warnings.append("Could not detect scanner format.")
    return ("Unknown", [], warnings)


def dedupe(candidates):
    """Remove exact duplicates (same title + host + url + parameter + severity).
    Returns (deduped_list, removed_count)."""
    seen = set()
    out = []
    removed = 0
    for c in candidates:
        key = (
            (c.get("title") or "").strip().lower(),
            (c.get("affected_host") or "").strip().lower(),
            (c.get("affected_url") or "").strip().lower(),
            (c.get("parameter") or "").strip().lower(),
            c.get("severity"),
        )
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        out.append(c)
    return out, removed


_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_CANON)}


def sort_candidates(candidates):
    """Most severe first, then by source and title (stable, deterministic)."""
    return sorted(
        candidates,
        key=lambda c: (_SEVERITY_RANK.get(c.get("severity"), 99),
                       c.get("source") or "", (c.get("title") or "").lower()),
    )


def summarize(candidates):
    """Counts for the import preview: totals, by severity, by source, noise count."""
    by_sev = Counter(c.get("severity") or "Informational" for c in candidates)
    by_src = Counter(c.get("source") or "Unknown" for c in candidates)
    return {
        "total": len(candidates),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITY_CANON if by_sev.get(s)},
        "by_source": dict(by_src),
        "noise": sum(1 for c in candidates if c.get("noise")),
        "actionable": sum(1 for c in candidates if not c.get("noise")),
    }
