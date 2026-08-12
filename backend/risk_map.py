"""Deterministic risk prioritization + security-framework mapping.

Two capabilities, both pure-stdlib, offline, and fully reproducible (no LLM):

1. RISK PRIORITY -- goes beyond raw CVSS severity by blending the signals
   already attached to a finding (CVSS base score, EPSS exploit probability,
   CISA KEV active-exploitation flag, and the affected environment) into a
   single priority band (Urgent / High / Moderate / Low) with a plain-language
   rationale. This is the modern, risk-based view: severity is *not* urgency
   until exploitation and exposure are factored in (CISA/SSVC-aligned).

2. FRAMEWORK MAPPING -- maps each finding, from its CWE (with a keyword
   fallback), to the frameworks clients ask about:
     - OWASP Top 10:2025  (current edition; SSRF folded into A01, two new
       categories, renumbered vs 2021)
     - PCI DSS v4.0.1     (Req 6.2.4 secure coding; 6.3.x components; plus
       data/auth/logging requirements)
     - NIST SP 800-53 Rev 5 control(s)
     - MITRE ATT&CK technique (indicative, where one applies)

Mappings are INDICATIVE -- a defensible starting point to confirm against the
specific engagement scope, not an authoritative compliance audit.
"""
import re

from qa_utils import summarize_qa
import attack_map

# ---------------------------------------------------------------------------
# Risk priority (tunable, transparent)
# ---------------------------------------------------------------------------
KEV_SCORE = 95            # active exploitation dominates everything else
KEV_PROD_SCORE = 99
CVSS_WEIGHT = 8.0         # CVSS base (0-10) -> 0-80 of the score
EPSS_HIGH = 0.50          # >= 50% predicted 30-day exploitation
EPSS_ELEVATED = 0.10      # >= 10%
EPSS_HIGH_BONUS = 18
EPSS_ELEVATED_BONUS = 9
PROD_BONUS = 8

URGENT_AT = 80
HIGH_AT = 56
MODERATE_AT = 32

_PROD_ENVS = {"prod", "production", "live"}

_BASE_RE = re.compile(r"Base\s+(\d+(?:\.\d+)?)", re.IGNORECASE)
_SEVERITY_SCORE = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
    "informational": 0.5, "info": 0.5, "none": 0.0,
}


def cvss_base_of(finding):
    """Best-effort CVSS base score (0-10). Reads the computed '(Base X.X, ...)'
    the analyzer appends to the vector; falls back to the severity label."""
    cvss = str((finding or {}).get("cvss", "") or "")
    match = _BASE_RE.search(cvss)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    sev = str((finding or {}).get("severity", "") or "").strip().lower()
    return _SEVERITY_SCORE.get(sev)


def _band(score):
    if score >= URGENT_AT:
        return "Urgent"
    if score >= HIGH_AT:
        return "High"
    if score >= MODERATE_AT:
        return "Moderate"
    return "Low"


def compute_risk_priority(finding):
    """Return {priority, score, rationale, signals} from CVSS + EPSS + KEV + env.

    The score is transparent and tunable via the module constants; the rationale
    explains every input that moved it."""
    qa = summarize_qa(finding)
    kev = bool(qa.get("kev"))
    epss = qa.get("epss")  # 0..1 or None
    base = cvss_base_of(finding)
    env_raw = str((finding or {}).get("environment", "") or "").strip()
    prod = env_raw.lower() in _PROD_ENVS

    signals = {
        "cvss_base": base,
        "epss": epss,
        "kev": kev,
        "environment": env_raw or "Unknown",
    }

    if kev:
        reasons = ["actively exploited in the wild (CISA KEV)"]
        score = KEV_SCORE
        if prod:
            reasons.append("production asset")
            score = KEV_PROD_SCORE
        return {"priority": "Urgent", "score": int(score),
                "rationale": "; ".join(reasons), "signals": signals}

    reasons = []
    if base is not None:
        reasons.append(f"CVSS base {base:.1f}")
        score = base * CVSS_WEIGHT
    else:
        reasons.append(f"severity {finding.get('severity') or 'unknown'} (no CVSS vector)")
        score = _SEVERITY_SCORE.get(
            str(finding.get("severity", "") or "").strip().lower(), 5.0
        ) * CVSS_WEIGHT

    if epss is not None:
        if epss >= EPSS_HIGH:
            score += EPSS_HIGH_BONUS
            reasons.append(f"high exploit probability (EPSS {epss * 100:.0f}%)")
        elif epss >= EPSS_ELEVATED:
            score += EPSS_ELEVATED_BONUS
            reasons.append(f"elevated exploit probability (EPSS {epss * 100:.0f}%)")

    if prod:
        score += PROD_BONUS
        reasons.append("production asset")

    score = max(0, min(100, round(score)))
    priority = _band(score)
    if priority in ("High", "Moderate", "Low") and not (epss is not None and epss >= EPSS_ELEVATED) and not prod:
        reasons.append("no active-exploitation or production-exposure signal to escalate")
    return {"priority": priority, "score": int(score),
            "rationale": "; ".join(reasons), "signals": signals}


# ---------------------------------------------------------------------------
# Framework mapping
# ---------------------------------------------------------------------------
# OWASP Top 10:2025 (current edition, finalized Jan 2026). Canonical names:
OWASP_2025 = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging and Alerting Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
}

# Weakness class -> framework records. PCI is v4.0.1; NIST is SP 800-53 Rev 5.
_CLASS_INFO = {
    "injection": {
        "label": "Injection",
        "owasp": "A05",
        "pci": "6.2.4 (injection attacks)",
        "nist": "SI-10 Information Input Validation",
        "attack": "T1190 Exploit Public-Facing Application",
    },
    "xss": {
        "label": "Cross-Site Scripting",
        "owasp": "A05",
        "pci": "6.2.4 (XSS); 6.4.3 if a payment-page script",
        "nist": "SI-10 Information Input Validation",
        "attack": "T1059 Command and Scripting Interpreter",
    },
    "csrf": {
        "label": "Cross-Site Request Forgery",
        "owasp": "A01",
        "pci": "6.2.4 (CSRF)",
        "nist": "SC-23 Session Authenticity",
        "attack": "",
    },
    "access_control": {
        "label": "Broken Access Control / IDOR",
        "owasp": "A01",
        "pci": "6.2.4 (access control); Req 7 (restrict access)",
        "nist": "AC-3 Access Enforcement; AC-6 Least Privilege",
        "attack": "T1190 Exploit Public-Facing Application",
    },
    "path_traversal": {
        "label": "Path Traversal",
        "owasp": "A01",
        "pci": "6.2.4 (access control / injection)",
        "nist": "AC-3 Access Enforcement; SI-10 Input Validation",
        "attack": "T1083 File and Directory Discovery",
    },
    "ssrf": {
        "label": "Server-Side Request Forgery",
        "owasp": "A01",  # 2025: SSRF folded into Broken Access Control
        "pci": "6.2.4 (business logic / injection)",
        "nist": "SC-7 Boundary Protection; AC-4 Information Flow Enforcement",
        "attack": "T1190 Exploit Public-Facing Application",
    },
    "info_disclosure": {
        "label": "Sensitive Information Disclosure",
        "owasp": "A01",
        "pci": "Req 3 (stored data); Req 4 (data in transit)",
        "nist": "SC-28 Protection of Information at Rest; AC-3 Access Enforcement",
        "attack": "T1213 Data from Information Repositories",
    },
    "auth": {
        "label": "Authentication / Session Failure",
        "owasp": "A07",
        "pci": "Req 8 (authentication / MFA); 6.2.4 (broken auth)",
        "nist": "IA-2 Identification and Authentication; IA-5 Authenticator Management",
        "attack": "T1078 Valid Accounts",
    },
    "crypto": {
        "label": "Cryptographic Failure",
        "owasp": "A04",
        "pci": "6.2.4 (crypto usage); Req 4 (transit); Req 3 (at rest)",
        "nist": "SC-8 Transmission Confidentiality and Integrity; SC-13 Cryptographic Protection",
        "attack": "T1557 Adversary-in-the-Middle",
    },
    "integrity": {
        "label": "Software / Data Integrity Failure",
        "owasp": "A08",
        "pci": "6.2.4 (data and data structures)",
        "nist": "SI-7 Software, Firmware, and Information Integrity",
        "attack": "T1565 Data Manipulation",
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "owasp": "A02",
        "pci": "Req 2 (secure configuration); 6.4.x (public-facing app)",
        "nist": "CM-6 Configuration Settings; CM-7 Least Functionality",
        "attack": "",
    },
    "misconfig_xxe": {
        "label": "XML External Entities (XXE)",
        "owasp": "A02",  # 2025: XXE under Security Misconfiguration
        "pci": "6.2.4 (injection / data structures)",
        "nist": "CM-6 Configuration Settings; SI-10 Input Validation",
        "attack": "T1190 Exploit Public-Facing Application",
    },
    "components": {
        "label": "Vulnerable / Outdated Component",
        "owasp": "A03",  # 2025: Software Supply Chain Failures
        "pci": "6.3.1 / 6.3.2 / 6.3.3 (inventory, identify, patch)",
        "nist": "RA-5 Vulnerability Monitoring; SA-22 Unsupported System Components",
        "attack": "T1195 Supply Chain Compromise",
    },
    "error_handling": {
        "label": "Improper Error / Exception Handling",
        "owasp": "A10",  # 2025: Mishandling of Exceptional Conditions
        "pci": "6.2.4 (secure coding)",
        "nist": "SI-11 Error Handling",
        "attack": "",
    },
    "logging": {
        "label": "Logging / Alerting Failure",
        "owasp": "A09",
        "pci": "Req 10 (logging and monitoring)",
        "nist": "AU-2 Event Logging; AU-6 Audit Record Review; SI-4 System Monitoring",
        "attack": "",
    },
    "open_redirect": {
        "label": "Open Redirect",
        "owasp": "A01",
        "pci": "6.2.4 (secure coding)",
        "nist": "SI-10 Information Input Validation",
        "attack": "T1566 Phishing",
    },
}

# CWE id -> weakness class.
_CWE_TO_CLASS = {
    # Injection
    77: "injection", 78: "injection", 88: "injection", 89: "injection",
    90: "injection", 91: "injection", 94: "injection", 95: "injection",
    564: "injection", 643: "injection", 652: "injection", 917: "injection", 943: "injection",
    # XSS
    79: "xss", 80: "xss", 83: "xss",
    # CSRF
    352: "csrf",
    # Path traversal
    22: "path_traversal", 23: "path_traversal", 35: "path_traversal", 36: "path_traversal",
    # Access control
    284: "access_control", 285: "access_control", 425: "access_control",
    566: "access_control", 639: "access_control", 862: "access_control",
    863: "access_control", 913: "access_control",
    # Info disclosure
    200: "info_disclosure", 201: "info_disclosure", 209: "error_handling",
    213: "info_disclosure", 538: "info_disclosure",
    # SSRF
    918: "ssrf",
    # Auth / session
    256: "auth", 287: "auth", 288: "auth", 290: "auth", 294: "auth",
    297: "auth", 306: "auth", 307: "auth", 384: "auth", 521: "auth",
    522: "auth", 613: "auth", 620: "auth", 640: "auth", 798: "auth",
    # Crypto
    295: "crypto", 311: "crypto", 319: "crypto", 321: "crypto", 326: "crypto",
    327: "crypto", 328: "crypto", 330: "crypto", 331: "crypto", 759: "crypto",
    760: "crypto", 916: "crypto",
    # Integrity / deserialization
    345: "integrity", 347: "integrity", 494: "integrity", 502: "integrity",
    565: "integrity", 829: "integrity", 915: "integrity",
    # Misconfiguration
    16: "misconfig", 260: "misconfig", 432: "misconfig", 437: "misconfig",
    548: "misconfig", 614: "misconfig", 693: "misconfig", 732: "misconfig",
    942: "misconfig", 1004: "misconfig", 1021: "misconfig", 1032: "misconfig",
    # XXE
    611: "misconfig_xxe", 776: "misconfig_xxe", 827: "misconfig_xxe",
    # Components / supply chain
    937: "components", 1035: "components", 1104: "components", 1395: "components",
    # Error / exceptional conditions
    248: "error_handling", 388: "error_handling", 390: "error_handling",
    392: "error_handling", 460: "error_handling", 636: "error_handling",
    703: "error_handling", 754: "error_handling", 755: "error_handling",
    # Logging
    117: "logging", 223: "logging", 532: "logging", 778: "logging",
    # Open redirect
    601: "open_redirect",
}

# Keyword fallback when no CWE is present (ordered: first match wins).
_KEYWORD_CLASS = [
    ("sql injection", "injection"), ("sqli", "injection"),
    ("command injection", "injection"), ("os command", "injection"),
    ("ldap injection", "injection"), ("template injection", "injection"),
    ("code injection", "injection"), ("xpath", "injection"),
    ("cross-site request forgery", "csrf"), ("csrf", "csrf"),
    ("cross-site scripting", "xss"), ("xss", "xss"),
    ("server-side request forgery", "ssrf"), ("ssrf", "ssrf"),
    ("idor", "access_control"), ("insecure direct object", "access_control"),
    ("broken access", "access_control"), ("authorization", "access_control"),
    ("privilege escalation", "access_control"), ("forced browsing", "access_control"),
    ("bola", "access_control"), ("bfla", "access_control"),
    ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
    ("xml external", "misconfig_xxe"), ("xxe", "misconfig_xxe"),
    ("deserial", "integrity"), ("integrity", "integrity"),
    ("hardcoded credential", "auth"), ("session fixation", "auth"),
    ("broken authentication", "auth"), ("authentication", "auth"),
    ("session", "auth"), ("brute force", "auth"), ("mfa", "auth"),
    ("cleartext", "crypto"), ("weak cipher", "crypto"), ("weak encryption", "crypto"),
    ("tls", "crypto"), ("ssl", "crypto"), ("certificate", "crypto"),
    ("cryptograph", "crypto"), ("hashing", "crypto"),
    ("open redirect", "open_redirect"),
    ("clickjack", "misconfig"), ("security header", "misconfig"),
    ("content security policy", "misconfig"), ("csp", "misconfig"),
    ("hsts", "misconfig"), ("cors", "misconfig"), ("default credential", "misconfig"),
    ("misconfigur", "misconfig"),
    ("outdated", "components"), ("vulnerable component", "components"),
    ("dependency", "components"), ("supply chain", "components"),
    ("verbose error", "error_handling"), ("stack trace", "error_handling"),
    ("error handling", "error_handling"), ("exception", "error_handling"),
    ("logging", "logging"), ("insufficient log", "logging"), ("audit log", "logging"),
    ("information disclosure", "info_disclosure"), ("sensitive data", "info_disclosure"),
    ("information exposure", "info_disclosure"),
]

_CWE_RE = re.compile(r"CWE[-\s_]?(\d{1,5})", re.IGNORECASE)


def extract_cwe(finding):
    """First CWE id referenced in the finding's cwe/title/description, or None."""
    for field in ("cwe", "title", "description"):
        text = str((finding or {}).get(field, "") or "")
        match = _CWE_RE.search(text)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                continue
    return None


def infer_class(finding):
    """Resolve the weakness class from CWE, falling back to keywords. Returns
    (class_key, basis) where basis explains how it was resolved, or (None, ...)."""
    cwe = extract_cwe(finding)
    if cwe is not None and cwe in _CWE_TO_CLASS:
        return _CWE_TO_CLASS[cwe], f"CWE-{cwe}"
    haystack = " ".join(
        str((finding or {}).get(f, "") or "") for f in ("title", "category", "description")
    ).lower()
    for keyword, klass in _KEYWORD_CLASS:
        if keyword in haystack:
            return klass, f"matched \"{keyword}\""
    if cwe is not None:
        return None, f"CWE-{cwe} (not in mapping table)"
    return None, "no CWE or recognizable class"


def map_frameworks(finding):
    """Map a finding to OWASP 2025 / PCI 4.0.1 / NIST 800-53 / MITRE ATT&CK.

    Returns a dict; values are '' when nothing applies. 'mapped' is False when the
    weakness class could not be resolved (assign manually)."""
    cwe = extract_cwe(finding)
    klass, basis = infer_class(finding)
    if not klass:
        return {
            "mapped": False,
            "class": None,
            "class_key": None,
            "attack_techniques": [],
            "cwe": f"CWE-{cwe}" if cwe is not None else "",
            "owasp": "",
            "pci": "",
            "nist": "",
            "attack": "",
            "basis": basis,
        }
    info = _CLASS_INFO[klass]
    # attack_map is authoritative now: it carries a tactic and the techniques a
    # weakness enables, where _CLASS_INFO held a single id and left four classes
    # blank. The single string is kept so anything reading `attack` still works.
    techniques = attack_map.techniques_for(klass)
    return {
        "mapped": True,
        # `class` is the label a reader sees; `class_key` is the stable identifier
        # other modules match on. Exposing both avoids changing what `class` means,
        # which the findings table already displays.
        "class_key": klass,
        "attack_techniques": techniques,
        "class": info["label"],
        "cwe": f"CWE-{cwe}" if cwe is not None else "",
        "owasp": OWASP_2025.get(info["owasp"], ""),
        "pci": "PCI DSS v4.0.1 " + info["pci"],
        "nist": info["nist"],
        "attack": attack_map.primary(klass) or info["attack"],
        "basis": basis,
    }


def assess(finding):
    """Convenience: combined risk priority + framework mapping for a finding."""
    return {
        "risk": compute_risk_priority(finding),
        "frameworks": map_frameworks(finding),
    }
