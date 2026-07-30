"""Pre-flight check on analyzer input.

Every analysis costs at least two model calls -- extraction, then the skeptical
reviewer -- so input that plainly is not security evidence should be turned away
before any of that is spent.

The check deliberately does NOT look for profanity or "inappropriate" content.
Real evidence is full of hostile strings: an XSS proof of concept is a rude
payload, log excerpts carry whatever users typed, and an attacker's input is the
whole point of the artefact. Filtering on tone would reject exactly the material
this tool exists to analyse.

What it looks for instead is whether the text carries any security-relevant
structure at all: protocol shapes, network identifiers, scanner output, code,
configuration, stack traces, payload markers, or the vocabulary of the field. The
gate is intentionally narrow -- a wrongly rejected analysis costs the user real
work, while a wrongly accepted one costs a few thousand tokens -- so it only
refuses text that is both short and entirely devoid of signal, or long and clearly
plain prose.
"""
import re

# Strong: protocol and payload shapes almost never appear by accident.
_STRONG = [
    ("http_message", re.compile(r"HTTP/\d(\.\d)?", re.I)),
    ("request_line", re.compile(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+", re.I | re.M)),
    ("http_header", re.compile(
        r"^\s*(Host|User-Agent|Authorization|Cookie|Set-Cookie|Content-Type|Referer|Origin|"
        r"X-Forwarded-For|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|"
        r"Access-Control-Allow-Origin|WWW-Authenticate|Location|Server)\s*:", re.I | re.M)),
    ("url", re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("identifier", re.compile(r"\b(CVE-\d{4}-\d{3,}|CWE-\d{1,4}|CAPEC-\d+)\b", re.I)),
    ("cvss_vector", re.compile(r"CVSS:\d\.\d/", re.I)),
    ("injection_payload", re.compile(
        r"('\s*(OR|AND)\s*'?\d|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|--\s*$|/\*.*\*/|"
        r"<script|javascript:|onerror\s*=|\.\./\.\./|%27|%3Cscript|\$\{|\{\{)", re.I | re.M)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\b")),
    ("metadata_endpoint", re.compile(r"169\.254\.169\.254|metadata\.google\.internal")),
    # "22/tcp open ssh" -- port/protocol notation barely occurs outside scanner output.
    ("port_service", re.compile(r"\b\d{1,5}/(tcp|udp)\b", re.I)),
]

# Medium: the vocabulary and artefacts of the work. Any two of these, or one plus
# some structure, is enough to look like a genuine submission.
_VOCABULARY = re.compile(
        r"\b(vulnerab\w*|exploit\w*|payload|proof[- ]of[- ]concept|poc|injection|sqli|xss|ssrf|xxe|csrf|"
        r"idor|bola|rce|lfi|rfi|ssti|deserializ\w*|traversal|clickjack\w*|open\s+redirect|"
        r"authenticat\w*|authoriz\w*|privilege|escalat\w*|bypass|brute[- ]force|enumerat\w*|"
        r"rate[- ]limit\w*|lockout|token|jwt|session|cookie|credential|password|secret|api[- ]key|"
        r"tls|ssl|certificate|cipher|hsts|csp|cors|same[- ]?site|httponly|"
        r"owasp|pci[- ]dss|mitre|att&ck|epss|kev|severity|remediat\w*|mitigat\w*|"
        r"nmap|nessus|burp|zap|nikto|sqlmap|metasploit|wireshark|scanner|scan\b|"
        r"ssh|ftps?|smtp|imap|pop3|dns|ldaps?|smb|netbios|rdp|vnc|telnet|snmp|"
        r"mysql|postgres\w*|mssql|oracle|redis|mongo\w*|elastic\w*|memcached|rabbitmq|"
        r"nginx|apache|openssh|iis|tomcat|jetty|gunicorn|uvicorn|node\.js|"
        r"port\s+\d+|banner|fingerprint|misconfigur\w*|hardcoded|disclosure|leak\w*)\b", re.I)

_MEDIUM = [
    ("security_vocabulary", _VOCABULARY),
    ("code_or_config", re.compile(
        r"(\bSELECT\b.+\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b.+\bSET\b|#!/|\bsudo\b|\bchmod\b|"
        r"\blocation\s*/|\bserver\s*\{|\bListen\b|\bDocumentRoot\b|\bdef\s+\w+\(|\bfunction\s+\w+\(|"
        r"\bclass\s+\w+|\bimport\s+\w+|\brequire\(|<\?xml|<\?php)", re.I)),
    ("stack_trace", re.compile(r"(Traceback \(most recent call last\)|\bat\s+[\w.$]+\([^)]*:\d+\)|\w+Exception\b|\w+Error:\s)", re.I)),
    ("structured_data", re.compile(r"(^\s*[\{\[]|</\w+>|<\w+[^>]*>.*</\w+>)", re.M)),
    ("key_value_block", re.compile(r"^\s*[\w.-]{2,40}\s*[:=]\s*\S+", re.M)),
    ("status_or_port", re.compile(r"\b(200|301|302|400|401|403|404|405|500|502|503)\b|\b:\d{2,5}\b")),
]

# Structural punctuation. Prose has very little of it; logs, code and config are
# full of it, which is what separates a pasted article from a config file.
_STRUCTURE = re.compile(r"[{}\[\]<>/\\|=;$#]")

MIN_CHARS_WITHOUT_SIGNAL = 120
MIN_STRUCTURE_RATIO = 0.008


def _matches(text, patterns):
    return [name for name, rx in patterns if rx.search(text)]


def assess_input(raw):
    """Judge whether text is plausibly security evidence.

    Returns a dict with ok, reason, signals, score and chars. `reason` is written
    for the person who submitted it, and says plainly that nothing was spent.
    """
    text = (raw or "").strip()
    chars = len(text)

    if chars == 0:
        return {
            "ok": False,
            "reason": "There is nothing to analyse. Paste an HTTP request or response, scanner output, a log excerpt, configuration, or a code snippet.",
            "signals": [], "score": 0, "chars": 0,
        }

    strong = _matches(text, _STRONG)
    medium = _matches(text, _MEDIUM)
    # Distinct vocabulary terms, not just "the vocabulary matched somewhere". Two
    # unrelated terms is real evidence of intent; one could be coincidence.
    vocab_terms = {t.lower() for t in _VOCABULARY.findall(text)}
    score = len(strong) * 2 + len(medium) + max(0, len(vocab_terms) - 1)
    signals = strong + medium

    lines = [l for l in text.splitlines() if l.strip()]
    structure_ratio = len(_STRUCTURE.findall(text)) / max(1, chars)

    # Any strong signal is enough on its own: a single request line or a CVE id is
    # a legitimate thing to submit.
    if strong:
        return {"ok": True, "reason": "", "signals": signals, "score": score, "chars": chars}

    # Two or more independent signals stand on their own, however terse:
    # "Port 443 accepts TLS 1.0" is a legitimate, if brief, submission.
    if len(medium) >= 2 or len(vocab_terms) >= 2:
        return {"ok": True, "reason": "", "signals": signals, "score": score, "chars": chars}

    # A single vocabulary match needs enough surrounding text to be worth a call.
    if medium and (chars >= 40 or len(lines) > 1):
        return {"ok": True, "reason": "", "signals": signals, "score": score, "chars": chars}

    # No signal at all. Short input is turned away outright.
    if chars < MIN_CHARS_WITHOUT_SIGNAL:
        return {
            "ok": False,
            "reason": (
                "This does not look like security evidence, so no analysis was run and no tokens were "
                "used. Paste an HTTP request or response, scanner output, a log excerpt, configuration, "
                "or a code snippet -- or describe the issue using the terms of the finding."
            ),
            "signals": [], "score": 0, "chars": chars,
        }

    # Long, but no signal and almost no structural punctuation: prose, not evidence.
    if structure_ratio < MIN_STRUCTURE_RATIO:
        return {
            "ok": False,
            "reason": (
                "This reads as prose rather than security evidence, so no analysis was run and no tokens "
                "were used. Include the request, response, scanner output, log lines, configuration, or "
                "code the finding rests on."
            ),
            "signals": [], "score": 0, "chars": chars,
        }

    # Long and structured, with no vocabulary match: unusual, but plausibly a log
    # or dump the patterns simply do not cover. Let it through.
    return {"ok": True, "reason": "", "signals": signals, "score": score, "chars": chars}
