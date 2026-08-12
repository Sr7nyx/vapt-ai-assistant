"""MITRE ATT&CK mapping for web and API weakness classes.

risk_map already carried one technique per class, and four classes carried none at
all. One technique is thin for a red-team report: an attacker rarely uses a
weakness in isolation, and the useful question is which TACTIC it serves and what
it enables next.

Two deliberate limits.

Every entry names its tactic. A technique id without a tactic is trivia; T1190
under Initial Access tells a reader where in an attack the finding sits, which is
the whole reason a report maps to ATT&CK at all.

Nothing is inferred. A class either has a mapping in this table or it does not,
and an unmapped class returns nothing rather than the nearest-looking technique.
A guessed ATT&CK id is worse than an absent one -- it reads as authoritative and
survives into a client's threat model.

Web application weaknesses map imperfectly to ATT&CK, which was built for
post-compromise behaviour on endpoints. That is a real limitation and is stated in
the report rather than papered over.
"""

# tactic -> the phase a reader recognises
TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


def _t(tid, name, tactic, note=""):
    return {"id": tid, "name": name, "tactic": tactic, "tactic_name": TACTICS[tactic], "note": note}


# Each class maps to the techniques an attacker actually chains, in the order they
# would be used. The first is the primary; the rest are what the weakness enables.
CLASS_TECHNIQUES = {
    "injection": [
        _t("T1190", "Exploit Public-Facing Application", "TA0001",
           "The injection itself, as the way in."),
        _t("T1213", "Data from Information Repositories", "TA0009",
           "Reading database contents once the query is under control."),
        _t("T1078", "Valid Accounts", "TA0004",
           "Authentication bypass, or credentials read from the database."),
    ],
    "xss": [
        _t("T1189", "Drive-by Compromise", "TA0001",
           "Script delivered to a user through a page they trust."),
        _t("T1539", "Steal Web Session Cookie", "TA0006",
           "The usual objective: session theft in the victim's browser."),
        _t("T1059.007", "JavaScript", "TA0002",
           "Execution in the victim's browser context."),
    ],
    "csrf": [
        _t("T1204.001", "User Execution: Malicious Link", "TA0002",
           "The victim's own browser performs the state change."),
        _t("T1565.001", "Stored Data Manipulation", "TA0040",
           "The action is taken with the victim's authority."),
    ],
    "access_control": [
        _t("T1190", "Exploit Public-Facing Application", "TA0001"),
        _t("T1078", "Valid Accounts", "TA0004",
           "Acting beyond the authorisation the account was granted."),
        _t("T1213", "Data from Information Repositories", "TA0009",
           "Reaching another principal's objects."),
    ],
    "path_traversal": [
        _t("T1083", "File and Directory Discovery", "TA0007"),
        _t("T1005", "Data from Local System", "TA0009",
           "Reading files outside the intended directory."),
    ],
    "ssrf": [
        _t("T1190", "Exploit Public-Facing Application", "TA0001"),
        _t("T1090", "Proxy", "TA0005",
           "The server issues the request, so its identity is used, not the attacker's."),
        _t("T1552.005", "Cloud Instance Metadata API", "TA0006",
           "The high-value target of most SSRF: instance credentials."),
    ],
    "info_disclosure": [
        _t("T1213", "Data from Information Repositories", "TA0009"),
        _t("T1592", "Gather Victim Host Information", "TA0007",
           "Versions, paths and stack details that shape a later attack."),
    ],
    "auth": [
        _t("T1078", "Valid Accounts", "TA0004"),
        _t("T1110", "Brute Force", "TA0006",
           "Where no rate limiting or lockout is enforced."),
        _t("T1556", "Modify Authentication Process", "TA0006",
           "Where the mechanism itself can be subverted, such as an unsigned token."),
    ],
    "crypto": [
        _t("T1557", "Adversary-in-the-Middle", "TA0006"),
        _t("T1040", "Network Sniffing", "TA0006",
           "Where transport is unencrypted or downgradeable."),
    ],
    "integrity": [
        _t("T1565", "Data Manipulation", "TA0040"),
        _t("T1195", "Supply Chain Compromise", "TA0001",
           "Where the unverified data is code or a dependency."),
    ],
    "misconfig": [
        _t("T1190", "Exploit Public-Facing Application", "TA0001"),
        _t("T1592", "Gather Victim Host Information", "TA0007",
           "Defaults and exposed interfaces that inform a later attack."),
    ],
    "misconfig_xxe": [
        _t("T1190", "Exploit Public-Facing Application", "TA0001"),
        _t("T1005", "Data from Local System", "TA0009",
           "External entities resolving to local files."),
        _t("T1090", "Proxy", "TA0005",
           "Out-of-band requests issued by the parser."),
    ],
    "components": [
        _t("T1195.001", "Compromise Software Dependencies and Development Tools", "TA0001"),
        _t("T1190", "Exploit Public-Facing Application", "TA0001",
           "Where the vulnerable component is reachable from outside."),
    ],
    "error_handling": [
        _t("T1592", "Gather Victim Host Information", "TA0007",
           "Stack traces and framework versions returned to the client."),
    ],
    "logging": [
        _t("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "TA0005",
           "Absent logging is what lets the rest of a chain go unnoticed."),
        _t("T1070", "Indicator Removal", "TA0005"),
    ],
    "open_redirect": [
        _t("T1566.002", "Phishing: Spearphishing Link", "TA0001",
           "A link on the real domain, which is what makes it convincing."),
        _t("T1204.001", "User Execution: Malicious Link", "TA0002"),
    ],
}


def techniques_for(klass):
    """Techniques for a weakness class, primary first. Empty when unmapped."""
    return list(CLASS_TECHNIQUES.get(klass or "", []))


def primary(klass):
    """The single technique to show where only one fits, matching the previous
    single-value field so nothing that reads it has to change."""
    techs = techniques_for(klass)
    return f"{techs[0]['id']} {techs[0]['name']}" if techs else ""


def coverage(findings):
    """ATT&CK coverage across a set of findings, grouped by tactic.

    Ordered by the phase of an attack rather than by count: a reader wants to see
    where in a kill chain the engagement found weaknesses, and sorting by frequency
    would put Discovery above Initial Access simply because there are more
    information-disclosure findings.
    """
    from collections import defaultdict

    by_tactic = defaultdict(dict)
    unmapped = 0

    for f in findings or []:
        frameworks = (f.get("_assessment") or {}).get("frameworks") or {}
        # class_key, not class: the latter is the human label ("Injection"), and
        # matching on a display string would silently break the moment one is
        # reworded.
        klass = frameworks.get("class_key") or ""
        techs = techniques_for(klass)
        if not techs:
            unmapped += 1
            continue
        # Only the primary technique counts toward coverage. Counting every
        # enabled technique would inflate the picture: one SSRF finding would
        # register across three tactics as though three things were found.
        t = techs[0]
        entry = by_tactic[t["tactic"]].setdefault(
            t["id"], {"id": t["id"], "name": t["name"], "count": 0}
        )
        entry["count"] += 1

    out = []
    for tid in TACTICS:
        if tid not in by_tactic:
            continue
        techs = sorted(by_tactic[tid].values(), key=lambda e: -e["count"])
        out.append({
            "tactic": tid,
            "tactic_name": TACTICS[tid],
            "techniques": techs,
            "count": sum(e["count"] for e in techs),
        })
    return {"tactics": out, "unmapped": unmapped}
