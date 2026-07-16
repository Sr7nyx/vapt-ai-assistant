"""Surface the analyzer's automated QA verdicts as structured flags.

The analyzer (gemini_client) writes a machine-generated QA block into each
finding's additional_remarks: deterministic CVSS result, severity cross-check,
evidence-grounding verdict, prompt-injection indicators, and the skeptical
reviewer's verdict. This module reads that block back into structured flags so
reports and the UI can show the important signals loudly. Pure stdlib.
"""
import re

_GROUNDING_RE = re.compile(
    r"Evidence grounding:\s*(VERIFIED|PARTIAL|UNVERIFIED|NO EVIDENCE|NO SOURCE)",
    re.IGNORECASE,
)
_VERDICT_RE = re.compile(r'verdict:\s*"([^"]+)"')
_EPSS_RE = re.compile(r"EPSS\s+(\d+(?:\.\d+)?)")

# Substrings that mark a line as a hard warning (used for red highlighting).
_WARNING_TOKENS = (
    "SEVERITY MISMATCH",
    "UNVERIFIED",
    "PROMPT-INJECTION",
    "REVIEWER DISAGREES",
    "COULD NOT PARSE",
    "CISA KEV: LISTED",
    "ACTIVELY EXPLOITED",
)


def is_warning_line(line):
    """True if a single QA line should be rendered as a warning (red)."""
    up = str(line).upper()
    return any(tok in up for tok in _WARNING_TOKENS)


def summarize_qa(finding):
    """Derive structured QA flags from a finding dict.

    Returns a dict:
      grounding         -> 'VERIFIED' | 'PARTIAL' | 'UNVERIFIED' | 'NO EVIDENCE' | 'NO SOURCE' | None
      severity_mismatch -> bool   (model severity disagrees with computed CVSS band)
      injection         -> bool   (prompt-injection indicators in the source)
      reviewer_disagree -> bool   (skeptical reviewer disagrees on severity)
      review_verdict    -> str | None
      warnings          -> list[str]  (hard issues; render red)
      cautions          -> list[str]  (soft issues; render amber)
      level             -> 'danger' | 'warn' | 'ok' | 'none'
    """
    ar = str((finding or {}).get("additional_remarks", "") or "")

    grounding = None
    match = _GROUNDING_RE.search(ar)
    if match:
        grounding = match.group(1).upper()

    severity_mismatch = "SEVERITY MISMATCH" in ar
    injection = "PROMPT-INJECTION INDICATORS" in ar
    reviewer_disagree = "REVIEWER DISAGREES" in ar

    review_verdict = None
    verdict_match = _VERDICT_RE.search(ar)
    if verdict_match:
        review_verdict = verdict_match.group(1).strip()

    # Exploitation intel (from CVE enrichment): CISA KEV + EPSS.
    kev = ("CISA KEV: LISTED" in ar) or ("ACTIVELY EXPLOITED" in ar.upper())
    epss_values = [float(v) for v in _EPSS_RE.findall(ar)]
    epss = max(epss_values) if epss_values else None
    intel = []
    if kev:
        intel.append("Actively exploited (CISA KEV)")
    if epss is not None and epss >= 0.10:
        intel.append(f"EPSS {epss * 100:.0f}%")

    warnings, cautions = [], []
    if injection:
        warnings.append("Prompt-injection indicators in source")
    if grounding == "UNVERIFIED":
        warnings.append("Evidence unverified (possibly fabricated)")
    if severity_mismatch:
        warnings.append("Severity disagrees with CVSS")
    if reviewer_disagree:
        warnings.append("Reviewer disagrees on severity")

    if grounding == "PARTIAL":
        cautions.append("Evidence only partially verified")
    elif grounding in ("NO EVIDENCE", "NO SOURCE"):
        cautions.append("Evidence not verifiable")
    if review_verdict and review_verdict.lower() in ("needs more evidence", "likely false positive"):
        cautions.append(f"Reviewer: {review_verdict}")

    if warnings or kev:
        level = "danger"
    elif cautions:
        level = "warn"
    elif grounding == "VERIFIED":
        level = "ok"
    else:
        level = "none"

    return {
        "grounding": grounding,
        "severity_mismatch": severity_mismatch,
        "injection": injection,
        "reviewer_disagree": reviewer_disagree,
        "review_verdict": review_verdict,
        "kev": kev,
        "epss": epss,
        "intel": intel,
        "warnings": warnings,
        "cautions": cautions,
        "level": level,
    }


def qa_flag_text(finding):
    """One-line summary of exploitation intel + QA warnings + cautions for
    spreadsheet cells and report banners. Returns '' when there is nothing to flag."""
    summary = summarize_qa(finding)
    parts = list(summary["intel"]) + list(summary["warnings"]) + list(summary["cautions"])
    return "; ".join(parts)
