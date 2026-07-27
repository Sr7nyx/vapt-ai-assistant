"""Deterministic verdict resolution.

The skeptical reviewer produces hedged signals: an evidence-grounding level, an
exploitability judgement, a false-positive risk, a verdict, a confidence. Those
are inputs, not conclusions. This module combines them by rule into a single
status and a confidence score.

The point is that confidence is *earned* by signals agreeing under a transparent
rule, not manufactured by asking a model to sound certain. When the signals are
unambiguous the engine commits to Confirmed or False Positive; when they conflict
or are weak it holds at Need Review, because forcing a verdict onto ambiguous
evidence is the failure this whole tool exists to avoid.

Two errors are treated asymmetrically, as they should be in security work:
  - Confirming a false positive wastes remediation effort.
  - Dismissing a real vulnerability is worse.
So the engine never dismisses a well-evidenced finding (VERIFIED grounding with
demonstrated exploitability can never resolve to False Positive), and never
confirms an ungrounded one (no Confirmed without at least PARTIAL grounding).
"""
import os
import re

# Statuses the resolver is allowed to assign. Accepted Risk, Fixed and the retest
# outcomes are human and business decisions and are never set automatically.
STATUS_CONFIRMED = "Confirmed"
STATUS_FALSE_POSITIVE = "False Positive"
STATUS_NEEDS_REVIEW = "Need Review"

# Human/terminal statuses the engine must never overwrite: if a person (or a
# retest) has already ruled on a finding, an auto-pass does not un-rule it.
PROTECTED_STATUSES = {
    "accepted risk",
    "fixed",
    "retest passed",
    "retest failed",
    "false positive",
    "confirmed",
}


def _norm(value):
    return str(value or "").strip().lower()


def _grounding_of(finding, review):
    g = _norm(review.get("grounding") if review else "")
    if g:
        return g.upper().replace("_", " ")
    text = str(finding.get("additional_remarks", "") or "")
    m = re.search(r"Evidence grounding:\s*(VERIFIED|PARTIAL|UNVERIFIED|NO EVIDENCE|NO SOURCE)", text, re.I)
    return m.group(1).upper() if m else ""


def _exploitability_bucket(review):
    """Collapse the reviewer's free-text exploitability to one of three tokens."""
    e = _norm(review.get("exploitability") if review else "")
    if not e:
        return ""
    if "demonstrat" in e or "confirmed" in e:
        return "demonstrated"
    if "theoret" in e or "no demonstrated" in e or "no impact" in e or "not exploit" in e:
        return "theoretical"
    if "plausib" in e or "potential" in e or "possible" in e:
        return "plausible"
    return ""


def _verdict_lean(review):
    v = _norm(review.get("verdict") if review else "")
    if not v:
        return 0
    if "false positive" in v:
        return -2
    if "confirmed" in v:
        return +2
    if "likely valid" in v or "likely true" in v or "valid" in v:
        return +1
    if "needs more" in v or "more evidence" in v or "inconclusive" in v:
        return 0
    return 0


def _auto_status_enabled():
    return (os.environ.get("VAPT_AUTO_STATUS") or "1").strip().lower() in ("1", "true", "yes", "on")


def resolve_verdict(finding, review=None):
    """Return a deterministic decision for a finding given its review signals.

    Result keys:
      resolved_status  Confirmed | False Positive | Need Review
      confidence       0.0 .. 1.0
      confidence_label High | Medium | Low
      rationale        one line naming the signals that drove the decision
      signals          the normalized signals the decision was based on
      auto_set         whether this status should overwrite the stored status
    """
    review = review or {}

    grounding = _grounding_of(finding, review)
    exploit = _exploitability_bucket(review)
    fp_risk = _norm(review.get("false_positive_risk"))
    reviewer_conf = _norm(review.get("confidence"))
    injection = bool(review.get("injection"))
    disagree = bool(review.get("severity_disagreement"))
    verdict_lean = _verdict_lean(review)
    reviewed = bool(review.get("reviewed"))

    signals = {
        "grounding": grounding or "n/a",
        "exploitability": exploit or "n/a",
        "false_positive_risk": fp_risk or "n/a",
        "reviewer_verdict_lean": verdict_lean,
        "injection": injection,
        "severity_disagreement": disagree,
    }

    # A finding nobody audited cannot be auto-decided. It also cannot be trusted;
    # it simply awaits review.
    if not reviewed:
        return {
            "resolved_status": STATUS_NEEDS_REVIEW,
            "confidence": 0.0,
            "confidence_label": "Low",
            "rationale": "Not independently reviewed; awaiting audit.",
            "signals": signals,
            "auto_set": False,
        }

    # Prompt-injection indicators in the source mean the evidence itself may be
    # adversarial. No automated verdict; a human must look.
    if injection:
        return {
            "resolved_status": STATUS_NEEDS_REVIEW,
            "confidence": 0.0,
            "confidence_label": "Low",
            "rationale": "Prompt-injection indicators in the source; manual review required.",
            "signals": signals,
            "auto_set": True,
        }

    # Score the evidence for and against the finding being real. Positive = more
    # likely a true positive; negative = more likely a false positive.
    score = 0.0
    reasons = []

    if grounding == "VERIFIED":
        score += 2.0; reasons.append("evidence verified")
    elif grounding == "PARTIAL":
        score += 0.5; reasons.append("evidence partial")
    elif grounding in ("UNVERIFIED", "NO EVIDENCE", "NO SOURCE"):
        score -= 2.0; reasons.append("evidence unverified")

    if exploit == "demonstrated":
        score += 2.0; reasons.append("exploitability demonstrated")
    elif exploit == "theoretical":
        score -= 1.5; reasons.append("exploitability only theoretical")
    elif exploit == "plausible":
        score += 0.0

    if fp_risk == "high":
        score -= 2.0; reasons.append("high false-positive risk")
    elif fp_risk == "low":
        score += 1.0; reasons.append("low false-positive risk")

    score += verdict_lean * 0.75
    if verdict_lean <= -2:
        reasons.append("reviewer judged false positive")
    elif verdict_lean >= 1:
        reasons.append("reviewer judged valid")

    # Guardrails that override the score, encoding the asymmetric cost of errors.
    well_evidenced = grounding == "VERIFIED" and exploit == "demonstrated"
    ungrounded = grounding in ("UNVERIFIED", "NO EVIDENCE", "NO SOURCE", "")

    decided = None
    if score >= 3.0 and grounding in ("VERIFIED", "PARTIAL"):
        decided = STATUS_CONFIRMED
    elif score <= -3.0 and not well_evidenced:
        decided = STATUS_FALSE_POSITIVE

    # A confirmation with no grounding is never allowed, whatever the score.
    if decided == STATUS_CONFIRMED and ungrounded:
        decided = None
        reasons.append("withheld: cannot confirm without grounding")
    # A dismissal of a well-evidenced finding is never allowed.
    if decided == STATUS_FALSE_POSITIVE and well_evidenced:
        decided = None
        reasons.append("withheld: evidence too strong to dismiss")

    # Confidence: how far the score sits from the undecided middle, tempered when
    # the reviewer itself was unsure or disagreed on severity.
    magnitude = min(1.0, abs(score) / 5.0)
    if reviewer_conf == "low":
        magnitude *= 0.7
    elif reviewer_conf == "medium":
        magnitude *= 0.85
    if disagree:
        magnitude *= 0.85
    confidence = round(magnitude, 2)

    if decided is None:
        status = STATUS_NEEDS_REVIEW
        lean = "leans valid" if score > 0.5 else "leans false-positive" if score < -0.5 else "genuinely ambiguous"
        rationale = f"Held for review ({lean}): " + ("; ".join(reasons) if reasons else "signals inconclusive") + "."
        # A held finding's confidence is confidence in the *ambiguity*, so report
        # it low rather than borrowing the score magnitude.
        confidence = round(min(confidence, 0.4), 2)
        label = "Low"
    else:
        status = decided
        rationale = ("Confirmed" if decided == STATUS_CONFIRMED else "Marked false positive") + ": " + "; ".join(reasons) + "."
        label = "High" if confidence >= 0.75 else "Medium" if confidence >= 0.5 else "Low"

    return {
        "resolved_status": status,
        "confidence": confidence,
        "confidence_label": label,
        "rationale": rationale,
        "signals": signals,
        "auto_set": _auto_status_enabled(),
    }


def apply_resolution(finding, review=None):
    """Attach the resolution to a finding and, when enabled and confident, set the
    status. Never overwrites a status a human or a retest already assigned."""
    res = resolve_verdict(finding, review)
    finding["_verdict"] = res
    if not res["auto_set"]:
        return finding
    current = _norm(finding.get("status"))
    if current in PROTECTED_STATUSES:
        res["auto_set"] = False
        return finding
    if res["resolved_status"] != STATUS_NEEDS_REVIEW:
        finding["status"] = res["resolved_status"]
    return finding
