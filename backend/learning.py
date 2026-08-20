"""What the system learns from being corrected.

Nothing here trains a model. Fine-tuning needs thousands of labelled examples, a
GPU budget and a hosting story, and it would trade a maintained frontier model for
a worse one you own forever. A wrapper that claims to "learn" without that is
describing a lookup table, and saying so plainly is better than implying otherwise.

What CAN accumulate is everything around the model:

  CALIBRATION  Every verdict a human overturns is a labelled example, already
               recorded in finding_events with actor and rationale. Nothing read it
               back. Comparing what the engine claimed against what the operator
               decided says whether its confidence numbers mean anything.

  PRIORS       A finding class dismissed as a false positive eleven times should
               not cost a review call on the twelfth. Identity comes from
               finding_identity.fingerprint(), which already ignores severity and
               volatile URL parts.

Both read data that is already stored. Neither changes a model, and neither hides
a finding: a prior lowers cost and raises a flag, it never suppresses.
"""
import re
from collections import defaultdict

import finding_identity


def class_key(finding):
    """Identity for a PRIOR, which is not the same as identity for a scan diff.

    finding_identity.fingerprint() includes the exact path, which is right when
    asking "is this the same finding as last month" -- /static/a.js and
    /static/b.js genuinely are different findings.

    It is wrong for a prior. An operator who dismissed "missing X-Frame-Options on
    a static asset" four times dismissed a CLASS, not four files, and keying on the
    path means the fifth file learns nothing from the first four.

    So a prior keys on title and CWE, plus the parameter when there is one, and
    drops the path entirely. Coarser on purpose: it is deciding whether to spend a
    review call, not whether two findings are the same.
    """
    f = finding or {}
    title = re.sub(r"[^a-z0-9 ]+", "", str(f.get("title") or "").lower())
    title = re.sub(r"\s+", " ", title).strip()
    cwe = re.sub(r"[^0-9]", "", str(f.get("cwe") or ""))
    param = str(f.get("parameter") or "").strip().lower()
    return "|".join([title, cwe, param])

# A correction is a human changing status or severity. Automatic changes are
# excluded: the engine agreeing with itself is not evidence of anything.
HUMAN_ACTORS_EXCLUDED = {"engine", "system", "pipeline", ""}

DISMISSED = {"false positive", "accepted risk"}
UPHELD = {"confirmed", "retest failed", "fixed", "retest passed"}


def _norm(v):
    return str(v or "").strip().lower()


def is_correction(event):
    """Whether an event is a human overturning a decision.

    The distinction matters: if automatic status changes counted, the engine would
    be measuring its own agreement with itself and always look well calibrated.
    """
    if _norm(event.get("action")) not in ("update", "edit", "retest"):
        return False
    if _norm(event.get("field")) not in ("status", "severity"):
        return False
    actor = _norm(event.get("actor"))
    if actor in HUMAN_ACTORS_EXCLUDED or "engine" in actor:
        return False
    return _norm(event.get("old_value")) != _norm(event.get("new_value"))


def calibration(findings, events):
    """Does a stated confidence mean what it says?

    Buckets findings by the confidence the verdict engine assigned, then measures
    how often each bucket was later overturned. A bucket claiming 0.8 whose
    findings are overturned 40% of the time is not 0.8, and this is the evidence
    to say so.

    Reported with a sample count, because a bucket holding three findings tells
    you nothing and presenting it as a rate would be worse than saying nothing.
    """
    overturned = set()
    for e in events or []:
        if is_correction(e):
            overturned.add(e.get("finding_id"))

    buckets = defaultdict(lambda: {"n": 0, "overturned": 0})
    for f in findings or []:
        verdict = (f.get("_verdict") or {})
        conf = verdict.get("confidence")
        if conf is None:
            continue
        # Ten-point buckets: finer than that and every bucket is too small to read.
        key = round(min(0.99, max(0.0, float(conf))) * 10) / 10
        b = buckets[key]
        b["n"] += 1
        if f.get("id") in overturned:
            b["overturned"] += 1

    rows = []
    for claimed in sorted(buckets):
        b = buckets[claimed]
        held = 1 - b["overturned"] / b["n"] if b["n"] else 0
        rows.append({
            "claimed": claimed,
            "observed": round(held, 3),
            "n": b["n"],
            "overturned": b["overturned"],
            # Below this a rate is noise. Stated rather than hidden, so a thin
            # bucket is visibly thin instead of quietly misleading.
            "reliable": b["n"] >= 8,
            "gap": round(held - claimed, 3),
        })

    reliable = [r for r in rows if r["reliable"]]
    # Brier-style error over the reliable buckets only: the mean squared distance
    # between what was claimed and what happened.
    error = (
        sum((r["observed"] - r["claimed"]) ** 2 * r["n"] for r in reliable)
        / sum(r["n"] for r in reliable)
    ) if reliable else None

    return {
        "buckets": rows,
        "samples": sum(r["n"] for r in rows),
        "corrections": len(overturned),
        "calibration_error": round(error, 4) if error is not None else None,
        # A single honest sentence, or an admission that there is not enough data.
        "verdict": _calibration_verdict(reliable, error),
    }


def _calibration_verdict(reliable, error):
    if not reliable:
        return ("Not enough adjudicated findings yet. A confidence figure cannot be "
                "checked against outcomes until roughly eight findings share a bucket.")
    worst = max(reliable, key=lambda r: abs(r["gap"]))
    if error is not None and error < 0.02:
        return ("Confidence tracks outcomes closely. Findings marked at a given "
                "confidence are upheld at about that rate.")
    direction = "overconfident" if worst["gap"] < 0 else "underconfident"
    return (
        f"The engine is {direction} around {worst['claimed']:.1f}: findings marked at "
        f"that confidence were upheld {worst['observed']:.0%} of the time across "
        f"{worst['n']} cases."
    )


def priors(findings, events, min_dismissals=3):
    """Finding classes this operator has repeatedly dismissed.

    A class marked false positive several times is unlikely to be real the next
    time, and paying a review call to be told so again is waste. This returns the
    evidence for pre-flagging, not an instruction to hide anything.

    Only DISMISSALS accumulate. Confirmations are counted for context but never
    used to auto-confirm: being wrong towards "this is probably not real" costs a
    second look, and being wrong towards "this is real" puts a false finding in a
    client report.
    """
    by_id = {f.get("id"): f for f in (findings or []) if f.get("id") is not None}

    tally = defaultdict(lambda: {"dismissed": 0, "upheld": 0, "titles": set(), "last": ""})
    for e in events or []:
        if not is_correction(e) or _norm(e.get("field")) != "status":
            continue
        f = by_id.get(e.get("finding_id"))
        if not f:
            continue
        fp = class_key(f)
        if not fp.strip("|"):
            continue
        new = _norm(e.get("new_value"))
        entry = tally[fp]
        if new in DISMISSED:
            entry["dismissed"] += 1
        elif new in UPHELD:
            entry["upheld"] += 1
        else:
            continue
        entry["titles"].add(str(f.get("title") or ""))
        created = e.get("created_at")
        entry["last"] = created.isoformat() if hasattr(created, "isoformat") else str(created or "")

    out = []
    for fp, t in tally.items():
        total = t["dismissed"] + t["upheld"]
        if t["dismissed"] < min_dismissals or total == 0:
            continue
        rate = t["dismissed"] / total
        # A class dismissed three times but upheld twice is not a reliable prior --
        # it is a class that needs judgement, which is the opposite of a shortcut.
        if rate < 0.8:
            continue
        out.append({
            "fingerprint": fp,
            "title": sorted(t["titles"])[0] if t["titles"] else "",
            "dismissed": t["dismissed"],
            "upheld": t["upheld"],
            "rate": round(rate, 3),
            "last_seen": t["last"],
        })
    out.sort(key=lambda r: (-r["dismissed"], r["title"]))
    return out


def apply_priors(candidates, prior_rows):
    """Annotate incoming candidates that match a learned prior.

    Adds `_prior` and nothing else. The finding still appears, still goes through
    triage, still reaches the reviewer if the operator wants it to -- what changes
    is that it arrives already carrying its own history, and the caller may choose
    to skip an expensive review for it.

    Suppressing would be the obvious next step and the wrong one: an operator who
    dismissed something eleven times in one context may still need it flagged in a
    new one, and a tool that silently drops findings is not one you can defend.
    """
    index = {r["fingerprint"]: r for r in (prior_rows or [])}
    hits = 0
    out = []
    for c in candidates or []:
        annotated = dict(c)
        row = index.get(class_key(c))
        if row:
            hits += 1
            annotated["_prior"] = {
                "state": "previously_dismissed",
                "dismissed": row["dismissed"],
                "upheld": row["upheld"],
                "rate": row["rate"],
                "note": (
                    f"You have dismissed this class {row['dismissed']} time"
                    f"{'' if row['dismissed'] == 1 else 's'} before"
                    + (f" and upheld it {row['upheld']}." if row["upheld"] else ".")
                ),
            }
        out.append(annotated)
    return out, hits


def review_savings(candidates):
    """How many review calls a run can skip because of priors.

    Reported rather than assumed: the point of the feature is cost, so the number
    should be visible instead of implied.
    """
    skippable = [c for c in (candidates or []) if (c.get("_prior") or {}).get("state")]
    return {
        "total": len(candidates or []),
        "skippable": len(skippable),
        "share": round(len(skippable) / len(candidates), 3) if candidates else 0.0,
    }
