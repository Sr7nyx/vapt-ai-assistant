"""Retest campaigns: verifying a round of fixes as one piece of work.

Per-finding retest already existed -- status, round, evidence, history. What did
not was any notion of a retest as an ACTIVITY. A tester finishing a remediation
round had to open findings one at a time and remember which they had covered,
and there was no way to say "these fourteen were retested on the ninth" or to
produce the delta a client actually asks for.

A campaign is deliberately not a table. It is derived from the retest data already
on each finding, which means it cannot drift out of step with the findings it
describes and there is no second source of truth to reconcile. The cost is that a
campaign has no independent lifecycle; that is the right trade here, because the
findings are the record and a campaign is a view of them.
"""
import json
from datetime import date, datetime

# What is worth retesting: anything an earlier round left open.
RETESTABLE_STATUSES = {"confirmed", "retest failed", "need review", "draft", ""}

# Outcomes a retest can record, and what each means for the finding.
OUTCOMES = {
    "Fixed": "The issue is no longer present.",
    "Partially Fixed": "The issue is reduced but not resolved.",
    "Open": "The issue is unchanged.",
    "Regressed": "The issue had been fixed and has returned.",
    "Accepted Risk": "The client has accepted the risk rather than remediating.",
}

CLOSED = {"fixed", "retest passed", "false positive", "accepted risk"}


def _rounds(finding):
    try:
        return json.loads(finding.get("retest_history") or "[]")
    except Exception:
        return []


def _iso(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value) if value else ""


def candidates(findings):
    """Findings a retest round should cover, most severe first.

    Excludes anything already closed: retesting a false positive or an accepted
    risk wastes the tester's time and muddies the round's outcome.
    """
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    out = [
        f for f in (findings or [])
        if str(f.get("status") or "").strip().lower() not in CLOSED
    ]
    out.sort(key=lambda f: (order.get(str(f.get("severity")), 9), str(f.get("title") or "")))
    return out


def rounds_present(findings):
    """Every retest round observed across a set of findings, newest first.

    Rounds are inferred rather than stored, so a round exists exactly when some
    finding was retested in it.
    """
    seen = {}
    for f in findings or []:
        for entry in _rounds(f):
            n = entry.get("round")
            if not n:
                continue
            info = seen.setdefault(n, {"round": n, "count": 0, "dates": set(), "testers": set()})
            info["count"] += 1
            if entry.get("date"):
                info["dates"].add(str(entry["date"])[:10])
            if entry.get("retester"):
                info["testers"].add(str(entry["retester"]))
    out = []
    for n in sorted(seen, reverse=True):
        info = seen[n]
        out.append({
            "round": n,
            "count": info["count"],
            "first_date": min(info["dates"]) if info["dates"] else "",
            "last_date": max(info["dates"]) if info["dates"] else "",
            "testers": sorted(info["testers"]),
        })
    return out


def campaign(findings, round_number=None):
    """The state of one retest round.

    With no round given, reports the most recent. Returns the outcome tally, the
    findings still outstanding, and how much of the round has been covered --
    which is the number a tester actually needs mid-round.
    """
    findings = list(findings or [])
    known = rounds_present(findings)
    if round_number is None:
        round_number = known[0]["round"] if known else 1

    tested, outstanding = [], []
    tally = {k: 0 for k in OUTCOMES}

    for f in findings:
        if str(f.get("status") or "").strip().lower() in CLOSED and not _rounds(f):
            # Closed without ever being retested: not part of this round's work.
            continue
        entry = next((e for e in _rounds(f) if e.get("round") == round_number), None)
        if entry:
            outcome = entry.get("retest_status") or entry.get("status") or ""
            if outcome in tally:
                tally[outcome] += 1
            tested.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "outcome": outcome,
                "date": _iso(entry.get("date")),
                "retester": entry.get("retester") or "",
                "note": entry.get("note") or "",
            })
        elif str(f.get("status") or "").strip().lower() not in CLOSED:
            outstanding.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "status": f.get("status"),
            })

    total = len(tested) + len(outstanding)
    return {
        "round": round_number,
        "known_rounds": known,
        "tested": tested,
        "outstanding": outstanding,
        "tally": tally,
        "total": total,
        "covered": len(tested),
        # Whole-number percent: a progress figure with decimals implies a
        # precision that a count of findings does not have.
        "coverage_pct": round(len(tested) / total * 100) if total else 0,
    }


def delta_report(findings, round_number=None):
    """What changed in a round, as a client would ask it.

    Deliberately separates "fixed" from "still open" from "regressed", because a
    regression is the outcome that matters most and a single remediation
    percentage would hide it.
    """
    state = campaign(findings, round_number)
    by_outcome = {}
    for t in state["tested"]:
        by_outcome.setdefault(t["outcome"] or "Untested", []).append(t)

    fixed = by_outcome.get("Fixed", [])
    regressed = by_outcome.get("Regressed", [])
    still_open = by_outcome.get("Open", []) + by_outcome.get("Partially Fixed", [])
    accepted = by_outcome.get("Accepted Risk", [])

    return {
        "round": state["round"],
        "coverage_pct": state["coverage_pct"],
        "fixed": fixed,
        "still_open": still_open,
        "regressed": regressed,
        "accepted": accepted,
        "outstanding": state["outstanding"],
        # Of what was actually retested. Reporting against the whole finding set
        # would let an untested round look like a low remediation rate.
        "remediation_pct": round(len(fixed) / len(state["tested"]) * 100) if state["tested"] else 0,
        "tested_count": len(state["tested"]),
    }
