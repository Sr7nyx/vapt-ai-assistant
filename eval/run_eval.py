#!/usr/bin/env python3
"""Evaluate the deterministic verdict engine against a labelled set.

Reports, with 95% Wilson score intervals (small-sample honest):
  - Precision and recall on decided findings (Confirmed vs False Positive)
  - Coverage: the share of findings the engine was willing to decide
  - False-positive reduction vs shipping first-pass findings unreviewed
  - Evidence-grounding accuracy

Default mode is offline and deterministic: it feeds each case's recorded reviewer
signals to the engine, so it measures the DECISION LAYER and runs anywhere,
including CI. It does not measure the LLM's signal-production quality; that needs
live runs against labelled raw evidence and is out of scope for a reproducible
metric. A --live hook is described in the README.

Usage:
  python run_eval.py                 # table to stdout
  python run_eval.py --json          # machine-readable
  python run_eval.py --md report.md  # write a markdown report
"""
import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
import verdict_engine  # noqa: E402


def wilson(successes, n, z=1.96):
    """95% Wilson score interval for a proportion. Returns (low, point, high)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - margin), p, min(1.0, centre + margin))


def evaluate(cases):
    tp = fp = tn = fn = 0          # on decided items; positive = Confirmed
    undecided_pos = undecided_neg = 0
    grounding_correct = grounding_total = 0

    per_case = []
    for c in cases:
        review = c.get("review", {})
        res = verdict_engine.resolve_verdict({"additional_remarks": ""}, review)
        status = res["resolved_status"]
        truth_positive = c["truth"] == "true_positive"

        # Grounding accuracy: engine's normalized grounding vs ground truth.
        eng_grounding = res["signals"]["grounding"].upper()
        truth_grounding = c.get("truth_grounding", "").upper()
        if truth_grounding:
            grounding_total += 1
            if eng_grounding == truth_grounding:
                grounding_correct += 1

        if status == verdict_engine.STATUS_CONFIRMED:
            if truth_positive:
                tp += 1; outcome = "TP"
            else:
                fp += 1; outcome = "FP (confirmed a false positive)"
        elif status == verdict_engine.STATUS_FALSE_POSITIVE:
            if truth_positive:
                fn += 1; outcome = "FN (dismissed a real finding)"
            else:
                tn += 1; outcome = "TN"
        else:
            if truth_positive:
                undecided_pos += 1
            else:
                undecided_neg += 1
            outcome = "held for review"

        per_case.append({
            "id": c["id"], "truth": c["truth"], "status": status,
            "confidence": res["confidence"], "outcome": outcome,
        })

    decided = tp + fp + tn + fn
    total = decided + undecided_pos + undecided_neg
    positives_total = tp + fn + undecided_pos

    precision = wilson(tp, tp + fp)
    recall = wilson(tp, tp + fn)               # recall among *decided* positives
    recall_all = wilson(tp, positives_total)   # recall against all true positives
    coverage = wilson(decided, total)
    grounding_acc = wilson(grounding_correct, grounding_total)

    # False-positive reduction: without a review layer, every first-pass finding
    # ships, so all labelled false positives would reach the report. The engine
    # prevents those it does not confirm.
    labelled_fp = sum(1 for c in cases if c["truth"] == "false_positive")
    fp_confirmed = fp
    fp_prevented = labelled_fp - fp_confirmed
    fp_reduction = wilson(fp_prevented, labelled_fp)

    # A dangerous-error rate worth stating plainly: real findings wrongly dismissed.
    danger = wilson(fn, positives_total)

    return {
        "n": total, "decided": decided,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                      "undecided_positive": undecided_pos, "undecided_negative": undecided_neg},
        "precision": precision,
        "recall_decided": recall,
        "recall_overall": recall_all,
        "coverage": coverage,
        "false_positive_reduction": fp_reduction,
        "grounding_accuracy": grounding_acc,
        "dangerous_dismissal_rate": danger,
        "per_case": per_case,
    }


def _pct(triple):
    lo, p, hi = triple
    return f"{p*100:5.1f}%  [{lo*100:4.1f}, {hi*100:4.1f}]"


def render_text(r):
    c = r["confusion"]
    lines = [
        "Verdict engine evaluation (deterministic decision layer)",
        "=" * 60,
        f"Cases: {r['n']}   Decided: {r['decided']}   Held for review: {r['n']-r['decided']}",
        "",
        f"  Confusion (decided items, positive = Confirmed)",
        f"    TP {c['tp']:2}   FP {c['fp']:2}   TN {c['tn']:2}   FN {c['fn']:2}",
        f"    undecided: {c['undecided_positive']} real, {c['undecided_negative']} false",
        "",
        f"  Precision (of Confirmed, share truly positive)   {_pct(r['precision'])}",
        f"  Recall on decided positives                      {_pct(r['recall_decided'])}",
        f"  Recall over all true positives                   {_pct(r['recall_overall'])}",
        f"  Coverage (share the engine decided)              {_pct(r['coverage'])}",
        f"  False-positive reduction vs no review            {_pct(r['false_positive_reduction'])}",
        f"  Evidence-grounding accuracy                      {_pct(r['grounding_accuracy'])}",
        f"  Dangerous-dismissal rate (real marked false)     {_pct(r['dangerous_dismissal_rate'])}",
        "",
        "Intervals are 95% Wilson score. Small hand-labelled synthetic set:",
        "an illustration of methodology, not a published benchmark.",
    ]
    return "\n".join(lines)


def render_md(r):
    c = r["confusion"]
    def row(name, t): lo, p, hi = t; return f"| {name} | {p*100:.1f}% | {lo*100:.1f}% - {hi*100:.1f}% |"
    return "\n".join([
        "# Verdict engine evaluation",
        "",
        f"Deterministic decision layer over a labelled synthetic set of **{r['n']}** findings.",
        "",
        f"- Decided: **{r['decided']}** | Held for review: **{r['n']-r['decided']}**",
        f"- Confusion on decided items (positive = Confirmed): TP {c['tp']}, FP {c['fp']}, TN {c['tn']}, FN {c['fn']}",
        "",
        "| Metric | Point | 95% Wilson interval |",
        "| --- | --- | --- |",
        row("Precision (decided)", r["precision"]),
        row("Recall (decided positives)", r["recall_decided"]),
        row("Recall (all true positives)", r["recall_overall"]),
        row("Coverage", r["coverage"]),
        row("False-positive reduction", r["false_positive_reduction"]),
        row("Evidence-grounding accuracy", r["grounding_accuracy"]),
        row("Dangerous-dismissal rate", r["dangerous_dismissal_rate"]),
        "",
        "> Intervals are 95% Wilson score. This is a small hand-labelled synthetic "
        "set illustrating the evaluation methodology, not a published benchmark. "
        "It measures the deterministic decision layer given reviewer signals, not "
        "the language model's signal-production quality.",
    ])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(os.path.dirname(__file__), "dataset.json"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--md", metavar="PATH")
    args = ap.parse_args()

    data = json.load(open(args.dataset))
    r = evaluate(data["cases"])

    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(render_text(r))
    if args.md:
        open(args.md, "w").write(render_md(r))
        print(f"\nWrote {args.md}")
    # Non-zero exit if the engine ever dismissed a real finding: that is the error
    # a security tool must not make, and CI should notice.
    return 1 if r["confusion"]["fn"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
