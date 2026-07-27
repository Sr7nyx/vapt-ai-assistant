# Evaluation

A labelled set and harness for the deterministic verdict engine. It quantifies
the project's central claim: that combining reviewer signals under a transparent
rule reduces false positives without dismissing real findings.

```bash
cd eval
python run_eval.py             # table
python run_eval.py --md report.md
python run_eval.py --json
```

## What is measured, and what is not

The engine takes the skeptical reviewer's signals (evidence grounding,
exploitability, false-positive risk, verdict, confidence) and resolves them into
a status: **Confirmed**, **False Positive**, or **Need Review**. This harness
feeds each labelled case's recorded signals to the engine and scores the
decisions against ground truth.

So it measures the **deterministic decision layer**: given a set of signals, does
the engine reach the right, safe conclusion? It runs offline and is fully
reproducible, which is why it can gate CI.

It does **not** measure the language model's quality at producing those signals
in the first place. That is a separate question that needs live runs against
labelled raw evidence, is non-deterministic, and depends on the chosen model. A
live evaluation would call the real analyzer on each case's raw input, capture
the signals it produces, and feed those to the same scoring code below. The
harness is structured to make that substitution straightforward, but the shipped,
reproducible metric is the decision-layer one.

## Metrics

All reported with **95% Wilson score intervals**, because the set is small and a
point estimate alone would overstate precision.

| Metric | Meaning |
| --- | --- |
| Precision (decided) | Of findings the engine marked Confirmed, the share that are truly positive |
| Recall (decided positives) | Of the true positives it decided on, the share it confirmed |
| Recall (all true positives) | Of every true positive, the share it confirmed rather than holding |
| Coverage | The share of findings the engine was willing to decide at all |
| False-positive reduction | Of labelled false positives, the share the engine kept out of a confirmed report |
| Evidence-grounding accuracy | The share where the engine's grounding matches ground truth |
| Dangerous-dismissal rate | The share of true positives wrongly marked false positive |

Coverage matters as much as precision. An engine can reach perfect precision by
deciding almost nothing, so the two are reported together: the design goal is
high precision at reasonable coverage, holding the genuinely ambiguous cases for
a human rather than guessing. **Dangerous-dismissal rate is the one that must
stay at zero** -- confirming a false positive wastes effort, but dismissing a
real vulnerability is the error a security tool cannot make, so the harness exits
non-zero if it is ever above zero.

## The dataset

`dataset.json` holds hand-labelled synthetic cases spanning clear true positives
(SQLi with differential and timing evidence, proven IDOR, SSRF returning
metadata), clear false positives (frameable static pages, host-header reflection
on a CDN asset, missing headers on static assets), genuinely ambiguous findings
(open redirect, verbose errors, wildcard CORS with no proven impact), a
prompt-injection case, an unreviewed case, and -- importantly -- a well-evidenced
true positive that the reviewer wrongly doubts, to confirm the engine does not
follow a nervous reviewer into dismissing a grounded finding.

Every scenario is synthetic (RFC 2606 domains, RFC 5737 addresses). These numbers
illustrate the methodology on a small set; they are not a published benchmark.
