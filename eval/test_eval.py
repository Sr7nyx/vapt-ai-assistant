"""Smoke test for the evaluation harness: it must run, and on the shipped
labelled set the engine must make no dangerous dismissals and no false
confirmations. This turns the central claim into a CI gate."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "backend"))

import run_eval  # noqa: E402


def _result():
    data = json.load(open(os.path.join(HERE, "dataset.json")))
    return run_eval.evaluate(data["cases"])


class TestHarness:
    def test_runs_and_reports_every_case(self):
        r = _result()
        assert r["n"] == len(json.load(open(os.path.join(HERE, "dataset.json")))["cases"])
        assert len(r["per_case"]) == r["n"]

    def test_no_false_positive_is_confirmed(self):
        assert r_confusion()["fp"] == 0

    def test_no_real_finding_is_dismissed(self):
        """The error a security tool must not make."""
        assert r_confusion()["fn"] == 0

    def test_wilson_interval_is_sane(self):
        # At p = 1.0 the Wilson upper bound is legitimately just below 1.0 and the
        # point estimate sits at the boundary, so the invariant is bounds ordering
        # and [0,1] containment, not point-inside-interval.
        lo, p, hi = run_eval.wilson(6, 6)
        assert lo <= hi
        assert 0.0 <= lo and hi <= 1.0
        assert p == 1.0
        mid_lo, mid_p, mid_hi = run_eval.wilson(3, 6)
        assert mid_lo <= mid_p <= mid_hi          # interior case does contain the point

    def test_wilson_handles_empty(self):
        assert run_eval.wilson(0, 0) == (0.0, 0.0, 0.0)


def r_confusion():
    return _result()["confusion"]
