"""Retest campaigns.

Per-finding retest data already existed. What did not was any notion of a retest as
an activity: a tester finishing a remediation round had to work finding by finding
and remember what they had covered.

A campaign is derived from the findings rather than stored, so it cannot drift out
of step with them. These tests pin the two numbers a tester and a client each ask
for -- how much of the round is covered, and what actually got fixed.
"""
import json

import pytest

import retest


def f(fid, title, severity, status, history=None):
    return {
        "id": fid, "title": title, "severity": severity, "status": status,
        "retest_history": json.dumps(history or []),
    }


ROUND_ONE = [
    f(1, "SQL injection", "Critical", "Retest Passed",
      [{"round": 1, "retest_status": "Fixed", "date": "2026-03-02", "retester": "S."}]),
    f(2, "Reflected XSS", "High", "Retest Failed",
      [{"round": 1, "retest_status": "Open", "date": "2026-03-02", "retester": "S."}]),
    f(3, "Missing CSP", "Low", "Confirmed"),
    f(4, "IDOR", "High", "Retest Failed",
      [{"round": 1, "retest_status": "Regressed", "date": "2026-03-02", "retester": "S."}]),
    f(5, "Verbose error", "Medium", "False Positive"),
    f(6, "Open redirect", "Medium", "Confirmed"),
]


class TestCandidates:
    def test_closed_findings_are_not_retested(self):
        """Retesting a false positive or an accepted risk wastes the tester's time
        and muddies the round's outcome."""
        titles = [c["title"] for c in retest.candidates(ROUND_ONE)]
        assert "Verbose error" not in titles

    def test_open_findings_are_included(self):
        titles = [c["title"] for c in retest.candidates(ROUND_ONE)]
        assert "Missing CSP" in titles and "Reflected XSS" in titles

    def test_ordered_by_severity(self):
        sevs = [c["severity"] for c in retest.candidates(ROUND_ONE)]
        assert sevs == sorted(sevs, key=lambda s: ["Critical", "High", "Medium", "Low", "Informational"].index(s))

    def test_empty_input_does_not_raise(self):
        assert retest.candidates([]) == []
        assert retest.candidates(None) == []


class TestCampaign:
    def test_reports_coverage_of_the_round(self):
        c = retest.campaign(ROUND_ONE)
        assert c["covered"] == 3
        assert c["total"] == 5
        assert c["coverage_pct"] == 60

    def test_tallies_outcomes(self):
        c = retest.campaign(ROUND_ONE)
        assert c["tally"]["Fixed"] == 1
        assert c["tally"]["Open"] == 1
        assert c["tally"]["Regressed"] == 1

    def test_lists_what_is_still_outstanding(self):
        c = retest.campaign(ROUND_ONE)
        titles = {o["title"] for o in c["outstanding"]}
        assert titles == {"Missing CSP", "Open redirect"}

    def test_rounds_are_inferred_from_the_findings(self):
        rounds = retest.rounds_present(ROUND_ONE)
        assert rounds[0]["round"] == 1
        assert rounds[0]["count"] == 3
        assert rounds[0]["testers"] == ["S."]

    def test_a_project_with_no_retests_does_not_raise(self):
        c = retest.campaign([f(1, "x", "Low", "Confirmed")])
        assert c["covered"] == 0 and c["coverage_pct"] == 0

    def test_malformed_history_is_survived(self):
        bad = [{"id": 1, "title": "x", "severity": "Low", "status": "Confirmed",
                "retest_history": "not json"}]
        c = retest.campaign(bad)
        assert c["covered"] == 0


class TestDeltaReport:
    def test_separates_regressions_from_still_open(self):
        """A regression is the outcome that matters most, and a single remediation
        percentage would hide it."""
        d = retest.delta_report(ROUND_ONE)
        assert [x["title"] for x in d["regressed"]] == ["IDOR"]
        assert [x["title"] for x in d["still_open"]] == ["Reflected XSS"]

    def test_remediation_is_measured_against_what_was_tested(self):
        """Measuring against every finding would make an incomplete round look like
        a poor remediation rate."""
        d = retest.delta_report(ROUND_ONE)
        assert d["tested_count"] == 3
        assert d["remediation_pct"] == 33

    def test_an_untested_round_reports_zero_rather_than_dividing_by_zero(self):
        d = retest.delta_report([f(1, "x", "Low", "Confirmed")])
        assert d["remediation_pct"] == 0
        assert d["tested_count"] == 0
