"""Deterministic verdict resolution.

Confidence here must be earned from signals agreeing under a rule, never
manufactured. The tests that matter most are the asymmetric guardrails: a
well-evidenced finding must never be auto-dismissed, and an ungrounded one must
never be auto-confirmed, because in security work those two errors do not cost
the same.
"""
import pytest

import verdict_engine as ve


def review(**kw):
    base = dict(
        reviewed=True, grounding="", exploitability="", false_positive_risk="",
        confidence="High", verdict="", injection=False, severity_disagreement=False,
    )
    base.update(kw)
    return base


class TestConfidentConfirmation:
    def test_verified_demonstrated_low_fp_confirms(self):
        r = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated by differential response",
            false_positive_risk="Low", verdict="Confirmed"))
        assert r["resolved_status"] == ve.STATUS_CONFIRMED
        assert r["confidence_label"] == "High"

    def test_partial_grounding_can_confirm_when_evidence_strong(self):
        r = ve.resolve_verdict({}, review(
            grounding="PARTIAL", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed"))
        assert r["resolved_status"] == ve.STATUS_CONFIRMED


class TestConfidentRejection:
    def test_unverified_theoretical_high_fp_is_false_positive(self):
        r = ve.resolve_verdict({}, review(
            grounding="UNVERIFIED", exploitability="No demonstrated impact, static page",
            false_positive_risk="High", verdict="Likely False Positive"))
        assert r["resolved_status"] == ve.STATUS_FALSE_POSITIVE


class TestAsymmetricGuardrails:
    def test_never_confirms_without_grounding(self):
        """Even a maximal score cannot confirm a finding with no grounding: that is
        the core claim -- no finding without evidence."""
        r = ve.resolve_verdict({}, review(
            grounding="", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed"))
        assert r["resolved_status"] != ve.STATUS_CONFIRMED

    def test_never_dismisses_a_well_evidenced_finding(self):
        """VERIFIED grounding with demonstrated exploitability must never be
        auto-marked false positive, even when the reviewer loses its nerve."""
        r = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated cross-account read",
            false_positive_risk="High", confidence="Low", verdict="Likely False Positive"))
        assert r["resolved_status"] != ve.STATUS_FALSE_POSITIVE
        assert r["resolved_status"] == ve.STATUS_NEEDS_REVIEW

    def test_conflicting_signals_hold_for_review(self):
        r = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="High",
            verdict="Likely False Positive"))
        assert r["resolved_status"] == ve.STATUS_NEEDS_REVIEW


class TestInjectionAndUnreviewed:
    def test_injection_forces_review_regardless_of_other_signals(self):
        r = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed", injection=True))
        assert r["resolved_status"] == ve.STATUS_NEEDS_REVIEW
        assert "injection" in r["rationale"].lower()

    def test_unreviewed_stays_for_review_with_zero_confidence(self):
        r = ve.resolve_verdict({}, review(reviewed=False))
        assert r["resolved_status"] == ve.STATUS_NEEDS_REVIEW
        assert r["confidence"] == 0.0


class TestAmbiguityIsHeld:
    def test_middling_signals_are_not_forced(self):
        r = ve.resolve_verdict({}, review(
            grounding="PARTIAL", exploitability="Plausible", false_positive_risk="Medium",
            verdict="Needs More Evidence"))
        assert r["resolved_status"] == ve.STATUS_NEEDS_REVIEW
        assert r["confidence"] <= 0.4

    def test_held_findings_report_low_confidence(self):
        r = ve.resolve_verdict({}, review(
            grounding="PARTIAL", exploitability="Plausible", false_positive_risk="Medium",
            verdict="Needs More Evidence"))
        assert r["confidence_label"] == "Low"


class TestConfidenceIsTempered:
    def test_low_reviewer_confidence_lowers_score(self):
        high = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed", confidence="High"))
        low = ve.resolve_verdict({}, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed", confidence="Low"))
        assert low["confidence"] <= high["confidence"]


class TestApplyResolution:
    def test_sets_status_when_confident(self, monkeypatch):
        monkeypatch.setenv("VAPT_AUTO_STATUS", "1")
        f = {"status": "Need Review"}
        ve.apply_resolution(f, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed"))
        assert f["status"] == "Confirmed"
        assert f["_verdict"]["resolved_status"] == "Confirmed"

    def test_does_not_touch_a_human_decision(self, monkeypatch):
        monkeypatch.setenv("VAPT_AUTO_STATUS", "1")
        for protected in ("Accepted Risk", "Fixed", "Retest Passed"):
            f = {"status": protected}
            ve.apply_resolution(f, review(
                grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
                verdict="Confirmed"))
            assert f["status"] == protected

    def test_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("VAPT_AUTO_STATUS", "0")
        f = {"status": "Need Review"}
        ve.apply_resolution(f, review(
            grounding="VERIFIED", exploitability="Demonstrated", false_positive_risk="Low",
            verdict="Confirmed"))
        assert f["status"] == "Need Review"          # unchanged
        assert f["_verdict"]["resolved_status"] == "Confirmed"  # still computed

    def test_held_finding_does_not_change_status(self, monkeypatch):
        monkeypatch.setenv("VAPT_AUTO_STATUS", "1")
        f = {"status": "Need Review"}
        ve.apply_resolution(f, review(
            grounding="PARTIAL", exploitability="Plausible", false_positive_risk="Medium",
            verdict="Needs More Evidence"))
        assert f["status"] == "Need Review"
