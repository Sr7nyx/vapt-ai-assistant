"""Verification-signal parsing.

These signals are what stop an unverified or contradicted finding from reaching a
report looking like a fact, so the parsing has to be exact.
"""
import pytest

import qa_utils


def remarks(text):
    return {"additional_remarks": text}


class TestGrounding:
    def test_unverified_raises_a_warning(self):
        qa = qa_utils.summarize_qa(remarks('Evidence grounding: UNVERIFIED'))
        assert qa["grounding"] == "UNVERIFIED"
        assert qa["warnings"]
        assert qa["level"] == "danger"

    def test_verified_produces_no_warning(self):
        qa = qa_utils.summarize_qa(remarks("Evidence grounding: VERIFIED"))
        assert qa["grounding"] == "VERIFIED"
        assert qa["warnings"] == []

    def test_partial_is_a_caution_not_a_warning(self):
        qa = qa_utils.summarize_qa(remarks("Evidence grounding: PARTIAL"))
        assert qa["grounding"] == "PARTIAL"
        assert qa["warnings"] == []
        assert qa["cautions"]

    def test_no_evidence_flagged(self):
        qa = qa_utils.summarize_qa(remarks("Evidence grounding: NO EVIDENCE"))
        assert qa["grounding"] == "NO EVIDENCE"


class TestOtherSignals:
    def test_severity_mismatch_warns(self):
        qa = qa_utils.summarize_qa(remarks("SEVERITY MISMATCH: model said Critical, CVSS says Low"))
        assert qa["severity_mismatch"] is True
        assert qa["warnings"]

    def test_prompt_injection_warns(self):
        """Injected instructions in scanner output are an attack on the pipeline
        and must always surface."""
        qa = qa_utils.summarize_qa(remarks("PROMPT-INJECTION INDICATORS found in source"))
        assert qa["injection"] is True
        assert qa["warnings"]

    def test_reviewer_verdict_captured(self):
        qa = qa_utils.summarize_qa(remarks('verdict: "Likely False Positive"'))
        assert qa["review_verdict"] == "Likely False Positive"


class TestCleanFindings:
    def test_no_remarks_produces_no_flags(self):
        qa = qa_utils.summarize_qa(remarks(""))
        assert qa["warnings"] == []
        assert qa["level"] == "none"

    def test_missing_field_does_not_raise(self):
        qa = qa_utils.summarize_qa({})
        assert qa["warnings"] == []

    def test_unrelated_text_is_not_a_signal(self):
        qa = qa_utils.summarize_qa(remarks("Retested on 2026-01-05 by the app team."))
        assert qa["warnings"] == []
        assert qa["injection"] is False


class TestFlagText:
    def test_returns_text_for_flagged_finding(self):
        assert qa_utils.qa_flag_text(remarks("Evidence grounding: UNVERIFIED"))

    def test_empty_for_clean_finding(self):
        assert qa_utils.qa_flag_text(remarks("")) in ("", None)


REVIEWED = """- Evidence grounding: PARTIAL. Some claims are supported by the supplied input.
- Skeptical review - verdict: "Likely False Positive" (confidence: High, false-positive risk: High).
  Reviewer severity: "Informational" | exploitability: "No demonstrated impact on a static page".
  REVIEWER DISAGREES ON SEVERITY: draft "Medium" vs reviewer "Informational".
  Reasoning: The page carries no forms and no authenticated state, so framing it yields no attacker benefit.
  Evidence still needed: A demonstration that a sensitive action can be triggered while framed.
- SEVERITY MISMATCH: model said Medium, computed CVSS band is Low."""


class TestReviewSummary:
    """The reviewer's reasoning has to reach the interface, not just the export.

    Showing a bare verdict with no basis asks the analyst to trust the model,
    which is the opposite of what the review pass is for.
    """

    def test_extracts_the_verdict_and_its_qualifiers(self):
        r = qa_utils.review_summary({"additional_remarks": REVIEWED})
        assert r["reviewed"] is True
        assert r["verdict"] == "Likely False Positive"
        assert r["confidence"] == "High"
        assert r["false_positive_risk"] == "High"

    def test_extracts_the_reasoning(self):
        r = qa_utils.review_summary({"additional_remarks": REVIEWED})
        assert "no forms" in r["reasoning"]
        assert "SEVERITY MISMATCH" not in r["reasoning"]

    def test_extracts_what_would_change_the_verdict(self):
        r = qa_utils.review_summary({"additional_remarks": REVIEWED})
        assert "sensitive action" in r["evidence_needed"]

    def test_reports_severity_disagreement(self):
        r = qa_utils.review_summary({"additional_remarks": REVIEWED})
        assert r["severity_disagreement"] is True
        assert r["reviewer_severity"] == "Informational"

    def test_carries_the_deterministic_qa_signals(self):
        r = qa_utils.review_summary({"additional_remarks": REVIEWED})
        assert r["grounding"] == "PARTIAL"
        assert r["severity_mismatch"] is True
        assert r["warnings"]

    def test_unreviewed_finding_is_marked_as_such(self):
        r = qa_utils.review_summary({"additional_remarks": ""})
        assert r["reviewed"] is False
        assert r["verdict"] == ""

    def test_missing_field_does_not_raise(self):
        assert qa_utils.review_summary({})["reviewed"] is False
        assert qa_utils.review_summary(None)["reviewed"] is False

    @pytest.mark.parametrize(
        "remark,expected",
        [
            ("- Skeptical review: skipped (per-batch review cap reached).", "skipped"),
            ("- Skeptical review: unavailable (rate limited).", "unavailable"),
        ],
    )
    def test_distinguishes_not_reviewed_from_reviewed_clean(self, remark, expected):
        """A finding nobody audited must not look like one that passed audit."""
        r = qa_utils.review_summary({"additional_remarks": remark})
        assert r["reviewed"] is False
        assert expected in r["unavailable"]

    def test_prompt_injection_surfaces(self):
        r = qa_utils.review_summary(
            {"additional_remarks": "- PROMPT-INJECTION INDICATORS found in source"}
        )
        assert r["injection"] is True
