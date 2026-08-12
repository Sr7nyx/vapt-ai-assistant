"""The HTML report.

Two properties matter more than appearance. It must be self-contained, because a
report that fetches a stylesheet or a font is one a client's security team is right
to object to -- and it stops rendering the day that host goes away. And user text
must be escaped, because a finding title legitimately contains payload markup: this
is a report about XSS that would otherwise contain it.
"""
import os
import tempfile

import report_html


PROJECT = {"name": "Acme <test>", "client": "Acme & Co", "tester": "S.", "scope": "app.acme.test"}


def render(findings, exec_summary="", methodology=""):
    path = os.path.join(tempfile.mkdtemp(), "r.html")
    report_html.export_to_html(PROJECT, findings, exec_summary, methodology, path)
    return open(path, encoding="utf-8").read()


class TestSelfContained:
    def test_no_external_resources(self):
        body = render([{"title": "x", "severity": "Low"}])
        assert "<script" not in body
        assert "<link " not in body
        assert "@import" not in body
        assert "src=" not in body

    def test_styles_are_inline(self):
        assert "<style>" in render([{"title": "x", "severity": "Low"}])

    def test_includes_a_print_stylesheet(self):
        """A client will print it, and a dark report on paper is unreadable."""
        assert "@media print" in render([{"title": "x", "severity": "Low"}])


class TestEscaping:
    def test_a_payload_in_a_title_is_escaped(self):
        """A report about XSS must not contain XSS."""
        body = render([{"title": "<script>alert(1)</script>", "severity": "High"}])
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body

    def test_evidence_is_escaped(self):
        body = render([{"title": "x", "severity": "Low", "evidence": "<img onerror=alert(1)>"}])
        assert "<img onerror" not in body

    def test_project_metadata_is_escaped(self):
        body = render([{"title": "x", "severity": "Low"}])
        assert "Acme &lt;test&gt;" in body


class TestContent:
    def test_findings_are_ordered_by_severity(self):
        body = render([
            {"title": "low one", "severity": "Low"},
            {"title": "crit one", "severity": "Critical"},
        ])
        assert body.index("crit one") < body.index("low one")

    def test_verification_is_shown_when_present(self):
        body = render([{
            "title": "x", "severity": "High",
            "_verification": {"status": "CONFIRMED", "summary": "checked", "exchange_id": "exchange-2"},
        }])
        assert "VERIFIED BY DETERMINISTIC CHECK" in body
        assert "exchange-2" in body

    def test_a_contradicted_finding_is_marked_as_such(self):
        body = render([{
            "title": "x", "severity": "High",
            "_verification": {"status": "REFUTED", "summary": "contradicted"},
        }])
        assert "CONTRADICTED BY EVIDENCE" in body

    def test_insufficient_verification_is_not_displayed(self):
        """Most classes cannot be settled from text. Showing that for every finding
        would make the useful cases invisible."""
        body = render([{
            "title": "x", "severity": "High",
            "_verification": {"status": "INSUFFICIENT", "summary": "cannot tell"},
        }])
        assert "DETERMINISTIC CHECK" not in body

    def test_a_regression_is_flagged(self):
        body = render([{"title": "x", "severity": "High", "_delta": {"state": "regressed"}}])
        assert "REGRESSED" in body

    def test_empty_sections_are_omitted(self):
        """An empty heading in a client deliverable reads as unfinished work."""
        body = render([{"title": "x", "severity": "Low"}])
        assert "Remediation" not in body
        assert "References" not in body

    def test_an_empty_report_still_renders(self):
        body = render([])
        assert "No findings in scope." in body
        assert "<html" in body
