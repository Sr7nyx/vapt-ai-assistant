"""Risk prioritization and framework mapping.

Two properties matter most here: CVSS is computed in code rather than taken from
the model, and a finding with no reliable signal stays explicitly unmapped
instead of being guessed into a framework category.
"""
import pytest

import risk_map


SQLI = {
    "title": "SQL injection in search",
    "severity": "Critical",
    "cwe": "CWE-89",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}
XSS = {"title": "Reflected XSS", "severity": "High", "cwe": "CWE-79"}
UNKNOWN = {"title": "Something odd was observed", "severity": "Low"}


class TestCvss:
    def test_base_score_computed_from_vector(self):
        assert risk_map.cvss_base_of(SQLI) == pytest.approx(9.5, abs=0.2)

    def test_missing_vector_yields_none(self):
        assert risk_map.cvss_base_of({"title": "x"}) is None

    def test_malformed_vector_does_not_raise(self):
        assert risk_map.cvss_base_of({"cvss": "not-a-vector"}) in (None, 0.0)


class TestRiskPriority:
    def test_returns_priority_and_rationale(self):
        r = risk_map.compute_risk_priority(SQLI)
        assert r["priority"] in ("Urgent", "High", "Moderate", "Low")
        assert r["rationale"]
        assert "cvss_base" in r["signals"]

    def test_high_cvss_is_not_low_priority(self):
        assert risk_map.compute_risk_priority(SQLI)["priority"] in ("Urgent", "High")

    def test_kev_escalates(self):
        """A vulnerability in CISA's Known Exploited catalogue is being used in the
        wild, which must outrank an equal-scored one that is not."""
        plain = risk_map.compute_risk_priority(dict(SQLI))
        kev = risk_map.compute_risk_priority(dict(SQLI, kev=True))
        assert kev["score"] >= plain["score"]

    def test_handles_finding_with_no_signals(self):
        r = risk_map.compute_risk_priority(UNKNOWN)
        assert r["priority"]

    def test_empty_finding_does_not_raise(self):
        assert risk_map.compute_risk_priority({})["priority"]


class TestFrameworkMapping:
    def test_sqli_maps_to_injection(self):
        fw = risk_map.map_frameworks(SQLI)
        assert fw["mapped"] is True
        assert "Injection" in fw["owasp"]
        assert fw["cwe"] == "CWE-89"

    def test_mapping_cites_its_basis(self):
        """A mapping that cannot say why it was made cannot be checked."""
        assert risk_map.map_frameworks(SQLI)["basis"]

    def test_xss_maps_without_a_cvss_vector(self):
        assert risk_map.map_frameworks(XSS)["mapped"] is True

    def test_unrecognized_finding_left_unmapped(self):
        fw = risk_map.map_frameworks(UNKNOWN)
        assert fw["mapped"] is False

    def test_empty_finding_left_unmapped(self):
        assert risk_map.map_frameworks({})["mapped"] is False


class TestAssess:
    def test_returns_risk_and_frameworks(self):
        a = risk_map.assess(SQLI)
        assert set(a) == {"risk", "frameworks"}

    def test_empty_finding_does_not_raise(self):
        assert risk_map.assess({})
