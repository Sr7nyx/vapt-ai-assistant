"""MITRE ATT&CK mapping.

The mapping previously carried one technique per class and left four classes blank.
One id is thin for a red-team report: an attacker rarely uses a weakness alone, and
the useful question is which tactic it serves and what it enables next.

The property worth defending is that nothing is guessed. A class either has a
mapping or it does not, and an unmapped class returns nothing rather than the
nearest-looking technique -- a fabricated ATT&CK id reads as authoritative and
survives into a client's threat model.
"""
import pytest

import attack_map as am


class TestCompleteness:
    def test_every_class_has_at_least_one_technique(self):
        blank = [k for k, v in am.CLASS_TECHNIQUES.items() if not v]
        assert blank == [], f"classes with no mapping: {blank}"

    @pytest.mark.parametrize("klass", ["csrf", "misconfig", "error_handling", "logging"])
    def test_previously_unmapped_classes_are_covered(self, klass):
        assert am.techniques_for(klass)

    def test_every_technique_names_a_tactic(self):
        """A technique id without a tactic is trivia. The tactic is what tells a
        reader where in an attack the finding sits."""
        for klass, techs in am.CLASS_TECHNIQUES.items():
            for t in techs:
                assert t["tactic"] in am.TACTICS, f"{klass}: {t['id']} has no valid tactic"
                assert t["tactic_name"]

    def test_technique_ids_look_like_attack_ids(self):
        import re
        for techs in am.CLASS_TECHNIQUES.values():
            for t in techs:
                assert re.match(r"^T\d{4}(\.\d{3})?$", t["id"]), t["id"]


class TestLookup:
    def test_an_unknown_class_returns_nothing(self):
        """Guessing is the failure mode this must not have."""
        assert am.techniques_for("not_a_class") == []
        assert am.primary("not_a_class") == ""

    def test_none_and_empty_are_handled(self):
        assert am.techniques_for(None) == []
        assert am.techniques_for("") == []

    def test_primary_is_the_first_technique(self):
        techs = am.techniques_for("ssrf")
        assert am.primary("ssrf").startswith(techs[0]["id"])

    def test_chains_describe_what_a_weakness_enables(self):
        """SSRF is the clearest case: the request forgery is the way in, and
        instance metadata is what an attacker actually wants from it."""
        ids = [t["id"] for t in am.techniques_for("ssrf")]
        assert "T1552.005" in ids


class TestCoverage:
    @staticmethod
    def finding(class_key):
        return {"_assessment": {"frameworks": {"class_key": class_key}}}

    def test_counts_only_the_primary_technique(self):
        """Counting every enabled technique would inflate the picture: one SSRF
        finding would register across three tactics as though three things were
        found."""
        cov = am.coverage([self.finding("ssrf")])
        assert sum(t["count"] for t in cov["tactics"]) == 1

    def test_groups_by_tactic(self):
        cov = am.coverage([self.finding("injection"), self.finding("injection"), self.finding("error_handling")])
        by_name = {t["tactic_name"]: t["count"] for t in cov["tactics"]}
        assert by_name["Initial Access"] == 2
        assert by_name["Discovery"] == 1

    def test_ordered_by_attack_phase_not_frequency(self):
        """A reader wants the kill chain in order. Sorting by count would put
        Discovery above Initial Access whenever there are more info-disclosure
        findings, which is almost always."""
        cov = am.coverage(
            [self.finding("error_handling")] * 5 + [self.finding("injection")]
        )
        names = [t["tactic_name"] for t in cov["tactics"]]
        assert names.index("Initial Access") < names.index("Discovery")

    def test_unmappable_findings_are_counted_not_hidden(self):
        cov = am.coverage([self.finding("injection"), {"_assessment": {}}, {}])
        assert cov["unmapped"] == 2

    def test_matches_on_the_stable_key_not_the_display_label(self):
        """`class` is the human label ("Injection"). Matching on it would break
        silently the moment one is reworded."""
        cov = am.coverage([{"_assessment": {"frameworks": {"class": "Injection"}}}])
        assert cov["unmapped"] == 1

    def test_empty_input_does_not_raise(self):
        cov = am.coverage([])
        assert cov["tactics"] == [] and cov["unmapped"] == 0
