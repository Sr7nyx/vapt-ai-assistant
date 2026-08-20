"""What the system learns from being corrected.

Nothing here trains a model, and the tests are written to keep it that way: they
check that decisions the operator already made are read back correctly, not that
any weights changed.

Two properties matter more than the arithmetic. A thin sample must be reported as
thin rather than presented as a rate, because a confidence figure derived from
three findings is worse than none. And a prior must never suppress a finding --
being wrong toward "probably not real" costs a second look, being wrong toward
"real" puts a false finding in a client report.
"""
from datetime import datetime, timezone

import pytest

import learning


def ev(fid, new, field="status", old="Need Review", actor="tester"):
    return {
        "finding_id": fid, "action": "update", "field": field,
        "old_value": old, "new_value": new, "actor": actor,
        "created_at": datetime.now(timezone.utc),
    }


def fnd(fid, title="Missing X-Frame-Options", conf=0.5, url="https://t.test/a.js", cwe="CWE-693"):
    return {
        "id": fid, "title": title, "affected_url": url, "cwe": cwe,
        "_verdict": {"confidence": conf},
    }


class TestIsCorrection:
    def test_a_human_status_change_counts(self):
        assert learning.is_correction(ev(1, "False Positive"))

    @pytest.mark.parametrize("actor", ["engine", "system", "", "verdict-engine"])
    def test_automatic_changes_do_not(self, actor):
        """If the engine's own changes counted, it would be measuring its agreement
        with itself and always look well calibrated."""
        assert not learning.is_correction(ev(1, "False Positive", actor=actor))

    def test_other_fields_do_not(self):
        assert not learning.is_correction(ev(1, "b", field="description", old="a"))

    def test_a_no_op_does_not(self):
        assert not learning.is_correction(ev(1, "Confirmed", old="Confirmed"))


class TestCalibration:
    def test_detects_overconfidence(self):
        findings = [fnd(i, conf=0.9) for i in range(1, 11)]
        events = [ev(i, "False Positive") for i in range(1, 5)]
        c = learning.calibration(findings, events)
        bucket = c["buckets"][0]
        assert bucket["claimed"] == 0.9
        assert bucket["observed"] == 0.6
        assert "overconfident" in c["verdict"]

    def test_reports_close_agreement_as_such(self):
        findings = [fnd(i, conf=0.9) for i in range(1, 21)]
        events = [ev(i, "False Positive") for i in range(1, 3)]
        c = learning.calibration(findings, events)
        assert c["calibration_error"] is not None
        assert "closely" in c["verdict"]

    def test_a_thin_bucket_is_marked_unreliable(self):
        """Three findings cannot establish a rate, and presenting one would be
        worse than saying nothing."""
        c = learning.calibration([fnd(1, conf=0.8), fnd(2, conf=0.8)], [])
        assert c["buckets"][0]["reliable"] is False
        assert "Not enough" in c["verdict"]

    def test_thin_buckets_are_excluded_from_the_error(self):
        c = learning.calibration([fnd(1, conf=0.8)], [])
        assert c["calibration_error"] is None

    def test_findings_without_a_verdict_are_ignored(self):
        c = learning.calibration([{"id": 1, "title": "x"}], [])
        assert c["samples"] == 0

    def test_empty_input_does_not_raise(self):
        c = learning.calibration([], [])
        assert c["samples"] == 0 and c["buckets"] == []


class TestClassKey:
    def test_the_path_is_not_part_of_a_prior(self):
        """An operator who dismissed a header finding on four static files
        dismissed a CLASS. Keying on the path means the fifth file learns nothing
        from the first four."""
        a = learning.class_key(fnd(1, url="https://t.test/static/1.js"))
        b = learning.class_key(fnd(2, url="https://t.test/static/2.js"))
        assert a == b

    def test_different_titles_are_different_classes(self):
        assert learning.class_key(fnd(1, title="SQL injection")) != learning.class_key(fnd(2))

    def test_the_parameter_separates_classes(self):
        a = dict(fnd(1), parameter="id")
        b = dict(fnd(2), parameter="name")
        assert learning.class_key(a) != learning.class_key(b)


class TestPriors:
    def test_a_repeatedly_dismissed_class_is_learned(self):
        findings = [fnd(i, url=f"https://t.test/s/{i}.js") for i in range(1, 5)]
        events = [ev(i, "False Positive") for i in range(1, 5)]
        rows = learning.priors(findings, events)
        assert len(rows) == 1
        assert rows[0]["dismissed"] == 4

    def test_below_the_threshold_nothing_is_learned(self):
        findings = [fnd(i) for i in range(1, 3)]
        events = [ev(i, "False Positive") for i in range(1, 3)]
        assert learning.priors(findings, events) == []

    def test_a_contested_class_is_not_learned(self):
        """Three dismissals against two confirmations is a class that needs
        judgement, which is the opposite of a shortcut."""
        findings = [fnd(i, url="https://t.test/same") for i in range(1, 6)]
        events = [ev(1, "False Positive"), ev(2, "False Positive"), ev(3, "False Positive"),
                  ev(4, "Confirmed"), ev(5, "Confirmed")]
        assert learning.priors(findings, events) == []

    def test_confirmations_never_create_a_prior(self):
        """Only dismissals accumulate. A prior that auto-confirmed would put a
        false finding in a client report."""
        findings = [fnd(i, url=f"https://t.test/s/{i}") for i in range(1, 6)]
        events = [ev(i, "Confirmed") for i in range(1, 6)]
        assert learning.priors(findings, events) == []

    def test_engine_changes_do_not_build_priors(self):
        findings = [fnd(i, url=f"https://t.test/s/{i}") for i in range(1, 5)]
        events = [ev(i, "False Positive", actor="engine") for i in range(1, 5)]
        assert learning.priors(findings, events) == []


class TestApplyPriors:
    @staticmethod
    def learned():
        findings = [fnd(i, url=f"https://t.test/s/{i}.js") for i in range(1, 5)]
        return learning.priors(findings, [ev(i, "False Positive") for i in range(1, 5)])

    def test_a_new_instance_of_a_known_class_matches(self):
        rows = self.learned()
        out, hits = learning.apply_priors(
            [{"title": "Missing X-Frame-Options", "affected_url": "https://t.test/s/99.js", "cwe": "CWE-693"}],
            rows,
        )
        assert hits == 1
        assert out[0]["_prior"]["state"] == "previously_dismissed"

    def test_an_unrelated_class_does_not_match(self):
        out, hits = learning.apply_priors(
            [{"title": "SQL injection", "affected_url": "https://t.test/api", "cwe": "CWE-89"}],
            self.learned(),
        )
        assert hits == 0
        assert "_prior" not in out[0]

    def test_nothing_is_removed(self):
        """A prior lowers cost and raises a flag. A tool that silently drops
        findings is not one you can defend."""
        cands = [
            {"title": "Missing X-Frame-Options", "affected_url": "https://t.test/s/9.js", "cwe": "CWE-693"},
            {"title": "SQL injection", "affected_url": "https://t.test/api", "cwe": "CWE-89"},
        ]
        out, _ = learning.apply_priors(cands, self.learned())
        assert len(out) == len(cands)

    def test_savings_are_reported(self):
        cands = [
            {"title": "Missing X-Frame-Options", "affected_url": "https://t.test/s/9.js", "cwe": "CWE-693"},
            {"title": "SQL injection", "affected_url": "https://t.test/api", "cwe": "CWE-89"},
        ]
        out, _ = learning.apply_priors(cands, self.learned())
        assert learning.review_savings(out) == {"total": 2, "skippable": 1, "share": 0.5}

    def test_no_priors_is_a_no_op(self):
        cands = [{"title": "x", "affected_url": "https://t.test/a", "cwe": "CWE-1"}]
        out, hits = learning.apply_priors(cands, [])
        assert hits == 0 and out == cands


class TestVerifierGaps:
    """Which finding classes no verifier claims -- a ranked list of what to build
    next, produced by the system rather than guessed at."""

    @staticmethod
    def fnd(fid, title, cwe, status=None):
        d = {"id": fid, "title": title, "cwe": cwe, "affected_url": f"https://t.test/{fid}"}
        if status is not None:
            d["_verification"] = {"status": status}
        return d

    def corpus(self):
        return [
            self.fnd(1, "Missing CSP", "CWE-693", "CONFIRMED"),
            self.fnd(2, "Missing CSP", "CWE-693", "REFUTED"),
            self.fnd(3, "SQL injection", "CWE-89"),
            self.fnd(4, "SQL injection", "CWE-89"),
            self.fnd(5, "SQL injection", "CWE-89"),
            self.fnd(6, "SSRF in webhook", "CWE-918"),
            self.fnd(7, "Reflected XSS", "CWE-79", "INSUFFICIENT"),
        ]

    def test_ranks_gaps_by_reach(self):
        g = learning.verifier_gaps(self.corpus())
        assert g["gaps"][0]["title"] == "SQL injection"
        assert g["gaps"][0]["unclaimed"] == 3

    def test_a_covered_class_is_not_a_gap(self):
        g = learning.verifier_gaps(self.corpus())
        assert all(r["title"] != "Missing CSP" for r in g["gaps"])

    def test_inconclusive_is_not_counted_as_a_gap(self):
        """A verifier claimed it but the evidence did not settle it. Writing another
        verifier would not have helped -- that is thin evidence, not missing code."""
        g = learning.verifier_gaps(self.corpus())
        assert all(r["title"] != "Reflected XSS" for r in g["gaps"])

    def test_coverage_counts_only_settled_findings(self):
        g = learning.verifier_gaps(self.corpus())
        assert g["coverage"] == round(2 / 7, 3)

    def test_the_recommendation_names_the_largest_gap(self):
        g = learning.verifier_gaps(self.corpus())
        assert "SQL injection" in g["recommendation"]

    def test_full_coverage_says_so(self):
        g = learning.verifier_gaps([self.fnd(1, "Missing CSP", "CWE-693", "CONFIRMED")])
        assert g["gaps"] == []
        assert "evidence quality" in g["recommendation"]

    def test_empty_input_does_not_raise(self):
        g = learning.verifier_gaps([])
        assert g["gaps"] == [] and g["findings"] == 0
