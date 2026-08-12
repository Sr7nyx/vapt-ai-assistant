"""Recognising the same finding across scans.

Without this, importing the same scan next month produces an entirely new set of
findings and the questions a vulnerability programme is run on -- what is new, what
came back, what is finally gone -- have no answer.

Identity is the whole thing, so these tests are mostly about what identity must
IGNORE. Two mistakes would each be quietly destructive: treating a re-rated finding
as new erases its history at the moment it got worse, and treating a rotated
session id as a different URL makes every rescan look like a fresh set.
"""
import pytest

import finding_identity as fi


class TestUrlNormalisation:
    @pytest.mark.parametrize(
        "a,b",
        [
            ("https://t.test/user/1042/profile", "https://t.test/user/7781/profile"),
            ("https://t.test/x?id=5", "https://t.test/x?id=5&session=ROTATED"),
            ("https://t.test/x?b=2&a=1", "https://t.test/x?a=1&b=2"),
            ("https://t.test/a/3f2b1c9d8e7f6a5b", "https://t.test/a/9a8b7c6d5e4f3a2b"),
            ("https://T.TEST/Path", "https://t.test/path"),
        ],
    )
    def test_incidental_differences_are_erased(self, a, b):
        assert fi.normalise_url(a) == fi.normalise_url(b)

    @pytest.mark.parametrize(
        "a,b",
        [
            ("https://t.test/a?id=1", "https://t.test/a?name=bob"),
            ("https://t.test/a", "https://t.test/b"),
            ("https://one.test/a", "https://two.test/a"),
        ],
    )
    def test_meaningful_differences_are_kept(self, a, b):
        assert fi.normalise_url(a) != fi.normalise_url(b)

    def test_empty_input_does_not_raise(self):
        assert fi.normalise_url("") == ""
        assert fi.normalise_url(None) == ""


class TestFingerprint:
    BASE = {
        "title": "SQL injection",
        "cwe": "CWE-89",
        "affected_url": "https://t.test/a?id=1",
        "parameter": "id",
    }

    def test_severity_is_not_part_of_identity(self):
        """A finding re-rated from High to Critical is the SAME finding. Treating it
        as new would erase its history at the exact moment it got worse."""
        a = fi.fingerprint({**self.BASE, "severity": "High"})
        b = fi.fingerprint({**self.BASE, "severity": "Critical"})
        assert a == b

    def test_status_is_not_part_of_identity(self):
        a = fi.fingerprint({**self.BASE, "status": "Confirmed"})
        b = fi.fingerprint({**self.BASE, "status": "Fixed"})
        assert a == b

    def test_title_punctuation_and_case_are_ignored(self):
        a = fi.fingerprint({**self.BASE, "title": "SQL Injection"})
        b = fi.fingerprint({**self.BASE, "title": "sql injection!"})
        assert a == b

    def test_parameter_is_part_of_identity(self):
        assert fi.fingerprint(self.BASE) != fi.fingerprint({**self.BASE, "parameter": "name"})

    def test_cwe_is_part_of_identity(self):
        assert fi.fingerprint(self.BASE) != fi.fingerprint({**self.BASE, "cwe": "CWE-79"})

    def test_empty_finding_does_not_raise(self):
        assert isinstance(fi.fingerprint({}), str)


class TestClassify:
    EXISTING = [
        {"id": 1, "title": "SQL injection", "cwe": "CWE-89", "affected_url": "https://t.test/a?id=1",
         "parameter": "id", "severity": "High", "status": "Confirmed", "first_found_date": "2026-01-05"},
        {"id": 2, "title": "Missing CSP", "cwe": "CWE-693", "affected_url": "https://t.test/admin",
         "severity": "Low", "status": "Fixed"},
        {"id": 3, "title": "Reflected XSS", "cwe": "CWE-79", "affected_url": "https://t.test/search",
         "parameter": "q", "severity": "High", "status": "Confirmed"},
        {"id": 4, "title": "Verbose error", "cwe": "CWE-209", "affected_url": "https://t.test/err",
         "severity": "Low", "status": "False Positive"},
    ]

    def scan(self):
        return [
            # session id rotated and severity re-rated: still the same finding
            {"title": "SQL Injection", "cwe": "CWE-89",
             "affected_url": "https://t.test/a?id=1&session=NEW", "parameter": "id", "severity": "Critical"},
            # was Fixed, and it is back
            {"title": "Missing CSP", "cwe": "CWE-693", "affected_url": "https://t.test/admin", "severity": "Low"},
            {"title": "Open redirect", "cwe": "CWE-601", "affected_url": "https://t.test/go",
             "parameter": "next", "severity": "Medium"},
            {"title": "Reflected XSS", "cwe": "CWE-79", "affected_url": "https://t.test/search",
             "parameter": "q", "severity": "High"},
        ]

    def test_states_are_assigned_correctly(self):
        out, _, summary = fi.classify(self.scan(), self.EXISTING)
        states = {c["title"]: c["_delta"]["state"] for c in out}
        assert states["SQL Injection"] == "reappraised"
        assert states["Missing CSP"] == "regressed"
        assert states["Open redirect"] == "new"
        assert states["Reflected XSS"] == "unchanged"
        assert summary == {"new": 1, "regressed": 1, "unchanged": 1, "reappraised": 1, "absent": 0}

    def test_a_regression_carries_its_previous_state(self):
        out, _, _ = fi.classify(self.scan(), self.EXISTING)
        csp = next(c for c in out if c["title"] == "Missing CSP")
        assert csp["_delta"]["previous_status"] == "Fixed"
        assert csp["_delta"]["existing_id"] == 2

    def test_a_reappraisal_records_the_move(self):
        out, _, _ = fi.classify(self.scan(), self.EXISTING)
        sqli = next(c for c in out if c["title"] == "SQL Injection")
        assert sqli["_delta"]["previous_severity"] == "High"
        assert sqli["_delta"]["first_found"] == "2026-01-05"

    def test_open_findings_the_scan_missed_are_reported(self):
        out, absent, _ = fi.classify([self.scan()[0]], self.EXISTING)
        titles = {a["title"] for a in absent}
        assert "Missing CSP" not in titles     # already Fixed
        assert "Verbose error" not in titles   # already False Positive
        assert "Reflected XSS" in titles       # open, and not reported this time

    def test_absent_findings_are_never_closed_automatically(self):
        """Absence is not proof of a fix -- the scan may not have covered it. The
        classifier reports them; it does not change them."""
        out, absent, _ = fi.classify([], self.EXISTING)
        assert all("status" in a for a in absent)
        assert all(a.get("status") not in fi.CLOSED_STATUSES for a in absent)

    def test_an_empty_project_makes_everything_new(self):
        out, absent, summary = fi.classify(self.scan(), [])
        assert summary["new"] == 4
        assert absent == []

    def test_an_empty_scan_does_not_raise(self):
        out, absent, summary = fi.classify([], [])
        assert out == [] and absent == [] and summary["new"] == 0
