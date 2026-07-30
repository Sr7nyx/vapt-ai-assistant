"""Audit trail.

Findings are mutable and the verdict engine writes to them automatically, so
without a recorded trail there is no answer to "who set this to Confirmed, and on
what basis". These tests pin the two things that make the trail trustworthy: that
meaningful changes are detected, and that the engine's reasoning survives the
commit rather than vanishing with the job result.
"""
import pytest

# pg_store imports the Postgres driver, which is in requirements.txt but may be
# absent in a bare checkout. The audit logic under test is pure, so skip rather
# than fail when the driver is missing.
pg_store = pytest.importorskip(
    "pg_store", reason="install backend/requirements.txt to run audit tests"
)


class TestDiff:
    def test_status_change_detected(self):
        changes = pg_store.diff_finding({"status": "Need Review"}, {"status": "Confirmed"})
        assert ("status", "Need Review", "Confirmed") in changes

    def test_severity_change_detected(self):
        changes = pg_store.diff_finding({"severity": "Medium"}, {"severity": "Critical"})
        assert ("severity", "Medium", "Critical") in changes

    def test_unchanged_fields_are_not_recorded(self):
        before = {"status": "Confirmed", "severity": "High", "title": "SQLi"}
        assert pg_store.diff_finding(before, dict(before)) == []

    def test_multiple_changes_all_recorded(self):
        changes = pg_store.diff_finding(
            {"status": "Need Review", "severity": "Low", "cvss": ""},
            {"status": "Confirmed", "severity": "High", "cvss": "CVSS:3.1/AV:N"},
        )
        assert {c[0] for c in changes} == {"status", "severity", "cvss"}

    def test_prose_edits_record_the_change_not_both_versions(self):
        """Storing the full before and after of every description edit would grow
        the trail faster than the findings themselves."""
        long_before = "x" * 5000
        changes = pg_store.diff_finding({"description": long_before}, {"description": "rewritten"})
        field, old, new = next(c for c in changes if c[0] == "description")
        assert old == "5000 chars"
        assert new == "rewritten"

    def test_missing_keys_are_treated_as_empty(self):
        changes = pg_store.diff_finding({}, {"status": "Confirmed"})
        assert ("status", "", "Confirmed") in changes

    def test_none_inputs_do_not_raise(self):
        assert pg_store.diff_finding(None, None) == []

    def test_untracked_field_is_ignored(self):
        """Bookkeeping columns are not interesting history."""
        assert pg_store.diff_finding({"updated_at": "a"}, {"updated_at": "b"}) == []


class TestClipping:
    def test_long_values_are_bounded(self):
        out = pg_store._clip("y" * 10_000)
        assert len(out) <= 240
        assert out.endswith("...")

    def test_short_values_pass_through(self):
        assert pg_store._clip("Confirmed") == "Confirmed"

    def test_none_becomes_empty(self):
        assert pg_store._clip(None) == ""


class TestAuditedFieldSelection:
    def test_risk_bearing_fields_are_audited_by_value(self):
        for field in ("status", "severity", "cvss", "cwe"):
            assert field in pg_store.AUDIT_SCALAR_FIELDS

    def test_prose_fields_are_audited_without_full_values(self):
        for field in ("description", "evidence", "remediation"):
            assert field in pg_store.AUDIT_TEXT_FIELDS

    def test_the_two_sets_do_not_overlap(self):
        assert not set(pg_store.AUDIT_SCALAR_FIELDS) & set(pg_store.AUDIT_TEXT_FIELDS)


class TestRecordEventIsNonFatal:
    def test_a_failing_insert_never_breaks_the_audited_operation(self, monkeypatch):
        """An audit write that raises must not roll back the edit it describes;
        losing a history row is bad, losing the user's work is worse."""
        def boom(*a, **k):
            raise RuntimeError("database unavailable")
        monkeypatch.setattr(pg_store, "_exec", boom)
        assert pg_store.record_event("u1", 5, 1, actor="user:a@b.test", action="updated") is False
