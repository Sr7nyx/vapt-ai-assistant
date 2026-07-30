"""Usage windowing.

The window is applied in SQL rather than by filtering rows in Python, so the test
captures the statement and parameters instead of needing a database.
"""
import pytest

pg_store = pytest.importorskip(
    "pg_store", reason="install backend/requirements.txt to run usage tests"
)


def capture(monkeypatch):
    """Swap the executors for recorders and hand back the list they append to."""
    calls = []
    monkeypatch.setattr(pg_store, "_one", lambda sql, params=(): (calls.append((sql, params)), {})[1])
    monkeypatch.setattr(pg_store, "_all", lambda sql, params=(): (calls.append((sql, params)), [])[1])
    return calls


class TestWindow:
    def test_all_time_applies_no_interval(self, monkeypatch):
        captured = capture(monkeypatch)
        pg_store.get_usage_summary("u1")
        assert captured, "no query was issued"
        for sql, params in captured:
            assert "make_interval" not in sql
            assert params == ("u1",)

    def test_window_adds_a_bounded_interval(self, monkeypatch):
        captured = capture(monkeypatch)
        pg_store.get_usage_summary("u1", 24)
        for sql, params in captured:
            assert "make_interval(hours => %s)" in sql
            assert params == ("u1", 24)

    def test_hours_are_coerced_to_int(self, monkeypatch):
        """The value reaches SQL as a bound parameter, but coercing it here means a
        string can never travel further into the query builder."""
        captured = capture(monkeypatch)
        pg_store.get_usage_summary("u1", "168")
        for _, params in captured:
            assert params[1] == 168
            assert isinstance(params[1], int)

    def test_zero_hours_is_treated_as_all_time(self, monkeypatch):
        captured = capture(monkeypatch)
        pg_store.get_usage_summary("u1", 0)
        for sql, _ in captured:
            assert "make_interval" not in sql

    def test_both_aggregate_and_per_model_queries_are_windowed(self, monkeypatch):
        captured = capture(monkeypatch)
        pg_store.get_usage_summary("u1", 1)
        assert len(captured) == 2
        assert all("make_interval" in sql for sql, _ in captured)
        assert any("GROUP BY model" in sql for sql, _ in captured)
