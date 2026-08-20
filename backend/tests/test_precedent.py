"""Retrieval: showing the reviewer how this operator has ruled before.

The honest version of "learns from every run" -- no weights change, the model is
simply shown the operator's own past decisions on similar findings.

Two properties matter more than the ranking. Only ADJUDICATED findings may be
retrieved: an unreviewed one carries no judgment, and putting the model's earlier
guess back in front of it is how a model talks itself into the same mistake twice.
And a weak match must return nothing, because an unrelated ruling presented as
relevant is worse than no context at all.
"""
import pytest

import precedent


def f(fid, title, cwe, status, severity="Medium", **kw):
    return {"id": fid, "title": title, "cwe": cwe, "status": status, "severity": severity, **kw}


HISTORY = [
    f(1, "Missing X-Frame-Options header", "CWE-1021", "False Positive", "Low",
      fp_checks="Static asset with no session context; clickjacking has no impact."),
    f(2, "Missing X-Frame-Options header", "CWE-1021", "False Positive", "Low"),
    f(3, "SQL injection in catalog filter", "CWE-89", "Confirmed", "Critical"),
    f(4, "Reflected XSS in search", "CWE-79", "Confirmed", "High"),
    f(5, "Cookie without Secure flag", "CWE-614", "Need Review"),
]


class TestSimilarity:
    def test_identical_titles_score_one(self):
        a = {"title": "Missing CSP", "cwe": "CWE-693"}
        assert precedent.similarity(a, dict(a)) == 1.0

    def test_unrelated_titles_score_zero(self):
        a = {"title": "SQL injection", "cwe": "CWE-89"}
        b = {"title": "Open redirect", "cwe": "CWE-601"}
        assert precedent.similarity(a, b) == 0.0

    def test_it_is_symmetric(self):
        a = {"title": "Missing X-Frame-Options header on the admin panel", "cwe": "CWE-1021"}
        b = {"title": "Missing X-Frame-Options", "cwe": "CWE-1021"}
        assert precedent.similarity(a, b) == precedent.similarity(b, a)

    def test_a_long_title_is_not_similar_to_everything(self):
        """Without normalising, more words would mean more overlap with anything."""
        verbose = {"title": "Potential security vulnerability issue detected in the "
                            "application relating to headers and cookies", "cwe": ""}
        other = {"title": "SQL injection", "cwe": "CWE-89"}
        assert precedent.similarity(verbose, other) < 0.2

    def test_empty_input_does_not_raise(self):
        assert precedent.similarity({}, {}) == 0.0


class TestRetrieval:
    def test_a_new_instance_of_a_ruled_class_finds_precedent(self):
        ps = precedent.find_precedents(
            {"title": "Missing X-Frame-Options header", "cwe": "CWE-1021"}, HISTORY
        )
        assert len(ps) == 2
        assert all(p["finding"]["status"] == "False Positive" for p in ps)

    def test_an_unrelated_finding_gets_nothing(self):
        """A weak match is worse than none: it puts an unrelated ruling in front of
        the model as though it were relevant."""
        ps = precedent.find_precedents(
            {"title": "Open redirect in return parameter", "cwe": "CWE-601"}, HISTORY
        )
        assert ps == []

    def test_unadjudicated_findings_are_never_retrieved(self):
        """Finding 5 is Need Review. Retrieving it would show the model its own
        earlier guess as though it were a decision."""
        ps = precedent.find_precedents({"title": "Cookie without Secure flag", "cwe": "CWE-614"}, HISTORY)
        assert ps == []

    def test_a_finding_is_not_its_own_precedent(self):
        ps = precedent.find_precedents(HISTORY[0], HISTORY)
        assert all(p["finding"]["id"] != 1 for p in ps)

    def test_the_limit_is_respected(self):
        history = [f(i, "Missing CSP header", "CWE-693", "False Positive") for i in range(1, 9)]
        assert len(precedent.find_precedents({"title": "Missing CSP header", "cwe": "CWE-693"}, history)) == 3

    def test_empty_history_does_not_raise(self):
        assert precedent.find_precedents({"title": "x", "cwe": "y"}, []) == []


class TestFormatting:
    def test_the_block_states_the_decision_and_the_reason(self):
        ps = precedent.find_precedents(
            {"title": "Missing X-Frame-Options header", "cwe": "CWE-1021"}, HISTORY
        )
        block = precedent.format_precedents(ps)
        assert "False Positive" in block
        assert "clickjacking has no impact" in block

    def test_it_does_not_instruct_the_model(self):
        """A precedent is context, not an order. A prompt that said 'therefore mark
        this a false positive' would defeat the reviewer's purpose."""
        block = precedent.format_precedents(
            precedent.find_precedents({"title": "Missing X-Frame-Options header", "cwe": "CWE-1021"}, HISTORY)
        )
        lowered = block.lower()
        assert "not instructions" in lowered
        for phrase in ("you must", "therefore mark", "always rule", "should be marked"):
            assert phrase not in lowered

    def test_no_precedents_produces_no_block(self):
        """An empty heading in a prompt is wasted tokens and invites the model to
        invent something to put under it."""
        assert precedent.format_precedents([]) == ""


class TestStats:
    def test_counts_only_adjudicated(self):
        s = precedent.precedent_stats(HISTORY)
        assert s["adjudicated"] == 4

    def test_a_thin_history_is_reported_as_not_useful(self):
        assert precedent.precedent_stats(HISTORY[:2])["useful"] is False

    def test_empty_history_does_not_raise(self):
        assert precedent.precedent_stats([])["adjudicated"] == 0
