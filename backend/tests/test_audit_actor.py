"""The audit helpers in the API layer.

main.py pulls in FastAPI and the OpenAI SDK, which a bare checkout may not have,
so the two pure helpers are extracted and exercised on their own.
"""
import ast
import os

import pytest

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")


def _load(*names):
    """Pull the named functions out of main.py along with the module-level
    constants they close over, and execute just those."""
    tree = ast.parse(open(MAIN).read())
    consts = [
        n for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id.isupper() for t in n.targets)
        and all(isinstance(v, (ast.Constant, ast.Tuple, ast.List, ast.Dict, ast.Set))
                for v in [n.value])
    ]
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(wanted) == len(names), f"missing helpers: {names}"
    ns = {}
    exec(compile(ast.Module(body=consts + wanted, type_ignores=[]), "<helpers>", "exec"), ns)
    return ns


HELPERS = _load("_strip_annotations", "_engine_note")


class TestStripAnnotations:
    def test_display_only_keys_never_reach_the_database(self):
        out = HELPERS["_strip_annotations"]({
            "title": "SQLi", "status": "Confirmed",
            "_verdict": {"x": 1}, "_review": {}, "_assessment": {}, "_risk": {},
            "_uid": "abc", "noise": True, "source": "burp", "scanner_confidence": "Firm",
        })
        assert out == {"title": "SQLi", "status": "Confirmed"}

    def test_ordinary_payload_is_untouched(self):
        payload = {"title": "XSS", "severity": "High"}
        assert HELPERS["_strip_annotations"](dict(payload)) == payload


class TestEngineNote:
    def test_records_the_engines_reasoning_when_it_set_the_status(self):
        note = HELPERS["_engine_note"]({
            "_verdict": {
                "auto_set": True, "resolved_status": "Confirmed",
                "confidence_label": "High", "rationale": "evidence verified; exploitability demonstrated.",
            }
        })
        assert "verdict engine" in note
        assert "High" in note
        assert "exploitability demonstrated" in note

    def test_silent_when_the_engine_did_not_decide(self):
        assert HELPERS["_engine_note"]({
            "_verdict": {"auto_set": True, "resolved_status": "Need Review", "rationale": "held"}
        }) == ""

    def test_silent_when_auto_set_is_off(self):
        assert HELPERS["_engine_note"]({
            "_verdict": {"auto_set": False, "resolved_status": "Confirmed", "rationale": "x"}
        }) == ""

    @pytest.mark.parametrize("payload", [{}, {"_verdict": None}, {"_verdict": "nonsense"}])
    def test_malformed_input_does_not_raise(self, payload):
        assert HELPERS["_engine_note"](payload) == ""
