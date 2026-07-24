"""Evidence slicing for the reviewer.

The reviewer runs once per finding. Previously each call carried the entire
original input, so a multi-section evidence file was re-sent a dozen times, which
is what exhausts a free-tier token allowance -- the reviewer lane hits its token
ceiling long before its request ceiling.

Slicing only helps if it keeps the right evidence. A slice that drops the proof a
finding rests on would make the reviewer mark a sound finding unverified, which
corrupts the exact signal the review pass exists to produce. These tests pin that
behaviour.
"""
import pytest

gemini_client = pytest.importorskip(
    "gemini_client", reason="install backend/requirements.txt to run reviewer tests"
)


EVIDENCE = """
=== section 1: authorization ===
GET /api/v1/account/profile?user_id=4472 HTTP/1.1
Host: app.test
HTTP/1.1 200 OK
{"user_id":4472,"email":"analyst-b@example.test"}

=== section 2: injection ===
GET /api/v1/reports/export?format=csv'+AND+'1'='1 HTTP/1.1
Host: app.test
HTTP/1.1 200 OK
{"rows":[...],"count":41827}

=== section 3: ssrf ===
POST /api/v2/integrations/webhook/test HTTP/1.1
{"url":"http://169.254.169.254/latest/meta-data/"}
HTTP/1.1 200 OK
{"status":200,"body":"demo-app-instance-role"}
"""

NOISE = "\n".join(
    f"GET /assets/chunk-{i}.js HTTP/1.1\nHost: app.test\nHTTP/1.1 200 OK\n" for i in range(300)
)
LARGE = NOISE[:6000] + EVIDENCE + NOISE[6000:]

IDOR = {
    "title": "Broken object level authorization",
    "affected_url": "https://app.test/api/v1/account/profile",
    "parameter": "user_id",
    "evidence": "GET /api/v1/account/profile?user_id=4472 HTTP/1.1",
}
SQLI = {
    "title": "SQL injection in report export",
    "affected_url": "https://app.test/api/v1/reports/export",
    "parameter": "format",
    "evidence": "GET /api/v1/reports/export?format=csv'+AND+'1'='1 HTTP/1.1",
}
SSRF = {
    "title": "Server-side request forgery",
    "affected_url": "https://app.test/api/v2/integrations/webhook/test",
    "evidence": '{"url":"http://169.254.169.254/latest/meta-data/"}',
}


class TestSmallInputUnchanged:
    def test_input_within_budget_is_returned_verbatim(self):
        """Short evidence must behave exactly as it did before slicing existed."""
        text, excerpted = gemini_client._relevant_input_slice(SQLI, EVIDENCE)
        assert text == EVIDENCE
        assert excerpted is False

    def test_empty_input(self):
        text, excerpted = gemini_client._relevant_input_slice(SQLI, "")
        assert text == ""
        assert excerpted is False

    def test_budget_of_zero_disables_slicing(self):
        text, excerpted = gemini_client._relevant_input_slice(SQLI, LARGE, budget=0)
        assert text == LARGE
        assert excerpted is False


class TestSlicingKeepsTheRightEvidence:
    @pytest.mark.parametrize(
        "finding,marker",
        [
            (IDOR, "user_id=4472"),
            (SQLI, "count\":41827"),
            (SSRF, "169.254.169.254"),
        ],
    )
    def test_slice_contains_the_findings_own_evidence(self, finding, marker):
        text, excerpted = gemini_client._relevant_input_slice(finding, LARGE)
        assert excerpted is True
        assert marker in text

    def test_slice_respects_the_budget(self):
        budget = 2000
        text, _ = gemini_client._relevant_input_slice(SQLI, LARGE, budget=budget)
        # Joining markers add a little; the payload itself must stay bounded.
        assert len(text) <= budget + 200

    def test_slice_is_much_smaller_than_the_input(self):
        text, _ = gemini_client._relevant_input_slice(SQLI, LARGE)
        assert len(text) < len(LARGE) / 4

    def test_omission_is_marked(self):
        """The reviewer must be able to see that material was removed."""
        text, _ = gemini_client._relevant_input_slice(SQLI, LARGE)
        assert "omitted" in text


class TestFallbacks:
    def test_unlocatable_finding_gets_head_and_tail(self):
        """With no anchor to match, the reviewer should still see the shape of the
        input rather than an arbitrary middle section."""
        finding = {"title": "zzz nothing matches this", "evidence": "qqqqqqqqqqqq"}
        text, excerpted = gemini_client._relevant_input_slice(finding, LARGE)
        assert excerpted is True
        assert text.startswith(LARGE[:200])
        assert text.endswith(LARGE[-200:])

    def test_finding_with_no_usable_fields(self):
        text, excerpted = gemini_client._relevant_input_slice({}, LARGE)
        assert excerpted is True
        assert text


class TestPromptDisclosure:
    def test_full_input_is_not_described_as_an_excerpt(self):
        prompt = gemini_client._build_review_prompt(SQLI, EVIDENCE)
        assert "ORIGINAL INPUT" in prompt
        assert "EXCERPT" not in prompt

    def test_excerpted_input_is_declared_to_the_reviewer(self):
        """If the reviewer is not told the input was narrowed, it can read a
        trimmed section as missing evidence and mark a sound finding unverified."""
        prompt = gemini_client._build_review_prompt(SQLI, LARGE)
        assert "EXCERPT" in prompt
        assert "do not treat omitted material as absent evidence" in prompt


class TestBudgetConfiguration:
    def test_default_budget(self, monkeypatch):
        monkeypatch.delenv("VAPT_REVIEW_INPUT_CHARS", raising=False)
        assert gemini_client._review_input_budget() == 4000

    def test_budget_from_environment(self, monkeypatch):
        monkeypatch.setenv("VAPT_REVIEW_INPUT_CHARS", "1500")
        assert gemini_client._review_input_budget() == 1500

    def test_invalid_budget_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("VAPT_REVIEW_INPUT_CHARS", "not-a-number")
        assert gemini_client._review_input_budget() == 4000
