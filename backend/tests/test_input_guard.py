"""Pre-flight check on analyzer input.

Every analysis costs at least two model calls, so obvious non-evidence should be
turned away before any of it is spent. The hard requirement is asymmetric: a
wrongly rejected submission costs the user real work, while a wrongly accepted one
costs a few thousand tokens. So the must-pass cases matter more than the
must-reject ones, and the first of them is the important one -- real evidence is
full of hostile strings, and a filter that keys on tone would reject exactly the
material this tool exists to analyse.
"""
import pytest

import input_guard


class TestRealEvidencePasses:
    @pytest.mark.parametrize(
        "label,text",
        [
            ("xss payload containing profanity", "<script>alert('fuck you')</script>"),
            ("rude string inside a log line", '127.0.0.1 - - "GET /?q=fuck+you HTTP/1.1" 200'),
            ("http request block", "GET /api/v1/account/profile?user_id=4472 HTTP/1.1\nHost: target.test"),
            ("bare sql injection payload", "' OR '1'='1"),
            ("cve identifier alone", "CVE-2022-3602"),
            ("cvss vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ("nmap port table", "22/tcp open ssh OpenSSH 8.9p1\n443/tcp open https nginx 1.24.0"),
            ("terse but real observation", "Port 443 accepts TLS 1.0"),
            ("finding described in prose", "The login page has no rate limiting or account lockout after repeated failures."),
            ("cookie flags", "Set-Cookie: session=abc123; Path=/ without Secure or HttpOnly"),
            ("zap json", '{"alert":"SQL Injection","riskdesc":"High (Medium)","cweid":"89"}'),
            ("stack trace", 'Traceback (most recent call last):\n  File "app.py", line 42\nValueError: bad input'),
            ("nginx config", "server {\n  listen 443 ssl;\n  location / { proxy_pass http://backend; }\n}"),
            ("path traversal", "GET /download?file=../../../../etc/passwd"),
            ("unsigned jwt", "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."),
            ("ssrf against metadata", 'POST /webhook {"url":"http://169.254.169.254/latest/meta-data/"}'),
        ],
    )
    def test_accepted(self, label, text):
        result = input_guard.assess_input(text)
        assert result["ok"] is True, f"{label} was wrongly rejected: {result['reason']}"

    def test_profanity_alone_is_not_the_signal(self):
        """The same rude words are accepted inside evidence and rejected without it,
        which shows the gate is keyed on structure rather than on tone."""
        assert input_guard.assess_input("<script>alert('fuck you')</script>")["ok"] is True
        assert input_guard.assess_input("Fuck you")["ok"] is False


class TestNonEvidenceRejected:
    @pytest.mark.parametrize(
        "text",
        [
            "Fuck you",
            "hello",
            "test",
            "asdasdasdasd",
            "what is the weather today in Kuala Lumpur",
            "write me a poem about the sea",
            "hi how are you doing today",
            "Can you open the report and tell me what you think about it please",
        ],
    )
    def test_rejected(self, text):
        assert input_guard.assess_input(text)["ok"] is False

    def test_long_prose_without_security_content_is_rejected(self):
        prose = (
            "The quarterly review meeting went well and the team agreed to revisit the roadmap "
            "in spring. Several people raised concerns about the timeline but the mood was positive. "
        ) * 3
        assert input_guard.assess_input(prose)["ok"] is False

    @pytest.mark.parametrize("text", ["", "   ", "\n\n\t "])
    def test_blank_input_is_rejected(self, text):
        assert input_guard.assess_input(text)["ok"] is False

    def test_rejection_says_nothing_was_spent(self):
        """The message has to make clear no quota was consumed, or a user will
        assume a failed analysis cost them a run."""
        reason = input_guard.assess_input("Fuck you")["reason"]
        assert "no tokens" in reason.lower()
        assert len(reason) > 40


class TestShape:
    def test_result_shape_is_stable(self):
        r = input_guard.assess_input("GET / HTTP/1.1")
        assert set(r) == {"ok", "reason", "signals", "score", "chars"}
        assert isinstance(r["signals"], list)
        assert isinstance(r["score"], int)

    def test_accepted_input_carries_no_reason(self):
        assert input_guard.assess_input("CVE-2022-3602")["reason"] == ""

    def test_signals_name_what_matched(self):
        r = input_guard.assess_input("GET /a HTTP/1.1\nHost: t.test")
        assert "request_line" in r["signals"]

    def test_none_is_handled(self):
        assert input_guard.assess_input(None)["ok"] is False
