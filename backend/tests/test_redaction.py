"""Stripping credentials before evidence leaves for a third-party model.

Two failure modes matter, and they pull in opposite directions. Leaking a
credential to a provider is the one this exists to prevent. Over-masking is the
one that quietly ruins the product -- if Secure and HttpOnly disappear, the
cookie-flag reasoning breaks; if a payload disappears, the reflection finding
does. Most of these tests are about the second.
"""
import pytest

import redaction


REQUEST = """GET /api/profile HTTP/1.1
Host: app.acme.test
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature
Cookie: session=A1B2C3D4E5F6; theme=dark
X-API-Key: sk_live_9f8e7d6c5b4a3210

HTTP/1.1 200 OK
Set-Cookie: JSESSIONID=9F8E7D6C5B4A; Path=/; Secure; HttpOnly
Content-Type: application/json

{"email":"alice@client.example","card":"4111111111111111","order":"1234567890123456"}"""


class TestCredentials:
    def test_bearer_tokens_are_masked(self):
        out, _ = redaction.redact(REQUEST)
        assert "abc123signature" not in out
        assert "eyJhbGciOiJIUzI1NiJ9" not in out

    def test_the_scheme_survives(self):
        """The model needs to know the request was authenticated. Deleting the
        line would change what the evidence means; masking the value does not."""
        out, _ = redaction.redact(REQUEST)
        assert "Authorization: Bearer [REDACTED:auth]" in out

    def test_cookie_values_go_but_names_stay(self):
        """Which cookie is set is often the finding, and a name is not a secret."""
        out, _ = redaction.redact(REQUEST)
        assert "A1B2C3D4E5F6" not in out
        assert "session=" in out
        assert "JSESSIONID=" in out

    def test_cookie_attributes_survive(self):
        """Secure and HttpOnly are exactly what the cookie-flag verifier and the
        reviewer reason about. Losing them would break the finding."""
        out, _ = redaction.redact(REQUEST)
        assert "Secure" in out and "HttpOnly" in out and "Path=/" in out

    def test_api_key_headers_are_masked(self):
        out, _ = redaction.redact(REQUEST)
        assert "sk_live_9f8e7d6c5b4a3210" not in out

    @pytest.mark.parametrize("secret,label", [
        ("AKIAIOSFODNN7EXAMPLE", "aws-key"),
        ("AIzaSyD-1234567890abcdefghijklmnopqrstu", "gcp-key"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github-token"),
        ("xoxb-123456789012-abcdefghijklmno", "slack-token"),
    ])
    def test_provider_keys_are_masked(self, secret, label):
        out, report = redaction.redact(f"body contains {secret} here")
        assert secret not in out
        assert label in report["counts"]

    def test_private_keys_are_masked(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----"
        out, _ = redaction.redact(text)
        assert "MIIEpAIB" not in out


class TestPii:
    def test_emails_are_masked(self):
        out, _ = redaction.redact(REQUEST)
        assert "alice@client.example" not in out

    def test_a_real_card_number_is_masked(self):
        out, _ = redaction.redact(REQUEST)
        assert "4111111111111111" not in out

    def test_a_long_id_that_is_not_a_card_survives(self):
        """Without the Luhn check, any 16-digit order number or timestamp pair
        would be masked, and the evidence would lose the identifier the finding is
        about."""
        out, _ = redaction.redact(REQUEST)
        assert "1234567890123456" in out


class TestOverMasking:
    """The failure mode that quietly ruins the product."""

    PLAIN = """GET /catalog?id=42 HTTP/1.1
Host: shop.test
User-Agent: Mozilla/5.0
Accept: text/html

HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0

<h1>Error</h1><p>SQLSTATE[42000]: Syntax error near '1'</p>"""

    def test_ordinary_evidence_is_untouched(self):
        out, report = redaction.redact(self.PLAIN)
        assert out == self.PLAIN
        assert report["redacted"] is False

    def test_a_payload_survives(self):
        """A reflected payload IS the finding. Masking it would destroy the
        evidence being reported."""
        text = "GET /s?q=<script>alert(1)</script> HTTP/1.1\n\nHTTP/1.1 200 OK\n\n<script>alert(1)</script>"
        out, _ = redaction.redact(text)
        assert "<script>alert(1)</script>" in out

    def test_status_codes_and_paths_survive(self):
        out, _ = redaction.redact(self.PLAIN)
        assert "500 Internal Server Error" in out
        assert "/catalog?id=42" in out


class TestTokenFindings:
    EVIDENCE = ("GET /api HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.\n"
                "Cookie: s=secret123\n\nHTTP/1.1 200 OK")

    def test_a_jwt_finding_keeps_its_token(self):
        """alg:none is visible only in the token. Masking it would destroy the
        evidence for exactly the finding that needs it."""
        out, report = redaction.redact(self.EVIDENCE, {"title": "JWT accepts alg none"})
        assert "eyJhbGciOiJub25lIn0" in out
        assert "jwt" in report["kept"]

    def test_but_other_credentials_are_still_masked(self):
        out, _ = redaction.redact(self.EVIDENCE, {"title": "JWT accepts alg none"})
        assert "secret123" not in out

    def test_an_unrelated_finding_masks_the_token(self):
        out, _ = redaction.redact(self.EVIDENCE, {"title": "SQL injection in filter"})
        assert "eyJhbGciOiJub25lIn0" not in out


class TestRobustness:
    def test_redaction_is_idempotent(self):
        """A second pass must not re-count placeholders as newly masked secrets --
        the audit remark would claim values were protected that were never there."""
        once, _ = redaction.redact("Authorization: Bearer abc123def456\nCookie: s=xyz789")
        twice, report = redaction.redact(once)
        assert once == twice
        assert report["total"] == 0

    @pytest.mark.parametrize("text", ["", "   ", None, "not evidence at all"])
    def test_junk_input_does_not_raise(self, text):
        out, report = redaction.redact(text)
        assert report["redacted"] is False

    def test_the_report_counts_what_was_masked(self):
        _, report = redaction.redact(REQUEST)
        assert report["total"] >= 5
        assert "auth" in report["counts"]

    def test_the_summary_is_empty_when_nothing_was_masked(self):
        _, report = redaction.redact("GET / HTTP/1.1\n\nHTTP/1.1 200 OK")
        assert redaction.summarise(report) == ""

    def test_the_summary_names_what_it_masked(self):
        _, report = redaction.redact(REQUEST)
        line = redaction.summarise(report)
        assert "masked before the model saw this" in line
        assert "auth" in line
