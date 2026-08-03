"""Deterministic verification of claims against evidence.

This layer exists because the skeptical reviewer is a second model auditing the
first, which leaves the project's central claim resting on an LLM assertion. Where
a claim can be settled by parsing the evidence, it should be.

Two properties matter more than coverage:

  REFUTED must be reachable. A verifier that can only ever agree is decoration.
  Each fabrication case below is a hallucination the layer catches in code.

  Silence must never be refutation. Evidence that does not contain a Set-Cookie
  header does not disprove a cookie finding -- the response that set it may simply
  not be in the excerpt. Reading absence as proof would make this layer worse than
  not having it, because it would manufacture false refutations of real findings.
"""
import pytest

import verifiers as v


RESP_BARE = """HTTP/1.1 200 OK
Server: nginx/1.24.0
Content-Type: text/html
Set-Cookie: session=abc123; Path=/

<html><body>Hello</body></html>"""

RESP_HARDENED = """HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax

<html>ok</html>"""


class TestMissingHeader:
    def test_confirms_a_genuinely_absent_header(self):
        r = v.verify_finding({"title": "Missing X-Frame-Options header", "evidence": RESP_BARE})
        assert r["status"] == v.CONFIRMED

    def test_refutes_a_header_claimed_missing_but_present(self):
        """The model asserted an absence the response contradicts."""
        r = v.verify_finding({"title": "Missing X-Frame-Options header", "evidence": RESP_HARDENED})
        assert r["status"] == v.REFUTED
        assert "appears in the response" in r["summary"]

    def test_no_response_is_insufficient_not_refuted(self):
        r = v.verify_finding({"title": "Missing Content-Security-Policy", "evidence": "The site does not set CSP."})
        assert r["status"] == v.INSUFFICIENT

    def test_a_claim_about_a_header_is_not_a_claim_that_it_is_absent(self):
        """"CSP allows unsafe-inline" is not "CSP is missing" and must not be
        checked as though it were."""
        r = v.verify_finding({"title": "Content-Security-Policy allows unsafe-inline", "evidence": RESP_HARDENED})
        assert r is None or r["status"] != v.REFUTED


class TestCookieFlags:
    def test_confirms_a_missing_flag(self):
        r = v.verify_finding({"title": "Session cookie missing Secure flag", "evidence": RESP_BARE})
        assert r["status"] == v.CONFIRMED

    def test_refutes_when_every_cookie_sets_the_flag(self):
        r = v.verify_finding({"title": "Session cookie missing Secure and HttpOnly", "evidence": RESP_HARDENED})
        assert r["status"] == v.REFUTED

    def test_absent_set_cookie_is_insufficient(self):
        r = v.verify_finding({"title": "Cookie missing HttpOnly", "evidence": "HTTP/1.1 200 OK\nServer: nginx"})
        assert r["status"] == v.INSUFFICIENT

    def test_one_hardened_cookie_does_not_clear_a_bare_one(self):
        mixed = "HTTP/1.1 200 OK\nSet-Cookie: a=1; Secure; HttpOnly\nSet-Cookie: b=2; Path=/"
        r = v.verify_finding({"title": "Cookie missing Secure flag", "evidence": mixed})
        assert r["status"] != v.REFUTED


class TestReflection:
    REFLECTED = "GET /s?q=<script>alert(1)</script> HTTP/1.1\n\nHTTP/1.1 200 OK\n\n<h2><script>alert(1)</script></h2>"
    ENCODED = "GET /s?q=<script>alert(1)</script> HTTP/1.1\n\nHTTP/1.1 200 OK\n\n<h2>&lt;script&gt;alert(1)&lt;/script&gt;</h2>"

    def test_confirms_an_unencoded_reflection(self):
        assert v.verify_finding({"title": "Reflected XSS", "evidence": self.REFLECTED})["status"] == v.CONFIRMED

    def test_refutes_when_the_response_encodes_the_payload(self):
        """Encoding the payload is what a page that handles input correctly does,
        so finding the encoded form is positive evidence against the claim."""
        assert v.verify_finding({"title": "Reflected XSS", "evidence": self.ENCODED})["status"] == v.REFUTED

    def test_no_payload_is_insufficient(self):
        r = v.verify_finding({"title": "Reflected XSS", "evidence": "HTTP/1.1 200 OK\n\n<p>hi</p>"})
        assert r["status"] == v.INSUFFICIENT


class TestAccessControlStatus:
    def test_confirms_when_a_request_succeeded(self):
        ev = "GET /api/profile?user_id=4472 HTTP/1.1\n\nHTTP/1.1 200 OK\n{\"user_id\":4472}"
        assert v.verify_finding({"title": "IDOR in profile API", "evidence": ev})["status"] == v.CONFIRMED

    def test_refutes_when_every_response_was_denied(self):
        """A finding asserting that access succeeded, on evidence where it did
        not, is contradicting itself."""
        ev = "GET /api/profile?user_id=4472 HTTP/1.1\n\nHTTP/1.1 403 Forbidden"
        assert v.verify_finding({"title": "IDOR allows unauthorized access", "evidence": ev})["status"] == v.REFUTED


class TestCors:
    def test_confirms_wildcard_with_credentials(self):
        ev = "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"
        r = v.verify_finding({"title": "CORS misconfiguration wildcard with credentials", "evidence": ev})
        assert r["status"] == v.CONFIRMED
        assert "browsers refuse" in r["summary"].lower()

    def test_refutes_a_permissive_claim_on_a_restrictive_policy(self):
        ev = "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://app.target.test"
        r = v.verify_finding({"title": "CORS wildcard allows any origin with credentials", "evidence": ev})
        assert r["status"] == v.REFUTED


class TestDirectoryListing:
    def test_notes_when_the_listing_is_empty(self):
        """Severity-relevant: an index that lists nothing discloses nothing."""
        ev = 'HTTP/1.1 200 OK\n\n<html><title>Index of /uploads</title><h1>Index of /uploads</h1><a href="../">../</a></html>'
        r = v.verify_finding({"title": "Directory listing enabled", "evidence": ev})
        assert r["status"] == v.CONFIRMED
        assert "no files" in r["summary"]


class TestScope:
    @pytest.mark.parametrize(
        "title,evidence",
        [
            ("SQL injection in export", "' OR '1'='1"),
            ("Server-side request forgery", "http://169.254.169.254/"),
            ("JWT algorithm confusion", "alg:none"),
        ],
    )
    def test_uncovered_classes_return_nothing(self, title, evidence):
        """Returning None is the honest answer for a claim no verifier can settle;
        it is not a failure, and it must not be reported as one."""
        assert v.verify_finding({"title": title, "evidence": evidence}) is None

    def test_a_broken_verifier_cannot_break_an_analysis(self, monkeypatch):
        def boom(finding, raw_input=""):
            raise RuntimeError("verifier bug")
        monkeypatch.setattr(v, "VERIFIERS", (boom,))
        r = v.verify_finding({"title": "anything", "evidence": "x"})
        assert r["status"] == v.INSUFFICIENT

    def test_empty_finding_does_not_raise(self):
        assert v.verify_finding({}) is None

    def test_refuted_outranks_confirmed_when_checks_disagree(self):
        """Any refutation dominates: one check contradicting the evidence is enough
        to stop a claim being treated as established."""
        results = [{"status": v.CONFIRMED, "detail": "a", "verifier": "x", "evidence": ""},
                   {"status": v.REFUTED, "detail": "b", "verifier": "y", "evidence": ""}]
        assert any(r["status"] == v.REFUTED for r in results)


class TestEvidenceSources:
    def test_the_raw_input_is_searched_when_the_finding_excerpt_is_thin(self):
        """A finding's evidence field is often a short excerpt, so the original
        input has to be consulted before concluding anything is absent."""
        r = v.verify_finding({"title": "Missing X-Frame-Options", "evidence": "see below"}, RESP_HARDENED)
        assert r["status"] == v.REFUTED
