"""Deterministic verification, scoped to one exchange.

These tests were rewritten when verification became exchange-scoped, and it is
worth saying why: several of the previous ones asserted the bug. They checked that
a 200 found anywhere in the evidence CONFIRMED an access-control finding, and that
a header found anywhere refuted a claim of absence. Both passed, and both were the
defect -- a test suite can pin the wrong behaviour just as firmly as the right one.

What matters here is the third answer. A verifier that guesses which exchange a
finding meant has reintroduced exactly the problem scoping removes, so INSUFFICIENT
is a result, not a failure to produce one.
"""
import pytest

import verifiers as v


TWO_RESPONSES = """GET /login HTTP/1.1
Host: t.test

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'
Set-Cookie: sid=1; Secure; HttpOnly

<html>login</html>

GET /admin HTTP/1.1
Host: t.test

HTTP/1.1 200 OK
Server: nginx
Set-Cookie: tracking=2; Path=/

<html>admin</html>"""


class TestScoping:
    """The regressions that motivated the whole change."""

    def test_a_header_on_another_exchange_does_not_refute_this_one(self):
        r = v.verify_finding({
            "title": "Missing Content-Security-Policy header",
            "affected_url": "https://t.test/admin",
            "evidence": TWO_RESPONSES,
        })
        assert r["status"] == v.CONFIRMED
        assert r["exchange_id"] == "exchange-2"

    def test_the_same_claim_on_the_other_exchange_is_refuted(self):
        r = v.verify_finding({
            "title": "Missing Content-Security-Policy header",
            "affected_url": "https://t.test/login",
            "evidence": TWO_RESPONSES,
        })
        assert r["status"] == v.REFUTED
        assert r["exchange_id"] == "exchange-1"

    def test_cookie_flags_are_read_from_the_bound_exchange_only(self):
        r = v.verify_finding({
            "title": "Cookie set without the Secure flag",
            "affected_url": "/admin",
            "evidence": TWO_RESPONSES,
        })
        assert r["status"] == v.CONFIRMED

    def test_an_unlocatable_finding_is_not_checked_against_a_guess(self):
        r = v.verify_finding({
            "title": "Missing Content-Security-Policy header",
            "evidence": TWO_RESPONSES,
        })
        assert r["status"] == v.INSUFFICIENT
        assert "does not identify which one" in r["summary"]


class TestReflection:
    REFLECTED = ("GET /s?q=<script>alert(1)</script> HTTP/1.1\n\n"
                 "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1><script>alert(1)</script></h1>")
    ENCODED = ("GET /s?q=<script>alert(1)</script> HTTP/1.1\n\n"
               "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1>")
    JSON = ("GET /api?q=<script>alert(1)</script> HTTP/1.1\n\n"
            "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"echo\":\"<script>alert(1)</script>\"}")
    OTHER_REQUEST = (
        "GET /s?q=hello HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>0 results</h1>\n\n"
        "GET /other?x=<script>alert(1)</script> HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<p>no</p>"
    )

    def test_confirms_an_executable_reflection(self):
        r = v.verify_finding({"title": "Reflected XSS", "affected_url": "/s", "evidence": self.REFLECTED})
        assert r["status"] == v.CONFIRMED
        assert "executable context" in r["summary"]

    def test_refutes_when_the_response_encodes_the_payload(self):
        r = v.verify_finding({"title": "Reflected XSS", "affected_url": "/s", "evidence": self.ENCODED})
        assert r["status"] == v.REFUTED

    def test_reflection_into_json_is_not_treated_as_xss(self):
        """Reflected, but with no executable context. These are different claims and
        the verifier should not conflate them."""
        r = v.verify_finding({"title": "Reflected XSS", "affected_url": "/api", "evidence": self.JSON})
        assert r["status"] == v.INSUFFICIENT
        assert "application/json" in r["summary"]

    def test_a_payload_from_another_request_is_not_reflection_here(self):
        r = v.verify_finding({
            "title": "Reflected XSS", "affected_url": "/s", "parameter": "q",
            "evidence": self.OTHER_REQUEST,
        })
        assert r["status"] == v.INSUFFICIENT


class TestAccessControl:
    """A 200 proves nothing on its own. The claim is that one principal reached
    another's object, so the evidence has to show that relationship."""

    BASELINE_THEN_DENIED = """GET /api/profile?user_id=1 HTTP/1.1
Cookie: session=alice

HTTP/1.1 200 OK

{"user_id":1,"email":"alice@example.test"}

GET /api/profile?user_id=2 HTTP/1.1
Cookie: session=alice

HTTP/1.1 403 Forbidden

{"error":"forbidden"}"""

    CROSS_PRINCIPAL = """GET /api/profile?user_id=1 HTTP/1.1
Cookie: session=alice

HTTP/1.1 200 OK

{"user_id":1,"email":"alice@example.test"}

GET /api/profile?user_id=2 HTTP/1.1
Cookie: session=alice

HTTP/1.1 200 OK

{"user_id":2,"email":"bob@example.test"}"""

    IDENTICAL_BODIES = CROSS_PRINCIPAL.replace(
        '{"user_id":2,"email":"bob@example.test"}', '{"user_id":1,"email":"alice@example.test"}'
    )

    ONLY_BASELINE = """GET /api/profile?user_id=1 HTTP/1.1
Cookie: session=alice

HTTP/1.1 200 OK

{"user_id":1,"email":"alice@example.test"}"""

    def test_confirms_when_one_caller_reaches_two_different_objects(self):
        r = v.verify_finding({"title": "IDOR allows unauthorized access", "evidence": self.CROSS_PRINCIPAL})
        assert r["status"] == v.CONFIRMED

    def test_refutes_when_the_cross_object_request_was_denied(self):
        """The successful response is the caller's own baseline, which the old
        verifier treated as proof of the finding."""
        r = v.verify_finding({"title": "IDOR allows unauthorized access", "evidence": self.BASELINE_THEN_DENIED})
        assert r["status"] == v.REFUTED

    def test_a_lone_successful_response_proves_nothing(self):
        r = v.verify_finding({"title": "IDOR allows unauthorized access", "evidence": self.ONLY_BASELINE})
        assert r["status"] == v.INSUFFICIENT
        assert "baseline" in r["summary"]

    def test_identical_bodies_do_not_demonstrate_disclosure(self):
        r = v.verify_finding({"title": "IDOR allows unauthorized access", "evidence": self.IDENTICAL_BODIES})
        assert r["status"] == v.INSUFFICIENT


class TestCors:
    def test_confirms_a_reflected_origin_with_credentials(self):
        """Only checkable now that the REQUEST is parsed: reflection means the
        response echoes the origin that was sent."""
        ev = ("GET /api/me HTTP/1.1\nOrigin: https://attacker.test\n\n"
              "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.test\n"
              "Access-Control-Allow-Credentials: true\n\n{}")
        r = v.verify_finding({"title": "CORS arbitrary origin trusted", "affected_url": "/api/me", "evidence": ev})
        assert r["status"] == v.CONFIRMED

    def test_refutes_a_permissive_claim_on_a_fixed_origin(self):
        ev = ("GET /api/me HTTP/1.1\nOrigin: https://attacker.test\n\n"
              "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://app.t.test\n\n{}")
        r = v.verify_finding({"title": "CORS wildcard allows any origin", "affected_url": "/api/me", "evidence": ev})
        assert r["status"] == v.REFUTED


class TestScope:
    # JWT moved out of this list when verify_jwt_alg_none was added: the class is
    # covered now, and leaving it here would assert the opposite of the feature.
    @pytest.mark.parametrize("title", ["SQL injection in export", "Server-side request forgery", "XXE injection"])
    def test_uncovered_classes_return_nothing(self, title):
        ev = "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\n\nbody"
        assert v.verify_finding({"title": title, "evidence": ev}) is None

    def test_evidence_with_no_exchange_returns_nothing(self):
        assert v.verify_finding({"title": "Missing CSP", "evidence": "The site does not set CSP."}) is None

    def test_a_broken_verifier_cannot_break_an_analysis(self, monkeypatch):
        def boom(finding, ex):
            raise RuntimeError("verifier bug")
        monkeypatch.setattr(v, "SINGLE_EXCHANGE_VERIFIERS", (boom,))
        # It must not raise; whether it reports anything depends on the claim.
        v.verify_finding({"title": "Missing CSP", "evidence": "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\n\n"})

    def test_empty_finding_does_not_raise(self):
        assert v.verify_finding({}) is None

    def test_results_name_the_exchange_they_checked(self):
        r = v.verify_finding({"title": "Missing CSP", "affected_url": "/admin", "evidence": TWO_RESPONSES})
        assert r["exchange_id"] == "exchange-2"
        assert r["exchange_count"] == 2
