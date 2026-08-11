"""The verifier classes the structured evidence model made possible.

Each of these needs something a text search could not reach: the request that
produced a response, or the relationship between two exchanges. They were not
practical before evidence was parsed, which is the return on having parsed it.

Every class is tested against a true positive AND a case it must refute. A verifier
that can only agree is decoration, and a suite that only tests agreement will not
notice when it becomes one.
"""
import base64
import json

import pytest

import verifiers as v


def jwt(alg):
    head = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).decode().rstrip("=")
    return f"{head}.eyJzdWIiOiIxIn0.sig"


class TestOpenRedirect:
    def test_confirms_a_caller_controlled_offsite_redirect(self):
        ev = "GET /go?next=https://evil.test/x HTTP/1.1\n\nHTTP/1.1 302 Found\nLocation: https://evil.test/x\n\n"
        r = v.verify_finding({"title": "Open redirect", "affected_url": "/go", "evidence": ev})
        assert r["status"] == v.CONFIRMED

    def test_refutes_a_same_site_redirect(self):
        ev = "GET /go?next=/dashboard HTTP/1.1\n\nHTTP/1.1 302 Found\nLocation: /dashboard\n\n"
        assert v.verify_finding({"title": "Open redirect", "affected_url": "/go", "evidence": ev})["status"] == v.REFUTED

    def test_offsite_but_not_caller_controlled_is_insufficient(self):
        """Leaving the site is not the finding. Caller control is."""
        ev = "GET /go HTTP/1.1\n\nHTTP/1.1 302 Found\nLocation: https://cdn.partner.test/\n\n"
        assert v.verify_finding({"title": "Open redirect", "affected_url": "/go", "evidence": ev})["status"] == v.INSUFFICIENT

    def test_a_location_without_a_redirect_status_is_insufficient(self):
        ev = "GET /go?next=https://evil.test HTTP/1.1\n\nHTTP/1.1 200 OK\nLocation: https://evil.test\n\n"
        assert v.verify_finding({"title": "Open redirect", "affected_url": "/go", "evidence": ev})["status"] == v.INSUFFICIENT


class TestJwt:
    def test_confirms_alg_none_from_the_token_itself(self):
        ev = f"GET /api HTTP/1.1\nAuthorization: Bearer {jwt('none')}\n\nHTTP/1.1 200 OK\n\n{{}}"
        r = v.verify_finding({"title": "JWT accepts alg none", "affected_url": "/api", "evidence": ev})
        assert r["status"] == v.CONFIRMED

    def test_refutes_an_unsigned_claim_when_the_token_is_signed(self):
        ev = f"GET /api HTTP/1.1\nAuthorization: Bearer {jwt('HS256')}\n\nHTTP/1.1 200 OK\n\n{{}}"
        r = v.verify_finding({"title": "JWT accepts alg none (unsigned)", "affected_url": "/api", "evidence": ev})
        assert r["status"] == v.REFUTED

    def test_a_signed_token_alone_settles_nothing_about_verification(self):
        """The header says which algorithm was declared, not whether the server
        checked the signature. Those are different claims."""
        ev = f"GET /api HTTP/1.1\nAuthorization: Bearer {jwt('RS256')}\n\nHTTP/1.1 200 OK\n\n{{}}"
        r = v.verify_finding({"title": "JWT signature not verified", "affected_url": "/api", "evidence": ev})
        assert r["status"] == v.INSUFFICIENT


class TestCacheable:
    def test_confirms_an_authenticated_response_with_no_directive(self):
        ev = "GET /my-account HTTP/1.1\nCookie: session=abc\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\nhi"
        r = v.verify_finding({"title": "Cacheable HTTPS response", "affected_url": "/my-account", "evidence": ev})
        assert r["status"] == v.CONFIRMED

    def test_refutes_when_no_store_is_set(self):
        ev = "GET /my-account HTTP/1.1\nCookie: session=abc\n\nHTTP/1.1 200 OK\nCache-Control: no-store\n\nhi"
        r = v.verify_finding({"title": "Cacheable HTTPS response", "affected_url": "/my-account", "evidence": ev})
        assert r["status"] == v.REFUTED

    def test_unauthenticated_content_may_legitimately_be_cacheable(self):
        ev = "GET /about HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\nabout us"
        r = v.verify_finding({"title": "Cacheable HTTPS response", "affected_url": "/about", "evidence": ev})
        assert r["status"] == v.INSUFFICIENT


class TestErrorDisclosure:
    def test_confirms_a_real_stack_trace(self):
        ev = ('GET /x HTTP/1.1\n\nHTTP/1.1 500 Internal Server Error\n\n'
              'Traceback (most recent call last):\n  File "app.py", line 42\nValueError: bad')
        r = v.verify_finding({"title": "Verbose error message disclosure", "affected_url": "/x", "evidence": ev})
        assert r["status"] == v.CONFIRMED

    def test_refutes_a_clean_error_page(self):
        ev = "GET /x HTTP/1.1\n\nHTTP/1.1 404 Not Found\nContent-Type: text/html\n\n<h1>Not found</h1>"
        r = v.verify_finding({"title": "Verbose error message disclosure", "affected_url": "/x", "evidence": ev})
        assert r["status"] == v.REFUTED

    def test_a_500_without_a_trace_discloses_nothing(self):
        ev = "GET /x HTTP/1.1\n\nHTTP/1.1 500 Internal Server Error\n\nSomething went wrong"
        r = v.verify_finding({"title": "Verbose error message disclosure", "affected_url": "/x", "evidence": ev})
        assert r["status"] == v.INSUFFICIENT


class TestSessionFixation:
    """Set-level: the claim is about what happened BETWEEN two exchanges."""

    BEFORE_AFTER = (
        "GET / HTTP/1.1\n\nHTTP/1.1 200 OK\nSet-Cookie: session={a}; Path=/\n\nx\n\n"
        "POST /login HTTP/1.1\n\nuser=a&password=b\n\nHTTP/1.1 302 Found\nSet-Cookie: session={b}; Path=/\n\n"
    )

    def test_confirms_when_the_identifier_survives_authentication(self):
        ev = self.BEFORE_AFTER.format(a="AAA", b="AAA")
        assert v.verify_finding({"title": "Session fixation", "evidence": ev})["status"] == v.CONFIRMED

    def test_refutes_when_the_identifier_is_regenerated(self):
        ev = self.BEFORE_AFTER.format(a="AAA", b="ZZZ")
        assert v.verify_finding({"title": "Session fixation", "evidence": ev})["status"] == v.REFUTED

    def test_without_a_login_exchange_there_is_nothing_to_compare(self):
        ev = "GET / HTTP/1.1\n\nHTTP/1.1 200 OK\nSet-Cookie: session=AAA\n\nx\n\nGET /a HTTP/1.1\n\nHTTP/1.1 200 OK\nSet-Cookie: session=BBB\n\ny"
        assert v.verify_finding({"title": "Session fixation", "evidence": ev})["status"] == v.INSUFFICIENT


class TestRateLimiting:
    @staticmethod
    def attempts(statuses):
        return "".join(
            f"POST /login HTTP/1.1\n\nu=a&p={i}\n\nHTTP/1.1 {s} X\n\nno\n\n"
            for i, s in enumerate(statuses)
        )

    def test_confirms_when_every_repeated_attempt_is_accepted(self):
        ev = self.attempts([200] * 5)
        assert v.verify_finding({"title": "No rate limiting on login", "evidence": ev})["status"] == v.CONFIRMED

    def test_refutes_when_the_endpoint_starts_returning_429(self):
        ev = self.attempts([200, 200, 429, 429, 429])
        assert v.verify_finding({"title": "No rate limiting on login", "evidence": ev})["status"] == v.REFUTED

    def test_a_single_attempt_shows_nothing(self):
        """Absence of a limit is demonstrated by repetition. One request cannot."""
        ev = self.attempts([200])
        assert v.verify_finding({"title": "No rate limiting on login", "evidence": ev})["status"] == v.INSUFFICIENT


class TestScope:
    @pytest.mark.parametrize("title", ["SQL injection", "Server-side request forgery", "XXE injection"])
    def test_still_uncovered_classes_return_nothing(self, title):
        ev = "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\n\nbody"
        assert v.verify_finding({"title": title, "evidence": ev}) is None
