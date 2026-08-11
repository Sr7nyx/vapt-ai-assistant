"""Structured evidence, and binding a finding to the exchange it is about.

The verifiers used to search the whole submission. That is only sound with one
exchange in it; with several it produced confident nonsense from the one component
the verdict engine trusts above the reviewer. These tests pin the parsing and, more
importantly, the refusal: when a finding cannot be tied to a specific exchange, the
correct answer is "cannot tell", not a guess.
"""
import pytest

import evidence_model as em

TWO = """GET /login HTTP/1.1
Host: t.test
User-Agent: curl/8

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'
Set-Cookie: a=1; Secure
Set-Cookie: b=2

<html>login</html>

POST /admin?tab=users HTTP/1.1
Host: t.test
Content-Type: application/x-www-form-urlencoded

id=7&name=x

HTTP/1.1 403 Forbidden
Server: nginx

denied"""


class TestParsing:
    def test_splits_into_exchanges(self):
        assert len(em.parse_exchanges(TWO)) == 2

    def test_request_line_is_decomposed(self):
        req = em.parse_exchanges(TWO)[1]["request"]
        assert req["method"] == "POST"
        assert req["path"] == "/admin"
        assert req["params"] == {"tab": ["users"]}

    def test_headers_are_read_per_exchange(self):
        """The whole point: a header on one response is not a header on another."""
        a, b = em.parse_exchanges(TWO)
        assert em.header(a, "content-security-policy") == ["default-src 'self'"]
        assert em.header(b, "content-security-policy") == []

    def test_repeated_headers_are_kept(self):
        """Collapsing Set-Cookie to one value silently loses cookies."""
        assert em.header(em.parse_exchanges(TWO)[0], "set-cookie") == ["a=1; Secure", "b=2"]

    def test_status_is_an_integer(self):
        assert em.parse_exchanges(TWO)[1]["response"]["status"] == 403

    def test_bodies_are_separated_from_headers(self):
        ex = em.parse_exchanges(TWO)
        assert ex[1]["request"]["body"] == "id=7&name=x"
        assert "denied" in ex[1]["response"]["body"]

    def test_a_response_without_a_request_is_still_parsed(self):
        """Pasting only a response is common and still checkable."""
        ex = em.parse_exchanges("HTTP/1.1 200 OK\nServer: nginx\n\nbody")
        assert len(ex) == 1
        assert ex[0]["response"]["status"] == 200

    def test_absolute_request_targets(self):
        ex = em.parse_exchanges("GET https://t.test/a/b?x=1 HTTP/1.1\n\nHTTP/1.1 200 OK\n\n")
        assert ex[0]["request"]["path"] == "/a/b"
        assert ex[0]["request"]["params"] == {"x": ["1"]}

    @pytest.mark.parametrize("text", ["", "not evidence at all", "   "])
    def test_junk_yields_nothing_rather_than_raising(self, text):
        assert em.parse_exchanges(text) == []


class TestBinding:
    def test_single_exchange_binds_without_locating_information(self):
        ex = em.parse_exchanges("GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\n\n")
        bound, why = em.bind({"title": "anything"}, ex)
        assert bound is not None and why == ""

    def test_binds_by_path(self):
        ex = em.parse_exchanges(TWO)
        bound, _ = em.bind({"affected_url": "https://t.test/admin"}, ex)
        assert bound["id"] == "exchange-2"

    def test_binds_by_relative_path(self):
        ex = em.parse_exchanges(TWO)
        bound, _ = em.bind({"affected_url": "/login"}, ex)
        assert bound["id"] == "exchange-1"

    def test_refuses_when_the_finding_names_no_location(self):
        """Guessing which exchange was meant is the bug this module removes."""
        bound, why = em.bind({"title": "Something vague"}, em.parse_exchanges(TWO))
        assert bound is None
        assert "does not identify which one" in why

    def test_refuses_when_the_path_is_not_in_the_evidence(self):
        bound, why = em.bind({"affected_url": "/nowhere"}, em.parse_exchanges(TWO))
        assert bound is None

    def test_refuses_when_two_exchanges_match_equally(self):
        text = (
            "GET /api?id=1 HTTP/1.1\n\nHTTP/1.1 200 OK\n\na\n\n"
            "GET /api?id=2 HTTP/1.1\n\nHTTP/1.1 200 OK\n\nb"
        )
        bound, why = em.bind({"affected_url": "/api", "parameter": "id"}, em.parse_exchanges(text))
        assert bound is None
        assert "equally well" in why

    def test_a_named_parameter_breaks_a_tie(self):
        text = (
            "GET /api?id=1 HTTP/1.1\n\nHTTP/1.1 200 OK\n\na\n\n"
            "GET /api?token=x HTTP/1.1\n\nHTTP/1.1 200 OK\n\nb"
        )
        bound, _ = em.bind({"affected_url": "/api", "parameter": "token"}, em.parse_exchanges(text))
        assert bound["id"] == "exchange-2"

    def test_binding_never_raises_on_empty_input(self):
        bound, why = em.bind({}, [])
        assert bound is None and why
