"""SSRF protection for user-supplied LLM provider URLs.

Users may point the server at their own OpenAI-compatible provider. That makes
the server issue outbound requests to a user-controlled host, which is an SSRF
primitive unless it is constrained. These are the tests that keep it constrained.

DNS is stubbed so the suite is hermetic: it must not depend on name resolution,
and it must be able to assert behaviour for addresses that resolve differently
depending on where the tests run.
"""
import pytest

import llm_config


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """By default, pretend every hostname resolves to a public address, so tests
    exercise the allowlist and URL rules rather than the network."""
    monkeypatch.setattr(llm_config, "_resolves_to_public_address", lambda host: True)


# Captured before any fixture patches it, so tests can exercise the real
# resolution logic against a stubbed DNS answer.
REAL_RESOLVER = llm_config._resolves_to_public_address


def resolves_to(monkeypatch, address):
    """Run the real address check against a forced DNS answer."""
    monkeypatch.setattr(llm_config, "_resolves_to_public_address", REAL_RESOLVER)
    monkeypatch.setattr(
        llm_config.socket,
        "getaddrinfo",
        lambda host, *a, **k: [(None, None, None, None, (address, 0))],
    )


class TestAllowedProviders:
    @pytest.mark.parametrize(
        "url",
        [
            "https://api.groq.com/openai/v1",
            "https://openrouter.ai/api/v1",
            "https://api.openai.com/v1",
            "https://api.mistral.ai/v1",
            "https://api.together.xyz/v1",
        ],
    )
    def test_known_providers_accepted(self, url):
        assert llm_config.validate_base_url(url) == url

    def test_trailing_slash_normalized(self):
        assert llm_config.validate_base_url("https://api.groq.com/openai/v1/") == "https://api.groq.com/openai/v1"

    def test_surrounding_whitespace_stripped(self):
        assert llm_config.validate_base_url("  https://api.groq.com/openai/v1  ") == "https://api.groq.com/openai/v1"

    def test_allowlist_extendable_by_operator(self, monkeypatch):
        monkeypatch.setenv("VAPT_ALLOWED_LLM_HOSTS", "llm.internal.example.com")
        assert "llm.internal.example.com" in llm_config.allowed_hosts()
        assert llm_config.validate_base_url("https://llm.internal.example.com/v1")


class TestSsrfRejections:
    def test_plain_http_rejected(self):
        """Downgrading to http would expose the API key in transit."""
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url("http://api.groq.com/openai/v1")

    def test_unknown_host_rejected(self):
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url("https://attacker.example.com/v1")

    def test_credentials_in_url_rejected(self):
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url("https://user:secret@api.groq.com/v1")

    @pytest.mark.parametrize("url", ["", "   ", None])
    def test_blank_rejected(self, url):
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url(url)

    def test_non_http_scheme_rejected(self):
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url("file:///etc/passwd")

    @pytest.mark.parametrize(
        "address",
        [
            "169.254.169.254",  # cloud instance metadata
            "127.0.0.1",        # loopback
            "10.0.0.5",         # private
            "192.168.1.10",     # private
            "172.16.0.1",       # private
            "0.0.0.0",          # unspecified
        ],
    )
    def test_internal_addresses_rejected_even_for_allowlisted_host(self, monkeypatch, address):
        """Defence in depth: an allowlisted name that resolves inward is still refused,
        which is what stops a DNS-rebinding style bypass of the allowlist."""
        resolves_to(monkeypatch, address)
        with pytest.raises(llm_config.ConfigError):
            llm_config.validate_base_url("https://api.groq.com/openai/v1")

    def test_unresolvable_host_rejected(self, monkeypatch):
        def boom(host, *a, **k):
            raise OSError("name resolution failed")

        monkeypatch.setattr(llm_config.socket, "getaddrinfo", boom)
        assert REAL_RESOLVER("nope.example.com") is False


class TestSanitizeLaneConfig:
    def test_valid_config_passes_through(self):
        out = llm_config.sanitize_lane_config(
            {
                "MAIN": {
                    "base_url": "https://api.groq.com/openai/v1",
                    "api_key": "  gsk_test  ",
                    "models": ["llama-3.3-70b-versatile", "  "],
                }
            }
        )
        assert out["MAIN"]["base_url"] == "https://api.groq.com/openai/v1"
        assert out["MAIN"]["api_key"] == "gsk_test"
        assert out["MAIN"]["models"] == ["llama-3.3-70b-versatile"]

    def test_unknown_lane_dropped(self):
        out = llm_config.sanitize_lane_config({"MAIN": {"api_key": "k"}, "SNEAKY": {"api_key": "x"}})
        assert set(out) == {"MAIN"}

    def test_lane_name_case_insensitive(self):
        assert set(llm_config.sanitize_lane_config({"main": {"api_key": "k"}})) == {"MAIN"}

    def test_blank_fields_omitted_so_server_config_applies(self):
        """A field the user left empty must fall through to the server environment
        rather than being sent as an empty override."""
        out = llm_config.sanitize_lane_config({"REVIEW": {"models": ["m"]}})
        assert "base_url" not in out["REVIEW"]
        assert "api_key" not in out["REVIEW"]

    def test_empty_input_yields_empty_config(self):
        assert llm_config.sanitize_lane_config({}) == {}
        assert llm_config.sanitize_lane_config(None) == {}

    def test_malicious_base_url_rejected(self):
        with pytest.raises(llm_config.ConfigError):
            llm_config.sanitize_lane_config({"MAIN": {"base_url": "https://169.254.169.254/v1"}})
