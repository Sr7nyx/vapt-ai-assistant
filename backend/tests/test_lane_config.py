"""Per-request model configuration.

Analysis jobs run in worker threads, and each may carry a different user's
provider, key, and model choice. The override therefore has to be thread-local:
if it were module-global, one user's API key could be used to bill another user's
job. That is the property this file exists to protect.
"""
import threading

import pytest

# The client imports pydantic and the OpenAI SDK, which are declared in
# requirements.txt but may be absent in a bare checkout.
gemini_client = pytest.importorskip(
    "gemini_client", reason="install backend/requirements.txt to run lane tests"
)


class TestLaneResolution:
    def test_defaults_used_when_nothing_is_set(self, monkeypatch):
        monkeypatch.delenv("VAPT_MAIN_MODELS", raising=False)
        monkeypatch.delenv("VAPT_MAIN_BASE_URL", raising=False)
        base, key, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "fallback")
        assert models == gemini_client.DEFAULT_MAIN_MODELS
        assert key == "fallback"
        assert base

    def test_environment_overrides_defaults(self, monkeypatch):
        monkeypatch.setenv("VAPT_MAIN_MODELS", "env-model-a, env-model-b")
        _, _, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "k")
        assert models == ["env-model-a", "env-model-b"]

    def test_request_override_beats_environment(self, monkeypatch):
        monkeypatch.setenv("VAPT_MAIN_MODELS", "env-model")
        monkeypatch.setenv("VAPT_MAIN_API_KEY", "env-key")
        with gemini_client.lane_config({"MAIN": {"api_key": "user-key", "models": ["user-model"]}}):
            _, key, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "k")
        assert models == ["user-model"]
        assert key == "user-key"

    def test_partial_override_falls_through_per_field(self, monkeypatch):
        """Overriding the model must not blank out the key."""
        monkeypatch.setenv("VAPT_MAIN_API_KEY", "env-key")
        with gemini_client.lane_config({"MAIN": {"models": ["only-model"]}}):
            _, key, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "k")
        assert models == ["only-model"]
        assert key == "env-key"

    def test_untouched_lane_is_unaffected(self):
        with gemini_client.lane_config({"MAIN": {"models": ["m"]}}):
            _, _, review = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "k")
        assert review == gemini_client.DEFAULT_REVIEW_MODELS

    def test_config_restored_after_context(self):
        with gemini_client.lane_config({"MAIN": {"models": ["temp"]}}):
            pass
        _, _, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "k")
        assert models == gemini_client.DEFAULT_MAIN_MODELS

    def test_none_config_is_a_no_op(self):
        with gemini_client.lane_config(None):
            _, key, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "fallback")
        assert models == gemini_client.DEFAULT_MAIN_MODELS
        assert key == "fallback"


class TestThreadIsolation:
    def test_concurrent_jobs_do_not_share_configuration(self):
        """Two users analyzing at the same time, each with their own key and model.
        Neither may observe the other's."""
        results = {}
        errors = []
        start = threading.Barrier(2)

        def worker(name, key, model):
            try:
                with gemini_client.lane_config({"MAIN": {"api_key": key, "models": [model]}}):
                    start.wait(timeout=5)   # force the two contexts to overlap
                    _, seen_key, seen_models = gemini_client._lane(
                        "MAIN", gemini_client.DEFAULT_MAIN_MODELS, "server-key"
                    )
                    results[name] = (seen_key, seen_models)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=("alice", "alice-key", "alice-model")),
            threading.Thread(target=worker, args=("bob", "bob-key", "bob-model")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors
        assert results["alice"] == ("alice-key", ["alice-model"])
        assert results["bob"] == ("bob-key", ["bob-model"])

    def test_override_does_not_leak_into_an_unconfigured_thread(self):
        """A job started without an override must use the server configuration even
        while another thread holds one."""
        seen = {}
        inside = threading.Event()
        release = threading.Event()

        def holder():
            with gemini_client.lane_config({"MAIN": {"api_key": "held-key", "models": ["held"]}}):
                inside.set()
                release.wait(timeout=5)

        def plain():
            inside.wait(timeout=5)
            _, key, models = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "server-key")
            seen["key"], seen["models"] = key, models
            release.set()

        t1, t2 = threading.Thread(target=holder), threading.Thread(target=plain)
        t1.start(); t2.start(); t1.join(timeout=10); t2.join(timeout=10)

        assert seen["key"] == "server-key"
        assert seen["models"] == gemini_client.DEFAULT_MAIN_MODELS


class TestCrossProviderKeyIsolation:
    """A key is only valid at the provider that issued it.

    Regression: setting VAPT_REVIEW_BASE_URL to a second provider without also
    setting VAPT_REVIEW_API_KEY silently sent the extraction provider's key to the
    review provider, surfacing as a bare 401 in the middle of a job rather than as
    a missing configuration value.
    """

    def test_key_does_not_cross_providers(self, monkeypatch):
        monkeypatch.setenv("VAPT_MAIN_BASE_URL", "https://api.groq.com/openai/v1")
        monkeypatch.setenv("VAPT_REVIEW_BASE_URL", "https://api.cerebras.ai/v1")
        monkeypatch.delenv("VAPT_REVIEW_API_KEY", raising=False)
        _, key, _ = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "groq-key")
        assert key == ""

    def test_lane_specific_key_is_used(self, monkeypatch):
        monkeypatch.setenv("VAPT_MAIN_BASE_URL", "https://api.groq.com/openai/v1")
        monkeypatch.setenv("VAPT_REVIEW_BASE_URL", "https://api.cerebras.ai/v1")
        monkeypatch.setenv("VAPT_REVIEW_API_KEY", "cerebras-key")
        _, key, _ = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "groq-key")
        assert key == "cerebras-key"

    def test_shared_key_still_works_on_one_provider(self, monkeypatch):
        """The common single-provider setup must keep working from one key."""
        monkeypatch.setenv("VAPT_MAIN_BASE_URL", "https://api.groq.com/openai/v1")
        monkeypatch.setenv("VAPT_REVIEW_BASE_URL", "https://api.groq.com/openai/v1")
        monkeypatch.delenv("VAPT_REVIEW_API_KEY", raising=False)
        _, key, _ = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "groq-key")
        assert key == "groq-key"

    def test_defaults_share_one_key(self, monkeypatch):
        monkeypatch.delenv("VAPT_MAIN_BASE_URL", raising=False)
        monkeypatch.delenv("VAPT_REVIEW_BASE_URL", raising=False)
        monkeypatch.delenv("VAPT_REVIEW_API_KEY", raising=False)
        _, key, _ = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "one-key")
        assert key == "one-key"

    def test_extraction_lane_always_accepts_the_caller_key(self, monkeypatch):
        monkeypatch.setenv("VAPT_MAIN_BASE_URL", "https://api.cerebras.ai/v1")
        monkeypatch.delenv("VAPT_MAIN_API_KEY", raising=False)
        _, key, _ = gemini_client._lane("MAIN", gemini_client.DEFAULT_MAIN_MODELS, "caller-key")
        assert key == "caller-key"

    def test_user_override_key_applies_across_providers(self):
        """An explicit per-lane key is a deliberate choice and must be honoured."""
        with gemini_client.lane_config(
            {"REVIEW": {"base_url": "https://api.cerebras.ai/v1", "api_key": "explicit"}}
        ):
            _, key, _ = gemini_client._lane("REVIEW", gemini_client.DEFAULT_REVIEW_MODELS, "groq-key")
        assert key == "explicit"
