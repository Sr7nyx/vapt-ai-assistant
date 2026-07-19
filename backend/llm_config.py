"""Validation for user-supplied LLM provider configuration.

Letting a user set an arbitrary base URL means the server will make an outbound
HTTP request to a host that the user controls. Unrestricted, that is a
server-side request forgery (SSRF) primitive: an attacker could point the backend
at cloud metadata (169.254.169.254), at localhost, or at hosts inside the private
network, and use the server as a proxy to reach them.

So user-supplied base URLs are constrained twice:
  1. the host must be on an allowlist of known OpenAI-compatible providers
     (extendable at deploy time via VAPT_ALLOWED_LLM_HOSTS), and
  2. the host must not resolve to a loopback, private, link-local, or otherwise
     reserved address -- belt and braces, in case an allowlisted or operator-added
     host ever resolves somewhere internal.

Server-side environment configuration (VAPT_*_BASE_URL) is trusted and not
subject to these checks; only what arrives in a request body is.
"""
import os
import socket
import ipaddress
from urllib.parse import urlparse

DEFAULT_ALLOWED_HOSTS = {
    "api.groq.com",
    "openrouter.ai",
    "api.openai.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.cerebras.ai",
    "integrate.api.nvidia.com",
    "models.inference.ai.azure.com",
    "generativelanguage.googleapis.com",
}

LANES = ("MAIN", "REVIEW")


class ConfigError(ValueError):
    """Raised when a user-supplied provider configuration is not acceptable."""


def allowed_hosts():
    extra = os.environ.get("VAPT_ALLOWED_LLM_HOSTS", "")
    extras = {h.strip().lower() for h in extra.split(",") if h.strip()}
    return DEFAULT_ALLOWED_HOSTS | extras


def _resolves_to_public_address(host):
    """False if the hostname resolves to any non-public address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        # Cannot resolve: treat as unusable rather than assuming it is safe.
        return False
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def validate_base_url(raw):
    """Return a normalized, SSRF-checked base URL, or raise ConfigError."""
    url = (raw or "").strip().rstrip("/")
    if not url:
        raise ConfigError("Base URL is empty.")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ConfigError("Provider base URL must use https.")
    if not parsed.hostname:
        raise ConfigError("Provider base URL has no host.")
    if parsed.username or parsed.password:
        raise ConfigError("Credentials in the base URL are not allowed.")

    host = parsed.hostname.lower()
    if host not in allowed_hosts():
        raise ConfigError(
            f"Provider host '{host}' is not on the allowlist. "
            "Allowed: " + ", ".join(sorted(allowed_hosts()))
        )
    if not _resolves_to_public_address(host):
        raise ConfigError(f"Provider host '{host}' does not resolve to a public address.")
    return url


def sanitize_lane_config(raw):
    """Validate a {lane: {base_url, api_key, models}} mapping from a request body.

    Unknown lanes are dropped, blank fields are omitted (so they fall through to
    the server environment), and every base URL is SSRF-checked.
    """
    out = {}
    for lane, cfg in (raw or {}).items():
        name = str(lane).upper()
        if name not in LANES or not cfg:
            continue
        data = cfg if isinstance(cfg, dict) else cfg.model_dump()
        entry = {}
        if data.get("base_url"):
            entry["base_url"] = validate_base_url(data["base_url"])
        if data.get("api_key"):
            entry["api_key"] = str(data["api_key"]).strip()
        models = [str(m).strip() for m in (data.get("models") or []) if str(m).strip()]
        if models:
            entry["models"] = models
        if entry:
            out[name] = entry
    return out
