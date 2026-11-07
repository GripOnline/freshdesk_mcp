"""Configuration for HTTP/OAuth mode, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_ALLOWED_REDIRECT_URIS = (
    # Claude on the web, Desktop, mobile and Cowork
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    # Claude Code and other native clients (RFC 8252 loopback, any port)
    "http://localhost/callback",
    "http://127.0.0.1/callback",
)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})

SCOPE = "freshdesk"
MCP_PATH = "/mcp"


class ConfigError(RuntimeError):
    pass


def normalize_domain(value: str) -> str:
    """Accept 'acme.freshdesk.com' or 'https://acme.freshdesk.com/' and return the host."""
    value = value.strip()
    if "://" in value:
        value = urlsplit(value).netloc
    value = value.strip("/").lower()
    if not value or "/" in value or " " in value:
        raise ConfigError(f"Invalid FRESHDESK_DOMAIN: {value!r}")
    return value


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as e:
        raise ConfigError(f"{name} must be an integer (seconds)") from e
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class OAuthConfig:
    freshdesk_domain: str
    public_base_url: str
    server_secret: bytes
    data_dir: Path
    allowed_redirect_uris: tuple[str, ...] = DEFAULT_ALLOWED_REDIRECT_URIS
    access_token_ttl: int = 8 * 3600
    refresh_token_ttl: int = 90 * 24 * 3600
    auth_code_ttl: int = 600
    consent_ttl: int = 900
    client_retention: int = 180 * 24 * 3600
    service_name: str = "Freshdesk MCP"

    @property
    def resource_url(self) -> str:
        return self.public_base_url + MCP_PATH

    @classmethod
    def from_env(cls) -> "OAuthConfig":
        missing = [n for n in ("FRESHDESK_DOMAIN", "PUBLIC_BASE_URL", "FRESHDESK_MCP_SECRET") if not os.getenv(n)]
        if missing:
            raise ConfigError("Missing required environment variable(s) for HTTP mode: " + ", ".join(missing))

        domain = normalize_domain(os.environ["FRESHDESK_DOMAIN"])

        base = os.environ["PUBLIC_BASE_URL"].strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ConfigError("PUBLIC_BASE_URL must be an absolute URL such as https://mcp.example.com")
        if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
            raise ConfigError("PUBLIC_BASE_URL must use https:// (http is only allowed for localhost testing)")
        if parts.query or parts.fragment:
            raise ConfigError("PUBLIC_BASE_URL must not contain a query string or fragment")

        secret = os.environ["FRESHDESK_MCP_SECRET"].encode()
        if len(secret) < 32:
            raise ConfigError("FRESHDESK_MCP_SECRET must be at least 32 characters (e.g. `openssl rand -base64 48`)")

        data_dir = Path(os.getenv("FRESHDESK_MCP_DATA_DIR", "./data")).resolve()

        redirect_env = os.getenv("ALLOWED_REDIRECT_URIS")
        if redirect_env:
            redirects = tuple(u.strip() for u in redirect_env.split(",") if u.strip())
        else:
            redirects = DEFAULT_ALLOWED_REDIRECT_URIS

        return cls(
            freshdesk_domain=domain,
            public_base_url=base,
            server_secret=secret,
            data_dir=data_dir,
            allowed_redirect_uris=redirects,
            access_token_ttl=_int_env("ACCESS_TOKEN_TTL", 8 * 3600),
            refresh_token_ttl=_int_env("REFRESH_TOKEN_TTL", 90 * 24 * 3600),
        )
