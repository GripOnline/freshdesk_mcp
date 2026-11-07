"""Run the MCP server over Streamable HTTP, protected by our own OAuth authorization server."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from .auth.config import MCP_PATH, SCOPE, OAuthConfig
from .auth.consent import register_routes
from .auth.freshdesk import FreshdeskUnavailable, InvalidApiKey, verify_api_key
from .auth.provider import FreshdeskOAuthProvider
from .credentials import Credentials, enable_oauth_mode

logger = logging.getLogger(__name__)


def configure_oauth(mcp: FastMCP, config: OAuthConfig) -> FreshdeskOAuthProvider:
    """Attach the OAuth provider, consent routes and HTTP settings to ``mcp``."""
    provider = FreshdeskOAuthProvider(config)

    mcp.settings.auth = AuthSettings(
        issuer_url=config.public_base_url,
        service_documentation_url=config.public_base_url + "/",
        resource_server_url=config.resource_url,
        validate_token_resource=True,
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    # FastMCP only accepts the provider in its constructor, while the tools are registered
    # on the module-level instance at import time. These attributes are what the
    # constructor sets (mcp>=1.30,<2); tests/test_oauth.py asserts the result works.
    if not hasattr(mcp, "_auth_server_provider") or not hasattr(mcp, "_token_verifier"):
        raise RuntimeError("Unsupported mcp SDK version: cannot attach OAuth provider")
    mcp._auth_server_provider = provider
    mcp._token_verifier = ProviderTokenVerifier(provider)

    mcp.settings.streamable_http_path = MCP_PATH
    # Stateless: every request carries its own bearer token, and sessions survive restarts.
    mcp.settings.stateless_http = True

    public = urlsplit(config.public_base_url)
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[public.netloc, f"{public.hostname}:*", "localhost:*", "127.0.0.1:*"],
        allowed_origins=[
            f"{public.scheme}://{public.netloc}",
            "https://claude.ai",
            "https://claude.com",
            "http://localhost:*",
            "http://127.0.0.1:*",
        ],
    )

    register_routes(mcp, provider)

    async def on_key_rejected(creds: Credentials) -> None:
        """Freshdesk returned 401: if the stored key is really dead, drop the grant so the
        next MCP request gets a 401 and the client asks the user to reconnect."""
        if not creds.grant_id:
            return
        try:
            await verify_api_key(creds.domain, creds.api_key)
        except InvalidApiKey:
            provider.revoke_grant(creds.grant_id)
        except FreshdeskUnavailable:
            pass

    enable_oauth_mode(on_key_rejected)
    return provider


def build_http_app(mcp: FastMCP, config: OAuthConfig) -> Starlette:
    configure_oauth(mcp, config)
    return mcp.streamable_http_app()


def run_http(mcp: FastMCP, host: str, port: int) -> None:
    import uvicorn

    config = OAuthConfig.from_env()
    app = build_http_app(mcp, config)
    logger.info("Freshdesk MCP (HTTP/OAuth) for %s at %s", config.freshdesk_domain, config.resource_url)
    # proxy_headers: trust X-Forwarded-* from FORWARDED_ALLOW_IPS (uvicorn default 127.0.0.1)
    uvicorn.run(app, host=host, port=port, proxy_headers=True, server_header=False)
