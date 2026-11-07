"""Resolve which Freshdesk account a tool call runs as.

- stdio (local) mode: FRESHDESK_API_KEY / FRESHDESK_DOMAIN from the environment.
- HTTP (OAuth) mode: the decrypted credentials of the OAuth grant behind the bearer token
  of the current MCP request. No central API key is used.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx

from .auth.freshdesk import basic_auth_header

logger = logging.getLogger(__name__)


class MissingCredentials(RuntimeError):
    pass


@dataclass(frozen=True)
class Credentials:
    domain: str
    api_key: str = field(repr=False)
    grant_id: str | None = None

    @property
    def api_base(self) -> str:
        return f"https://{self.domain}/api/v2"

    @property
    def authorization(self) -> str:
        return basic_auth_header(self.api_key)


class _State:
    oauth_mode: bool = False
    on_key_rejected: Callable[[Credentials], Awaitable[None]] | None = None
    transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock transport here


state = _State()


def enable_oauth_mode(on_key_rejected: Callable[[Credentials], Awaitable[None]]) -> None:
    state.oauth_mode = True
    state.on_key_rejected = on_key_rejected


def _token_from_request():
    """Access token attached by the SDK's bearer-auth middleware to the current request."""
    try:
        from mcp.server.lowlevel.server import request_ctx

        request = request_ctx.get().request
        user = request.scope.get("user") if request is not None else None
        token = getattr(user, "access_token", None)
        if token is not None:
            return token
    except LookupError:
        pass
    from mcp.server.auth.middleware.auth_context import get_access_token

    return get_access_token()


def current_credentials() -> Credentials:
    if state.oauth_mode:
        token = _token_from_request()
        api_key = getattr(token, "api_key", None)
        domain = getattr(token, "domain", None)
        if not api_key or not domain:
            raise MissingCredentials("This request is not authorised for Freshdesk. Reconnect the connector.")
        return Credentials(domain=domain, api_key=api_key, grant_id=getattr(token, "grant_id", None))

    api_key = os.getenv("FRESHDESK_API_KEY")
    domain = os.getenv("FRESHDESK_DOMAIN")
    if not api_key or not domain:
        raise MissingCredentials("FRESHDESK_API_KEY and FRESHDESK_DOMAIN must be set")
    return Credentials(domain=domain.strip().removeprefix("https://").strip("/"), api_key=api_key)


def api_base() -> str:
    return current_credentials().api_base


def authorization_header() -> str:
    return current_credentials().authorization


def http_client() -> httpx.AsyncClient:
    """AsyncClient for Freshdesk calls; in OAuth mode it detects revoked/rotated API keys."""
    if not state.oauth_mode:
        return httpx.AsyncClient(transport=state.transport)
    creds = current_credentials()

    async def check_response(response: httpx.Response) -> None:
        if response.status_code == 401 and state.on_key_rejected is not None:
            await state.on_key_rejected(creds)

    return httpx.AsyncClient(transport=state.transport, event_hooks={"response": [check_response]})
