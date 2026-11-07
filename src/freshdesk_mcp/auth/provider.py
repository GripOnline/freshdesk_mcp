"""OAuth 2.1 authorization server provider for the MCP Python SDK.

The SDK serves /register, /authorize, /token, /revoke and the discovery metadata; this
provider supplies storage and the hand-off to our own consent page.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

from pydantic import AnyUrl, Field

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken

from .config import LOOPBACK_HOSTS, SCOPE, OAuthConfig
from .freshdesk import Agent
from .store import KIND_ACCESS, KIND_CODE, KIND_REFRESH, GrantStore, IssuedTokens, parse_token

logger = logging.getLogger(__name__)

SWEEP_INTERVAL = 3600
MAX_PENDING = 2000


# ---------------------------------------------------------------------- redirect URIs


def _is_loopback(parts) -> bool:
    return parts.scheme == "http" and (parts.hostname or "").lower() in LOOPBACK_HOSTS


def redirect_matches(candidate: str, registered: str) -> bool:
    """Exact match, or RFC 8252 loopback match that ignores the port."""
    if candidate == registered:
        return True
    c, r = urlsplit(candidate), urlsplit(registered)
    if not (_is_loopback(c) and _is_loopback(r)):
        return False
    return (
        (c.hostname or "").lower() == (r.hostname or "").lower()
        and (c.path or "/") == (r.path or "/")
        and c.query == r.query
        and not c.fragment
    )


def redirect_allowed(uri: str, allowlist: tuple[str, ...]) -> bool:
    return any(redirect_matches(uri, allowed) for allowed in allowlist)


def is_loopback_redirect(uri: str) -> bool:
    return _is_loopback(urlsplit(uri))


class FreshdeskClient(OAuthClientInformationFull):
    """Registered client whose loopback redirect URIs match on any port (RFC 8252 §7.3)."""

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None and self.redirect_uris:
            candidate = str(redirect_uri)
            if any(redirect_matches(candidate, str(r)) for r in self.redirect_uris):
                return redirect_uri
            raise InvalidRedirectUriError(f"Redirect URI '{redirect_uri}' not registered for client")
        return super().validate_redirect_uri(redirect_uri)


# ---------------------------------------------------------------------- tokens


class FreshdeskAccessToken(AccessToken):
    """Access token enriched with the decrypted Freshdesk credentials for this request."""

    grant_id: str
    domain: str
    api_key: str = Field(repr=False, exclude=True)


# ---------------------------------------------------------------------- consent sessions


@dataclass
class ConsentSession:
    """Server-side state of one visit to the consent or grant-management page."""

    id: str
    csrf: str
    created: float
    # OAuth request being authorised (None for the stand-alone /grants page)
    client_id: str | None = None
    client_name: str | None = None
    params: AuthorizationParams | None = None
    # Set once the API key has been verified
    api_key: str | None = None
    agent: Agent | None = None
    api_key_kek: tuple[str, bytes] | None = None
    attempts: int = 0

    @property
    def verified(self) -> bool:
        return self.api_key is not None


class ConsentSessions:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._sessions: OrderedDict[str, ConsentSession] = OrderedDict()

    def _purge(self) -> None:
        cutoff = time.time() - self.ttl
        for sid in [sid for sid, s in self._sessions.items() if s.created < cutoff]:
            del self._sessions[sid]
        while len(self._sessions) > MAX_PENDING:
            self._sessions.popitem(last=False)

    def create(self, **kwargs: Any) -> ConsentSession:
        self._purge()
        session = ConsentSession(
            id=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(32), created=time.time(), **kwargs
        )
        self._sessions[session.id] = session
        return session

    def get(self, sid: str | None) -> ConsentSession | None:
        if not sid:
            return None
        self._purge()
        return self._sessions.get(sid)

    def discard(self, sid: str) -> None:
        self._sessions.pop(sid, None)


# ---------------------------------------------------------------------- provider


class FreshdeskOAuthProvider:
    def __init__(self, config: OAuthConfig, store: GrantStore | None = None):
        self.config = config
        self.store = store or GrantStore(config)
        self.sessions = ConsentSessions(config.consent_ttl)
        self._last_sweep = 0.0

    # -- maintenance

    async def maybe_sweep(self) -> None:
        if time.time() - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = time.time()
        try:
            removed = await asyncio.to_thread(self.store.sweep)
            if removed:
                logger.info("Removed %d expired grant(s)", removed)
        except Exception:  # pragma: no cover - never break a request because of cleanup
            logger.exception("Grant sweep failed")

    # -- clients

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.load_client(client_id)
        if data is None:
            return None
        return FreshdeskClient.model_validate(data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "At least one redirect_uri is required")
        for uri in uris:
            if not redirect_allowed(uri, self.config.allowed_redirect_uris):
                logger.info("Rejected client registration with redirect URI host %r", urlsplit(uri).hostname)
                raise RegistrationError(
                    "invalid_redirect_uri", "This server only accepts the redirect URIs of approved MCP clients"
                )
        self.store.save_client(client_info)

    # -- authorization

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not redirect_allowed(str(params.redirect_uri), self.config.allowed_redirect_uris):
            raise AuthorizeError("invalid_request", "redirect_uri is not allowed")
        if params.resource and params.resource.rstrip("/") != self.config.resource_url.rstrip("/"):
            raise AuthorizeError("invalid_request", "Unknown resource")
        if not params.scopes:
            params = params.model_copy(update={"scopes": [SCOPE]})
        session = self.sessions.create(
            client_id=client.client_id, client_name=client.client_name, params=params
        )
        await self.maybe_sweep()
        return f"{self.config.public_base_url}/consent?{urlencode({'req': session.id})}"

    def complete_authorization(self, session: ConsentSession) -> str:
        """Create the grant for a verified session and return the client redirect URL."""
        assert session.params is not None and session.api_key and session.api_key_kek and session.agent
        params = session.params
        redirect_uri = str(params.redirect_uri)
        payload = {
            "api_key": session.api_key,
            "domain": self.config.freshdesk_domain,
            "agent_id": session.agent.id,
            "agent_name": session.agent.name,
            "agent_email": session.agent.email,
            "client_id": session.client_id,
            "client_name": session.client_name,
            "redirect_uri": redirect_uri,
            "redirect_host": urlsplit(redirect_uri).hostname,
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "scopes": params.scopes or [SCOPE],
            "resource": self.config.resource_url,
            "code_challenge": params.code_challenge,
        }
        code = self.store.create_grant(session.api_key_kek, payload, session.client_id or "")
        self.sessions.discard(session.id)
        return construct_redirect(redirect_uri, code=code, state=params.state)

    def deny_authorization(self, session: ConsentSession) -> str:
        assert session.params is not None
        self.sessions.discard(session.id)
        return construct_redirect(
            str(session.params.redirect_uri),
            error="access_denied",
            error_description="The user denied the request",
            state=session.params.state,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        grant = self.store.open_with_token(authorization_code, KIND_CODE)
        if grant is None or grant.doc.get("client_id") != client.client_id:
            return None
        p = grant.payload
        return AuthorizationCode(
            code=authorization_code,
            scopes=p["scopes"],
            expires_at=float(grant.doc["wraps"]["code"]["exp"]),
            client_id=p["client_id"],
            code_challenge=p["code_challenge"],
            redirect_uri=AnyUrl(p["redirect_uri"]),
            redirect_uri_provided_explicitly=p["redirect_uri_provided_explicitly"],
            resource=p["resource"],
        )

    def _token_response(self, issued: IssuedTokens) -> OAuthToken:
        return OAuthToken(
            access_token=issued.access_token,
            token_type="Bearer",
            expires_in=max(1, issued.access_expires_at - int(time.time())),
            scope=" ".join(issued.payload.get("scopes") or [SCOPE]),
            refresh_token=issued.refresh_token,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        issued = await self.store.exchange_code(authorization_code.code)
        if issued is None:
            raise TokenError("invalid_grant", "authorization code is invalid or was already used")
        logger.info("Issued tokens for a new grant (client %s)", client.client_id)
        return self._token_response(issued)

    # -- refresh tokens

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        grant = self.store.open_with_token(refresh_token, KIND_REFRESH)
        if grant is None or grant.doc.get("client_id") != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=grant.payload["client_id"],
            scopes=grant.payload["scopes"],
            expires_at=int(grant.doc["wraps"]["refresh"]["exp"]),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        issued = await self.store.rotate_refresh(refresh_token.token)
        if issued is None:
            raise TokenError("invalid_grant", "refresh token is invalid or was already used")
        return self._token_response(issued)

    # -- access tokens

    async def load_access_token(self, token: str) -> FreshdeskAccessToken | None:
        grant = self.store.open_with_token(token, KIND_ACCESS)
        if grant is None:
            return None
        await self.store.touch(grant)
        await self.maybe_sweep()
        p = grant.payload
        return FreshdeskAccessToken(
            token=token,
            client_id=p["client_id"],
            scopes=p["scopes"],
            expires_at=int(grant.doc["wraps"]["access"]["exp"]),
            resource=p["resource"],
            subject=str(p.get("agent_id")) if p.get("agent_id") is not None else None,
            grant_id=grant.grant_id,
            domain=p["domain"],
            api_key=p["api_key"],
        )

    # -- revocation

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        for kind in (KIND_ACCESS, KIND_REFRESH):
            parsed = parse_token(token.token, kind)
            if parsed:
                self.store.delete(parsed[0])
                return

    def revoke_grant(self, grant_id: str) -> None:
        """Drop a grant whose stored API key Freshdesk no longer accepts."""
        if self.store.delete(grant_id):
            logger.info("Revoked a grant because Freshdesk rejected its API key")


def construct_redirect(base: str, **params: str | None) -> str:
    parts = urlsplit(base)
    query = [(k, v) for k, v in params.items() if v is not None]
    extra = urlencode(query)
    new_query = f"{parts.query}&{extra}" if parts.query else extra
    return parts._replace(query=new_query).geturl()
