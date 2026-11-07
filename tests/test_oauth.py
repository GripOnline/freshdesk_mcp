"""End-to-end tests for HTTP mode: DCR -> authorize -> consent -> token -> MCP -> refresh -> revoke.

Freshdesk is mocked; no network access is needed.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import secrets
from html import unescape
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from freshdesk_mcp import credentials, server
from freshdesk_mcp.auth import consent as consent_mod
from freshdesk_mcp.auth.config import OAuthConfig
from freshdesk_mcp.auth.freshdesk import Agent, InvalidApiKey
from freshdesk_mcp import http_server

BASE = "https://mcp.example.test"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
GOOD_KEY = "GoodKey1234567890abc"
OTHER_KEY = "OtherKey987654321xyz"
DOMAIN = "acme.freshdesk.com"


class FakeFreshdesk:
    """Mocks /agents/me (key verification) and /tickets/<id> for tool calls."""

    def __init__(self):
        self.valid_keys = {GOOD_KEY: Agent(1, "Jane Doe", "jane@acme.test"), OTHER_KEY: Agent(2, "Bob", "bob@acme.test")}
        self.seen_auth: list[str] = []

    async def verify(self, domain: str, api_key: str) -> Agent:
        assert domain == DOMAIN
        if api_key not in self.valid_keys:
            raise InvalidApiKey("401")
        return self.valid_keys[api_key]

    def handler(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        self.seen_auth.append(auth)
        key = base64.b64decode(auth.removeprefix("Basic ")).decode().removesuffix(":X")
        if key not in self.valid_keys:
            return httpx.Response(401, json={"code": "invalid_credentials"})
        m = re.match(r"^/api/v2/tickets/(\d+)$", request.url.path)
        if m:
            return httpx.Response(200, json={"id": int(m.group(1)), "subject": f"Ticket for {key[:4]}"})
        return httpx.Response(404)


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = FakeFreshdesk()
    monkeypatch.setattr(consent_mod, "verify_api_key", fake.verify)
    monkeypatch.setattr(http_server, "verify_api_key", fake.verify)
    monkeypatch.setattr(credentials.state, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(credentials.state, "oauth_mode", False)
    monkeypatch.setattr(credentials.state, "on_key_rejected", None)

    config = OAuthConfig(
        freshdesk_domain=DOMAIN,
        public_base_url=BASE,
        server_secret=b"s" * 48,
        data_dir=tmp_path / "data",
    )
    mcp = FastMCP("test")
    mcp.add_tool(server.get_ticket)
    app = http_server.build_http_app(mcp, config)
    return app, fake, config


@contextlib.asynccontextmanager
async def running(env):
    """Run the app's lifespan inside the test task (async yield fixtures would exit it elsewhere)."""
    from sse_starlette.sse import AppStatus

    AppStatus.should_exit_event = None  # sse_starlette keeps a global Event bound to one event loop
    app = env[0]
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("203.0.113.5", 1234))
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
            yield c


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def hidden(html: str, name: str) -> str:
    m = re.search(rf"name='{name}' value='([^']*)'", html)
    assert m, f"no hidden field {name}"
    return unescape(m.group(1))


async def register(c, redirect=CALLBACK):
    r = await c.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": "Claude",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    return r


async def start_authorize(c, client_id, redirect=CALLBACK):
    verifier, challenge = pkce()
    r = await c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "resource": f"{BASE}/mcp",
        },
    )
    assert r.status_code == 302, r.text
    return r.headers["location"], verifier


async def full_connect(c, api_key=GOOD_KEY):
    reg = await register(c)
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    location, verifier = await start_authorize(c, client_id)
    page = await c.get(location)
    r = await c.post(
        "/consent",
        data={"session": hidden(page.text, "session"), "csrf": hidden(page.text, "csrf"), "action": "verify", "api_key": api_key},
    )
    assert "Signed in to" in r.text
    r = await c.post(
        "/consent", data={"session": hidden(r.text, "session"), "csrf": hidden(r.text, "csrf"), "action": "approve"}
    )
    assert r.status_code == 303
    q = parse_qs(urlsplit(r.headers["location"]).query)
    tok = await c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": q["code"][0],
            "redirect_uri": CALLBACK,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200, tok.text
    return client_id, tok.json()


def sse_json(resp: httpx.Response) -> dict:
    if resp.headers.get("content-type", "").startswith("application/json"):
        return resp.json()
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:])
    raise AssertionError(resp.text)


MCP_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


async def call_tool(c, token, name, args):
    headers = {**MCP_HEADERS, "authorization": f"Bearer {token}"}
    init = await c.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        },
    )
    if init.status_code != 200:
        return init
    r = await c.post(
        "/mcp", headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}},
    )
    return r


# ---------------------------------------------------------------------- tests


async def test_discovery_and_401(env):
    async with running(env) as client:
        r = await client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]
        prm = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"] == f"{BASE}/mcp"
        assert prm["authorization_servers"][0].rstrip("/") == BASE
        asm = (await client.get("/.well-known/oauth-authorization-server")).json()
        assert asm["registration_endpoint"] == f"{BASE}/register"
        assert asm["code_challenge_methods_supported"] == ["S256"]


async def test_registration_rejects_unknown_redirects(env):
    async with running(env) as client:
        r = await register(client, "https://evil.example/callback")
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"


async def test_full_flow_tool_call_refresh_and_revoke(env):
    async with running(env) as client:
        _, fake, config = env
        client_id, tokens = await full_connect(client)
        assert tokens["token_type"].lower() == "bearer" and tokens["refresh_token"]

        # The API key must not be stored in plaintext anywhere
        for f in (config.data_dir / "grants").glob("*.json"):
            raw = f.read_text()
            assert GOOD_KEY not in raw and "Jane" not in raw and "claude.ai" not in raw

        # Tool call runs with the user's own key
        r = await call_tool(client, tokens["access_token"], "get_ticket", {"ticket_id": 42})
        assert r.status_code == 200, r.text
        result = sse_json(r)["result"]
        assert "Ticket for Good" in json.dumps(result)
        assert fake.seen_auth[-1] == "Basic " + base64.b64encode(f"{GOOD_KEY}:X".encode()).decode()

        # Refresh rotates both tokens; old ones stop working
        r = await client.post(
            "/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id}
        )
        assert r.status_code == 200, r.text
        new = r.json()
        r = await client.post(
            "/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id}
        )
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        assert (await call_tool(client, tokens["access_token"], "get_ticket", {"ticket_id": 1})).status_code == 401
        assert (await call_tool(client, new["access_token"], "get_ticket", {"ticket_id": 1})).status_code == 200

        # The /grants page lists the connection (with last-used) and can revoke it
        page = await client.get("/grants")
        r = await client.post(
            "/grants",
            data={"session": hidden(page.text, "session"), "csrf": hidden(page.text, "csrf"), "action": "verify", "api_key": GOOD_KEY},
        )
        assert "Jane Doe" in r.text and "claude.ai" in r.text and "Revoke" in r.text
        assert "never" not in r.text.split("<tbody>")[1]  # last used is filled in
        grant_id = hidden(r.text, "grant")
        # Another user's key cannot see or revoke it
        page2 = await client.get("/grants")
        r2 = await client.post(
            "/grants",
            data={"session": hidden(page2.text, "session"), "csrf": hidden(page2.text, "csrf"), "action": "verify", "api_key": OTHER_KEY},
        )
        assert "no active connections" in r2.text
        r2 = await client.post(
            "/grants",
            data={"session": hidden(page2.text, "session"), "csrf": hidden(page2.text, "csrf"), "action": "revoke", "grant": grant_id},
        )
        assert (await call_tool(client, new["access_token"], "get_ticket", {"ticket_id": 1})).status_code == 200

        r = await client.post(
            "/grants",
            data={"session": hidden(r.text, "session"), "csrf": hidden(r.text, "csrf"), "action": "revoke", "grant": grant_id},
        )
        assert "revoked" in r.text
        assert (await call_tool(client, new["access_token"], "get_ticket", {"ticket_id": 1})).status_code == 401


async def test_code_is_single_use_and_needs_pkce(env):
    async with running(env) as client:
        reg = await register(client)
        client_id = reg.json()["client_id"]
        location, verifier = await start_authorize(client, client_id)
        page = await client.get(location)
        r = await client.post(
            "/consent",
            data={"session": hidden(page.text, "session"), "csrf": hidden(page.text, "csrf"), "action": "verify", "api_key": GOOD_KEY},
        )
        r = await client.post("/consent", data={"session": hidden(r.text, "session"), "csrf": hidden(r.text, "csrf"), "action": "approve"})
        code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK, "client_id": client_id}
        bad = await client.post("/token", data={**data, "code_verifier": "x" * 50})
        assert bad.status_code == 400
        ok = await client.post("/token", data={**data, "code_verifier": verifier})
        assert ok.status_code == 200
        again = await client.post("/token", data={**data, "code_verifier": verifier})
        assert again.status_code == 400 and again.json()["error"] == "invalid_grant"


async def test_consent_rejects_bad_key_csrf_and_deny(env):
    async with running(env) as client:
        reg = await register(client)
        location, _ = await start_authorize(client, reg.json()["client_id"])
        page = await client.get(location)
        assert "Connect Claude to Freshdesk" in page.text
        assert page.headers["x-frame-options"] == "DENY"
        sid, csrf = hidden(page.text, "session"), hidden(page.text, "csrf")
        r = await client.post("/consent", data={"session": sid, "csrf": csrf, "action": "verify", "api_key": "WrongKey12345"})
        assert "did not accept" in r.text
        r = await client.post("/consent", data={"session": sid, "csrf": "nope", "action": "approve"})
        assert r.status_code == 400
        r = await client.post("/consent", data={"session": sid, "csrf": csrf, "action": "approve"})
        assert "enter your API key first" in r.text
        r = await client.post("/consent", data={"session": sid, "csrf": csrf, "action": "deny"})
        assert r.status_code == 303
        q = parse_qs(urlsplit(r.headers["location"]).query)
        assert q["error"] == ["access_denied"] and q["state"] == ["xyz"]


async def test_loopback_redirect_any_port_with_warning(env):
    async with running(env) as client:
        reg = await register(client, "http://localhost:33418/callback")
        assert reg.status_code == 201, reg.text
        location, _ = await start_authorize(client, reg.json()["client_id"], "http://localhost:5555/callback")
        page = await client.get(location)
        r = await client.post(
            "/consent",
            data={"session": hidden(page.text, "session"), "csrf": hidden(page.text, "csrf"), "action": "verify", "api_key": GOOD_KEY},
        )
        assert "localhost:5555" in r.text and "Local application" in r.text


async def test_rejected_key_revokes_grant(env):
    async with running(env) as client:
        _, fake, _ = env
        _, tokens = await full_connect(client)
        del fake.valid_keys[GOOD_KEY]  # user regenerated their key in Freshdesk
        r = await call_tool(client, tokens["access_token"], "get_ticket", {"ticket_id": 1})
        assert r.status_code == 200  # this call reports the Freshdesk error...
        assert (await call_tool(client, tokens["access_token"], "get_ticket", {"ticket_id": 1})).status_code == 401  # ...then reconnect
