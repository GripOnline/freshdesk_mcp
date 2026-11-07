"""Consent page (/consent) and self-service grant management (/grants)."""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from html import escape
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .freshdesk import FreshdeskUnavailable, InvalidApiKey, verify_api_key
from .provider import ConsentSession, ConsentSessions, FreshdeskOAuthProvider, is_loopback_redirect

logger = logging.getLogger(__name__)

MAX_ATTEMPTS_PER_SESSION = 5
IP_WINDOW = 300
MAX_ATTEMPTS_PER_IP = 20

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # No form-action directive: Chrome applies it to the redirect after "Approve".
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
    "frame-ancestors 'none'; base-uri 'none'",
}

KNOWN_CLIENT_HOSTS = {
    "claude.ai": "Claude",
    "claude.com": "Claude",
}


class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and hits[0] < now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > 10000:  # keep memory bounded
            for k in [k for k, v in self._hits.items() if not v]:
                del self._hits[k]
        return True


# ---------------------------------------------------------------------- rendering

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--text:#1d2330;--muted:#5d6675;--border:#dde1e7;--accent:#1f6feb;
--accent-text:#fff;--danger:#c62828;--warn-bg:#fff4e5;--warn-border:#f0b35b;--ok-bg:#eaf6ec}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--text:#e6e8eb;--muted:#9aa3ae;
--border:#323843;--accent:#4c8dff;--danger:#ff6b6b;--warn-bg:#3a2d15;--warn-border:#9c6b1c;--ok-bg:#1b3021}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:640px;margin:40px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
h1{font-size:22px;margin:0 0 8px}h2{font-size:17px;margin:0 0 12px}
p{margin:8px 0}.muted{color:var(--muted)}.small{font-size:13px}
label{display:block;font-weight:600;margin:16px 0 6px}
input[type=password]{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;
background:var(--bg);color:var(--text);font:inherit}
.actions{display:flex;gap:12px;margin-top:20px;flex-wrap:wrap}
button{font:inherit;padding:10px 18px;border-radius:8px;border:1px solid var(--border);cursor:pointer;
background:var(--card);color:var(--text)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-text)}
button.danger{color:var(--danger);padding:6px 12px;font-size:13px}
.error{color:var(--danger);font-weight:600}
.warn{background:var(--warn-bg);border:1px solid var(--warn-border);border-radius:8px;padding:12px;margin:12px 0}
.who{background:var(--ok-bg);border-radius:8px;padding:10px 12px;margin:12px 0}
.target{font-size:18px;font-weight:700;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
td.r{text-align:right}
code{font-size:13px}
a{color:var(--accent)}
"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<meta name='robots' content='noindex'><title>{escape(title)}</title><style>{CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )
    return HTMLResponse(html, status_code=status, headers=SECURITY_HEADERS)


def _fmt_time(ts: Any) -> str:
    if not ts:
        return "never"
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _hidden(session: ConsentSession) -> str:
    return (
        f"<input type='hidden' name='session' value='{escape(session.id)}'>"
        f"<input type='hidden' name='csrf' value='{escape(session.csrf)}'>"
    )


def _client_label(name: str | None, host: str | None) -> str:
    if host in KNOWN_CLIENT_HOSTS:
        return KNOWN_CLIENT_HOSTS[host]
    return name or "An MCP client"


def _destination(redirect_uri: str) -> tuple[str, bool]:
    """Return (display host, is_loopback)."""
    parts = urlsplit(redirect_uri)
    loopback = is_loopback_redirect(redirect_uri)
    host = parts.hostname or redirect_uri
    if loopback and parts.port:
        host = f"{host}:{parts.port}"
    return host, loopback


def _key_form(session: ConsentSession, domain: str, action_url: str, error: str | None) -> str:
    err = f"<p class='error'>{escape(error)}</p>" if error else ""
    return f"""
<form method='post' action='{escape(action_url)}' autocomplete='off'>
  {_hidden(session)}
  <input type='hidden' name='action' value='verify'>
  <label for='api_key'>Your Freshdesk API key</label>
  <input type='password' id='api_key' name='api_key' required autofocus autocomplete='off'
         spellcheck='false' minlength='8' maxlength='128'>
  <p class='muted small'>Find it in Freshdesk ({escape(domain)}): click your profile picture &rarr;
  <em>Profile settings</em> &rarr; <em>View API key</em>. The key is checked with Freshdesk and
  stored encrypted; it is not shown to the application you are connecting.</p>
  {err}
  <div class='actions'><button class='primary' type='submit'>Continue</button></div>
</form>"""


def _grants_table(session: ConsentSession, grants: list[tuple[str, dict]], action_url: str) -> str:
    if not grants:
        return "<p class='muted'>You have no active connections.</p>"
    rows = []
    for gid, p in grants:
        label = _client_label(p.get("client_name"), p.get("redirect_host"))
        dest, _ = _destination(p.get("redirect_uri") or "")
        rows.append(
            "<tr>"
            f"<td>{escape(label)}<br><span class='muted small'>{escape(dest)}</span></td>"
            f"<td>{escape(_fmt_time(p.get('granted_at')))}</td>"
            f"<td>{escape(_fmt_time(p.get('last_used_at')))}</td>"
            "<td class='r'>"
            f"<form method='post' action='{escape(action_url)}'>{_hidden(session)}"
            "<input type='hidden' name='action' value='revoke'>"
            f"<input type='hidden' name='grant' value='{escape(gid)}'>"
            "<button class='danger' type='submit'>Revoke</button></form></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Application / redirect domain</th><th>Granted</th><th>Last used</th><th></th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _who(session: ConsentSession, domain: str) -> str:
    agent = session.agent
    assert agent is not None
    email = f" ({escape(agent.email)})" if agent.email else ""
    return f"<div class='who'>Signed in to <strong>{escape(domain)}</strong> as <strong>{escape(agent.name)}</strong>{email}</div>"


# ---------------------------------------------------------------------- handlers


class ConsentRoutes:
    def __init__(self, provider: FreshdeskOAuthProvider):
        self.provider = provider
        self.config = provider.config
        self.ip_limiter = RateLimiter(MAX_ATTEMPTS_PER_IP, IP_WINDOW)
        # Separate from the OAuth consent sessions so visits to /grants cannot evict them
        self.manage_sessions = ConsentSessions(provider.config.consent_ttl)

    @property
    def domain(self) -> str:
        return self.config.freshdesk_domain

    # -- shared pieces

    def _expired(self, what: str) -> HTMLResponse:
        return _page(
            "Request expired",
            "<div class='card'><h1>This page has expired</h1>"
            f"<p>{escape(what)}</p></div>",
            status=400,
        )

    async def _list_grants(self, session: ConsentSession) -> list[tuple[str, dict]]:
        assert session.api_key_kek is not None
        return await asyncio.to_thread(self.provider.store.list_for_owner, session.api_key_kek)

    async def _verify(self, request: Request, session: ConsentSession, api_key: str) -> str | None:
        """Verify the key and attach it to the session. Returns an error message or None."""
        client_ip = request.client.host if request.client else "unknown"
        session.attempts += 1
        if session.attempts > MAX_ATTEMPTS_PER_SESSION or not self.ip_limiter.allow(client_ip):
            return "Too many attempts. Please wait a few minutes and start again."
        api_key = api_key.strip()
        try:
            agent = await verify_api_key(self.domain, api_key)
        except InvalidApiKey:
            return "Freshdesk did not accept this API key."
        except FreshdeskUnavailable:
            return "Freshdesk could not be reached to check the key. Please try again."
        session.api_key = api_key
        session.agent = agent
        session.api_key_kek = await asyncio.to_thread(self.provider.store.api_key_kek, api_key)
        return None

    @staticmethod
    def _check_csrf(session: ConsentSession, form: Any) -> bool:
        return hmac.compare_digest(str(form.get("csrf", "")), session.csrf)

    # -- /consent

    def _render_consent(self, session: ConsentSession, error: str | None = None, grants=None) -> HTMLResponse:
        assert session.params is not None
        redirect_uri = str(session.params.redirect_uri)
        dest, loopback = _destination(redirect_uri)
        host = urlsplit_host(redirect_uri)
        if host in KNOWN_CLIENT_HOSTS:
            label = KNOWN_CLIENT_HOSTS[host]
            header = f"<h1>Connect {escape(label)} to Freshdesk</h1>"
            who = escape(label)
        else:
            # The name of other clients is self-declared at registration: don't present it as verified
            header = "<h1>Connect an application to Freshdesk</h1>"
            if session.client_name:
                header += (
                    f"<p>The application calls itself <strong>{escape(session.client_name)}</strong>.</p>"
                )
            who = "This application"
        header += (
            f"<p class='muted'>{who} wants to use Freshdesk ({escape(self.domain)}) on your behalf, "
            "with your own Freshdesk permissions.</p>"
        )
        if not session.verified:
            body = f"<div class='card'>{header}{_key_form(session, self.domain, '/consent', error)}</div>"
            return _page("Connect to Freshdesk", body)

        warn = ""
        if loopback:
            warn = (
                "<div class='warn'><strong>Local application.</strong> You will be redirected to a program "
                "running on this computer. Only continue if you just started this connection yourself, "
                "for example from Claude Code.</div>"
            )
        err = f"<p class='error'>{escape(error)}</p>" if error else ""
        consent = f"""
<div class='card'>{header}{_who(session, self.domain)}
  <p>After you approve, you will be redirected to:</p>
  <p class='target'>{escape(dest)}</p>
  {warn}{err}
  <form method='post' action='/consent'>{_hidden(session)}
    <div class='actions'>
      <button class='primary' type='submit' name='action' value='approve'>Approve</button>
      <button type='submit' name='action' value='deny'>Deny</button>
    </div>
  </form>
  <p class='muted small'>You can review and revoke connections at any time on
  <a href='/grants'>{escape(self.config.public_base_url)}/grants</a>.</p>
</div>
<div class='card'><h2>Your existing connections</h2>{_grants_table(session, grants or [], '/consent')}</div>"""
        return _page("Approve access", consent)

    async def consent_get(self, request: Request) -> Response:
        session = self.provider.sessions.get(request.query_params.get("req"))
        if session is None or session.params is None:
            return self._expired("Go back to the application and start connecting again.")
        if session.verified:
            return self._render_consent(session, grants=await self._list_grants(session))
        return self._render_consent(session)

    async def consent_post(self, request: Request) -> Response:
        form = await request.form()
        session = self.provider.sessions.get(str(form.get("session", "")))
        if session is None or session.params is None:
            return self._expired("Go back to the application and start connecting again.")
        if not self._check_csrf(session, form):
            return _page("Error", "<div class='card'><h1>Invalid request</h1></div>", status=400)

        action = form.get("action")
        if action == "deny":
            return RedirectResponse(self.provider.deny_authorization(session), status_code=303, headers=SECURITY_HEADERS)

        if action == "verify":
            error = await self._verify(request, session, str(form.get("api_key", "")))
            if error:
                return self._render_consent(session, error=error)
            return self._render_consent(session, grants=await self._list_grants(session))

        if not session.verified:
            return self._render_consent(session, error="Please enter your API key first.")

        if action == "approve":
            # Synchronous on purpose: it also updates the in-memory session store (not thread-safe)
            redirect = self.provider.complete_authorization(session)
            return RedirectResponse(redirect, status_code=303, headers=SECURITY_HEADERS)

        if action == "revoke":
            assert session.api_key_kek is not None
            await asyncio.to_thread(
                self.provider.store.delete_for_owner, session.api_key_kek, str(form.get("grant", ""))
            )
            return self._render_consent(session, grants=await self._list_grants(session))

        return self._render_consent(session, error="Unknown action.")

    # -- /grants

    def _render_grants(self, session: ConsentSession, error: str | None = None, grants=None, notice=None):
        intro = (
            "<h1>Your Freshdesk connections</h1>"
            f"<p class='muted'>Applications you connected to Freshdesk ({escape(self.domain)}) through this server.</p>"
        )
        if not session.verified:
            body = f"<div class='card'>{intro}{_key_form(session, self.domain, '/grants', error)}</div>"
            return _page("Freshdesk connections", body)
        note = f"<p>{escape(notice)}</p>" if notice else ""
        body = (
            f"<div class='card'>{intro}{_who(session, self.domain)}{note}"
            f"{_grants_table(session, grants or [], '/grants')}</div>"
        )
        return _page("Freshdesk connections", body)

    async def grants_get(self, request: Request) -> Response:
        session = self.manage_sessions.create()
        return self._render_grants(session)

    async def grants_post(self, request: Request) -> Response:
        form = await request.form()
        session = self.manage_sessions.get(str(form.get("session", "")))
        if session is None:
            return self._expired("Please open this page again.")
        if not self._check_csrf(session, form):
            return _page("Error", "<div class='card'><h1>Invalid request</h1></div>", status=400)
        action = form.get("action")
        if action == "verify":
            error = await self._verify(request, session, str(form.get("api_key", "")))
            if error:
                return self._render_grants(session, error=error)
            return self._render_grants(session, grants=await self._list_grants(session))
        if not session.verified:
            return self._render_grants(session, error="Please enter your API key first.")
        if action == "revoke":
            assert session.api_key_kek is not None
            ok = await asyncio.to_thread(
                self.provider.store.delete_for_owner, session.api_key_kek, str(form.get("grant", ""))
            )
            notice = "The connection was revoked." if ok else None
            return self._render_grants(session, grants=await self._list_grants(session), notice=notice)
        return self._render_grants(session, grants=await self._list_grants(session))

    async def index(self, request: Request) -> Response:
        body = (
            "<div class='card'><h1>Freshdesk MCP server</h1>"
            f"<p>This server connects AI assistants such as Claude to Freshdesk ({escape(self.domain)}).</p>"
            f"<p>MCP endpoint: <code>{escape(self.config.resource_url)}</code></p>"
            "<p><a href='/grants'>Manage your connections</a></p></div>"
        )
        return _page("Freshdesk MCP", body)


def urlsplit_host(uri: str) -> str | None:
    return urlsplit(uri).hostname


def register_routes(mcp: Any, provider: FreshdeskOAuthProvider) -> ConsentRoutes:
    routes = ConsentRoutes(provider)
    mcp.custom_route("/consent", methods=["GET"])(routes.consent_get)
    mcp.custom_route("/consent", methods=["POST"])(routes.consent_post)
    mcp.custom_route("/grants", methods=["GET"])(routes.grants_get)
    mcp.custom_route("/grants", methods=["POST"])(routes.grants_post)
    mcp.custom_route("/", methods=["GET"])(routes.index)

    async def healthz(request: Request) -> Response:
        return Response("ok", media_type="text/plain")

    mcp.custom_route("/healthz", methods=["GET"])(healthz)
    return routes
