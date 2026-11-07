# Design: public HTTPS deployment with per-user OAuth (Freshdesk API key consent)

Status: **implemented**

Decisions: Freshdesk domain fixed via `FRESHDESK_DOMAIN`; tokens 8 h access / 90-day sliding
refresh; loopback (Claude Code) redirects allowed with a warning; Docker behind a reverse proxy,
single instance.

Implementation notes (where the build differs from or adds to the plan below):
- SDK: `mcp>=1.30,<2` (latest 1.x) rather than 2.x, so the existing `FastMCP` code keeps working.
  `http_server.configure_oauth` attaches the provider to the module-level instance.
- Token format is `fdm_<kind>.<grant_id>.<secret>`: `.` separators, because base64url contains `_`.
- The scrypt salt for the API-key wrap is derived from the owner id, so listing a user's grants
  needs only one scrypt derivation.
- `/grants` keeps its own session store, so visits to it cannot evict OAuth consent sessions.
- The Streamable HTTP transport is stateless, so MCP sessions survive restarts.
- The names of non-Claude clients (self-declared at DCR) are shown as unverified.
- Tests: `tests/test_oauth.py` (full flow, Freshdesk mocked).

## Goal

- The server starts without a central `FRESHDESK_API_KEY`.
- It is served over Streamable HTTP on a public HTTPS URL. An organisation adds it once as a
  custom connector in Claude, and each member connects it themselves.
- On connect, the MCP client (Claude) is sent through an OAuth 2.1 flow. Instead of logging in
  with a password, the user enters **their own Freshdesk API key**. The server checks the key
  against Freshdesk, then shows a consent screen naming the domain the user will be sent back to.
- The API key is stored on disk only in encrypted form. You need either the issued token or
  the API key itself to decrypt it.
- A user who returns with the same API key sees their existing grants (client, redirect domain,
  granted at, last used) and can revoke them.
- Local stdio mode with `FRESHDESK_API_KEY` env vars keeps working as before.

## Feasibility (verified against docs and SDK)

| Requirement | Status |
|---|---|
| Claude custom connectors support per-user OAuth | Yes. "OAuth 2.0: each user signs in to your service with their own account when they connect." |
| Client registration | Claude uses DCR (RFC 7591) or CIMD. We implement DCR, which the MCP Python SDK provides. |
| Discovery | `401` + `WWW-Authenticate: Bearer resource_metadata=...` (RFC 9728) + RFC 8414 AS metadata. The SDK provides both. |
| PKCE S256 | Required by Claude. The SDK enforces it. |
| Callback URLs | `https://claude.ai/api/mcp/auth_callback` (claude.ai, Desktop, mobile, Cowork). Claude Code uses a loopback `http://localhost:<any>/callback` or `http://127.0.0.1:<any>/callback`. Also allow the `claude.com` variant for the future. |
| Refresh tokens | Claude refreshes on `401` and proactively. Public clients **must** get rotated refresh tokens. Invalid refresh → `invalid_grant`. |
| Latency | Token/registration endpoints must answer within 10s (30s for refresh). |
| Consent screen | The MCP spec requires the consent screen to show the redirect URI's hostname, plus a warning when only loopback URIs are registered. This matches the requirement. |
| Custom consent UI in the SDK | `OAuthAuthorizationServerProvider.authorize()` returns any URL. We redirect to our own `/consent` page (a custom route) and finish the flow there. |
| Key verification | `GET https://<domain>/api/v2/agents/me` with Basic auth `<key>:X` returns 200 with the agent's name and email, or 401. |
| Egress | Anthropic calls the MCP server from `160.79.104.0/21`. The consent page is opened by the user's own browser. |

Conclusion: the design works with Claude. The main dependency change is upgrading `mcp`
from the locked 1.4.1 (no auth-server support, no Streamable HTTP) to a current release.

## Architecture

```
Claude ──(DCR, /authorize, /token, Bearer)──► freshdesk-mcp (Starlette via MCP SDK)
                                                 ├─ /mcp                 Streamable HTTP, bearer-protected
                                                 ├─ /.well-known/*       SDK metadata
                                                 ├─ /register /authorize /token /revoke   SDK
                                                 ├─ /consent  (GET/POST) custom routes, our HTML
                                                 ├─ /grants   (GET/POST) self-service grant management
                                                 └─ GrantStore (encrypted files in DATA_DIR)
User browser ──► /consent ──► server checks key on https://<domain>/api/v2/agents/me
```

### Code changes

1. **Dependency**: `mcp>=2.x` (`FastMCP` → `MCPServer` rename, see the SDK migration guide)
   or the latest `mcp<2`. Decide during build. Add `cryptography`. Requires Python 3.10+, which the project already requires.
2. **Credential resolution**: replace the 61 inline uses of
   `FRESHDESK_API_KEY` / `FRESHDESK_DOMAIN` with one helper,
   `_fd_request(method, path, **kw)` or at least `_auth_headers()` + `_base_url()`:
   - HTTP mode: `get_access_token()` (SDK auth context) → our `FreshdeskAccessToken`, which
     carries the decrypted API key in memory for that request only.
   - stdio mode: env vars, as today.
   - A Freshdesk `401` during a tool call marks the grant invalid (the key was rotated or the
     agent deactivated). The grant is deleted so the next MCP request gets `401`, and Claude
     asks the user to reconnect.
3. **`main()`**: `--transport stdio|http` (default stdio, for backwards compatibility),
   `--host`, `--port`. Only `FRESHDESK_DOMAIN` is needed in HTTP mode; the API key is not.
4. **New modules**: `auth/provider.py` (OAuth provider), `auth/store.py` (encrypted grant
   store), `auth/consent.py` (routes + HTML templates), `auth/crypto.py`.
5. **Dockerfile / smithery.yaml / README**: HTTP mode, a persistent volume for `DATA_DIR`,
   reverse-proxy/TLS notes.

### Configuration (HTTP mode)

| Env | Purpose |
|---|---|
| `FRESHDESK_DOMAIN` | e.g. `grip.freshdesk.com`. Pinned server-side (see open questions). |
| `PUBLIC_BASE_URL` | e.g. `https://freshdesk-mcp.example.nl`. OAuth issuer and resource URL. |
| `FRESHDESK_MCP_DATA_DIR` | Persistent directory for grants and client registrations. |
| `FRESHDESK_MCP_SECRET` | 32+ byte server secret (pepper). Mixed into every KDF and owner hash, so a copied data dir alone is not enough to attack. |
| `ALLOWED_REDIRECT_URIS` | Default: claude.ai/claude.com callbacks + loopback. DCR rejects other redirect URIs. |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | Defaults: 8h / 90 days (sliding on refresh). |

## Cryptographic design (envelope encryption)

Each grant has a random 256-bit **data key (DEK)**. The secret part of the grant is encrypted once
with the DEK (AES-256-GCM). The DEK is then **wrapped** (encrypted) several times, once per "key
holder":

| Wrap | KEK derived from | Purpose |
|---|---|---|
| `code` | authorization code secret (HKDF-SHA256, salt = server secret) | Only between consent and the token exchange. Removed afterwards. |
| `access` | access token secret (HKDF) | Every MCP request decrypts the API key. |
| `refresh` | refresh token secret (HKDF) | Token refresh: unwrap the DEK, issue new tokens, re-wrap, drop the old wraps (rotation). |
| `apikey` | Freshdesk API key (scrypt, per-file salt, + server secret) | User returns to `/consent` or `/grants` with the same key → list and revoke grants. |

Token format: `fdm_at_<grant_id>_<secret>` / `fdm_rt_<grant_id>_<secret>` / code
`fdm_code_<grant_id>_<secret>` (`grant_id` = 128-bit random, `secret` = 256-bit random, base64url).
The `grant_id` locates the file. The `secret` is the only thing that can unwrap the DEK, and
AES-GCM authentication proves it is valid. No token or hash of a token is stored on disk.

File `DATA_DIR/grants/<grant_id>.json`:

```json
{
  "v": 1,
  "owner": "<HMAC-SHA256(server_secret, domain + ':' + api_key)>",
  "payload": "<AES-GCM(DEK) of {api_key, domain, agent_id, agent_name, agent_email,
               client_id, client_name, redirect_uri, redirect_host, scopes, resource,
               granted_at, last_used_at, access_expires_at, refresh_expires_at}>",
  "wraps": {
    "access":  {"exp": 1731000000, "nonce": "...", "ct": "..."},
    "refresh": {"exp": 1738000000, "nonce": "...", "ct": "..."},
    "apikey":  {"salt": "...", "nonce": "...", "ct": "..."}
  }
}
```

- Only `owner` is plaintext. It lets `/grants` find a user's files without decrypting
  everything, and it can only be computed by someone who has the API key. Redirect domain,
  dates and last-used are **inside** the encrypted payload, because both the token holder and
  the key holder can decrypt it.
- `last_used_at` is updated when a token is loaded, throttled to once per 60s. The file is
  written atomically (temp file + `os.replace`) under a per-grant lock.
- Revoking deletes the file, which immediately invalidates the access and refresh tokens.
  The SDK `/revoke` endpoint does the same.
- Expired grants (refresh expired, or code never exchanged after 10 min) are purged by a
  periodic sweep. The sweep only needs the plaintext `exp` fields.

**What this does and does not protect against** (state plainly in the README): disk theft,
backups and other people with filesystem access cannot read API keys without a token or the
key itself. The running server process does see the key in memory during each request. Encryption
at rest is not a defence against someone who can change the server code.

## OAuth flow

1. Claude → `POST /register` (DCR). The SDK validates the request. Our `register_client`
   rejects redirect URIs outside `ALLOWED_REDIRECT_URIS`, then persists to
   `DATA_DIR/clients/<client_id>.json`. Client data is public, so it is not encrypted.
2. Claude → `GET /authorize?...&code_challenge=...&state=...&resource=...`. The SDK validates
   the client, redirect URI and PKCE. `provider.authorize()` stores a *pending request* in memory
   (10 min TTL, random 256-bit id) and returns `/consent?req=<id>`.
3. **Consent page 1** (`GET /consent`): "Connect *{client_name}* to Freshdesk ({domain})". It has an
   API key field, a link to "where to find your API key" (Freshdesk → Profile settings →
   View API key), and a CSRF token tied to the pending request.
4. `POST /consent` (action=verify): rate-limited per IP and per pending request. Calls
   `/api/v2/agents/me`. On 401 the page shows "invalid API key". On success the key and agent
   info are attached to the pending request (memory only).
5. **Consent page 2**:
   - "Signed in as **Jane Doe** (jane@…)".
   - "**Claude** wants to access Freshdesk on your behalf with your permissions. After you
     approve, you will be redirected to **claude.ai**." This shows the redirect host. For a
     loopback redirect it shows "a local application on this computer (localhost)" with a warning.
   - Buttons: **Approve** / **Deny**.
   - Below: "Your existing connections", a table of client, redirect domain, granted, last used,
     and a **Revoke** button. It is built by decrypting the user's grants via the `apikey` wrap.
6. Approve → create the grant file with `code` + `apikey` wraps → `302 redirect_uri?code=…&state=…`.
   Deny → `302 redirect_uri?error=access_denied&state=…`.
7. Claude → `POST /token` (authorization_code + PKCE verifier). The SDK verifies PKCE and calls
   `load_authorization_code` / `exchange_authorization_code`, which unwraps with the code,
   adds the access and refresh wraps, and removes the code wrap. The code is single-use.
8. Claude → `/mcp` with `Authorization: Bearer fdm_at_…`. `load_access_token` unwraps and returns a
   `FreshdeskAccessToken` (subject = agent id). Tools use that request's key.
9. Refresh → rotation as described above. A missing or expired grant gives `invalid_grant`.

`/grants` is the same as page 1 + the table, without a pending OAuth request, so a user can manage
grants without starting a connection from Claude.

Web hardening: CSRF tokens, `X-Frame-Options: DENY` / CSP `frame-ancestors 'none'`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Never log keys, tokens or form bodies.
Constant-time comparisons. The API key field uses `autocomplete="off"`.

## Operational notes and limits

- **Single instance**: pending consent requests are held in memory. If the server restarts during
  the few minutes a user is on the consent screen, they simply retry. For multiple replicas, move
  pending requests to the encrypted store or use sticky sessions. Out of scope for now.
- **Persistent volume** needed for `DATA_DIR`. Losing it means every user reconnects, but nothing
  leaks.
- **TLS**: terminate at a reverse proxy (Caddy, nginx, Traefik). `PUBLIC_BASE_URL` must match
  the URL configured in Claude exactly, including the path (`/mcp`).
- **DCR growth**: Claude may register a new client on each fresh connection. Sweep clients that
  have had no grants for 30 days.
- **Key rotation in Freshdesk**: old grants keep the old key and fail on the next call → the grant
  is deleted → Claude asks the user to reconnect. The new key cannot list grants made with the old
  key, because the owner hash differs. Those grants are cleaned up lazily or when they expire.
- **Permissions**: the connection has exactly the agent's Freshdesk permissions, including the
  existing destructive tools such as `delete_ticket`. There are no OAuth scopes beyond a single
  default scope.
- Users have reported issues with the claude.ai web connector flow at the Connect step
  (anthropics/claude-ai-mcp issues 215/313/410). Test with claude.ai and Claude Desktop
  early.

## Test plan

- Unit: crypto round-trips (each wrap unwraps the same DEK; a wrong secret fails), owner hash,
  atomic writes, expiry sweep, rotation invalidating old refresh tokens.
- Provider: a full OAuth flow against the SDK's Starlette app with `httpx.ASGITransport`. DCR →
  authorize → consent (Freshdesk mocked) → token → `/mcp` tools/list → refresh → revoke → 401.
- Manual: MCP Inspector, then Claude as a custom connector (org-level), with two users
  connecting with different keys, and revoke from `/grants` while Claude is connected.

## Open questions

1. Freshdesk domain pinned server-side (recommended for an org deployment) or entered by the user
   on the consent page?
2. Token lifetimes: 8h access / 90-day sliding refresh OK?
3. Allow Claude Code / loopback redirects (default yes, with a warning), or only claude.ai/claude.com?
4. Deployment target (Docker + reverse proxy, single instance)?
