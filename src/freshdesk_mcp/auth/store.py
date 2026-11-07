"""Encrypted, file-based storage for OAuth grants and registered OAuth clients.

Grant file layout (``<data_dir>/grants/<grant_id>.json``)::

    {
      "v": 1,
      "owner": "<HMAC of domain + API key>",       # lets a returning user find their grants
      "client_id": "<OAuth client id>",            # public; used to clean up unused clients
      "payload": {"nonce": ..., "ct": ...},        # AES-GCM(DEK): API key + all metadata
      "wraps": {                                   # DEK encrypted per credential
        "code":    {"exp": ..., "nonce": ..., "ct": ...},   # only until the code is exchanged
        "access":  {"exp": ..., "nonce": ..., "ct": ...},
        "refresh": {"exp": ..., "nonce": ..., "ct": ...},
        "apikey":  {"nonce": ..., "ct": ...}
      }
    }

Tokens look like ``fdm_<kind>.<grant_id>.<secret>``. The grant id locates the file; the
secret is never stored and is the only input (besides the server secret) from which the
key that unwraps the DEK can be derived.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.shared.auth import OAuthClientInformationFull

from . import crypto
from .config import OAuthConfig

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
GRANT_ID_BYTES = 16
SECRET_BYTES = 32
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_TOKEN_RE = re.compile(r"^fdm_(code|at|rt)\.([A-Za-z0-9_-]{16,64})\.([A-Za-z0-9_-]{32,128})$")

KIND_CODE = "code"
KIND_ACCESS = "at"
KIND_REFRESH = "rt"
_WRAP_NAME = {KIND_CODE: "code", KIND_ACCESS: "access", KIND_REFRESH: "refresh"}

LAST_USED_RESOLUTION = 60  # seconds between "last used" writes for one grant


def make_token(kind: str, grant_id: str) -> tuple[str, bytes]:
    secret = secrets.token_bytes(SECRET_BYTES)
    return f"fdm_{kind}.{grant_id}.{crypto.b64e(secret)}", secret


def parse_token(token: str, expected_kind: str) -> tuple[str, bytes] | None:
    m = _TOKEN_RE.match(token or "")
    if not m or m.group(1) != expected_kind:
        return None
    try:
        return m.group(2), crypto.b64d(m.group(3))
    except ValueError:
        return None


@dataclass
class OpenGrant:
    """A grant decrypted with one of its credentials."""

    grant_id: str
    doc: dict[str, Any]
    dek: bytes
    payload: dict[str, Any]


@dataclass
class IssuedTokens:
    access_token: str
    refresh_token: str
    access_expires_at: int
    payload: dict[str, Any]


class GrantStore:
    def __init__(self, config: OAuthConfig):
        self.config = config
        self.secret = config.server_secret
        self.grants_dir = config.data_dir / "grants"
        self.clients_dir = config.data_dir / "clients"
        for d in (config.data_dir, self.grants_dir, self.clients_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:  # pragma: no cover - e.g. volume owned by another user
                pass
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ file helpers

    def _grant_path(self, grant_id: str) -> Path:
        if not _ID_RE.match(grant_id):
            raise ValueError("invalid grant id")
        return self.grants_dir / f"{grant_id}.json"

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            logger.warning("Unreadable store file %s", path.name)
            return None

    @staticmethod
    def _write_json(path: Path, doc: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _lock(self, grant_id: str) -> asyncio.Lock:
        lock = self._locks.get(grant_id)
        if lock is None:
            lock = self._locks[grant_id] = asyncio.Lock()
        return lock

    # ------------------------------------------------------------------ crypto helpers

    def _wrap(self, dek: bytes, kek: bytes, grant_id: str, purpose: str, exp: int | None) -> dict[str, Any]:
        box: dict[str, Any] = crypto.encrypt(kek, dek, crypto.wrap_aad(grant_id, purpose))
        if exp is not None:
            box["exp"] = exp
        return box

    def _token_kek(self, secret: bytes, purpose: str, grant_id: str) -> bytes:
        return crypto.kek_from_token(self.secret, secret, purpose, grant_id)

    def _encrypt_payload(self, dek: bytes, grant_id: str, payload: dict[str, Any]) -> dict[str, str]:
        return crypto.encrypt_json(dek, payload, crypto.payload_aad(grant_id))

    def _decrypt_payload(self, dek: bytes, grant_id: str, doc: dict[str, Any]) -> dict[str, Any]:
        return crypto.decrypt_json(dek, doc["payload"], crypto.payload_aad(grant_id))

    def owner_for(self, api_key: str) -> str:
        return crypto.owner_id(self.secret, self.config.freshdesk_domain, api_key)

    def api_key_kek(self, api_key: str) -> tuple[str, bytes]:
        """Derive (owner, KEK) for an API key. Slow (scrypt): call from a worker thread."""
        owner = self.owner_for(api_key)
        return owner, crypto.kek_from_api_key(self.secret, owner, api_key)

    # ------------------------------------------------------------------ grants

    def create_grant(
        self, api_key_kek: tuple[str, bytes], payload: dict[str, Any], client_id: str
    ) -> str:
        """Create a grant after consent and return the (single-use) authorization code."""
        owner, kek = api_key_kek
        grant_id = crypto.random_id(GRANT_ID_BYTES)
        dek = crypto.new_dek()
        code, code_secret = make_token(KIND_CODE, grant_id)
        now = int(time.time())
        payload = {**payload, "created_at": now, "granted_at": None, "last_used_at": None}
        doc = {
            "v": FORMAT_VERSION,
            "owner": owner,
            "client_id": client_id,
            "payload": self._encrypt_payload(dek, grant_id, payload),
            "wraps": {
                "code": self._wrap(
                    dek, self._token_kek(code_secret, "code", grant_id), grant_id, "code",
                    now + self.config.auth_code_ttl,
                ),
                "apikey": self._wrap(dek, kek, grant_id, "apikey", None),
            },
        }
        self._write_json(self._grant_path(grant_id), doc)
        return code

    def open_with_token(self, token: str, kind: str) -> OpenGrant | None:
        """Decrypt a grant with a code / access / refresh token. None if invalid or expired."""
        parsed = parse_token(token, kind)
        if parsed is None:
            return None
        grant_id, secret = parsed
        doc = self._read_json(self._grant_path(grant_id))
        if not doc or doc.get("v") != FORMAT_VERSION:
            return None
        purpose = _WRAP_NAME[kind]
        box = doc.get("wraps", {}).get(purpose)
        if not box:
            return None
        if box.get("exp") is not None and box["exp"] < time.time():
            return None
        try:
            dek = crypto.decrypt(self._token_kek(secret, purpose, grant_id), box, crypto.wrap_aad(grant_id, purpose))
            payload = self._decrypt_payload(dek, grant_id, doc)
        except crypto.DecryptionError:
            return None
        return OpenGrant(grant_id=grant_id, doc=doc, dek=dek, payload=payload)

    def _issue(self, grant: OpenGrant, drop: str) -> IssuedTokens:
        """Replace the access/refresh wraps with fresh tokens and drop the used credential."""
        gid = grant.grant_id
        now = int(time.time())
        access, access_secret = make_token(KIND_ACCESS, gid)
        refresh, refresh_secret = make_token(KIND_REFRESH, gid)
        access_exp = now + self.config.access_token_ttl
        refresh_exp = now + self.config.refresh_token_ttl
        wraps = dict(grant.doc["wraps"])
        wraps.pop(drop, None)
        wraps["access"] = self._wrap(grant.dek, self._token_kek(access_secret, "access", gid), gid, "access", access_exp)
        wraps["refresh"] = self._wrap(
            grant.dek, self._token_kek(refresh_secret, "refresh", gid), gid, "refresh", refresh_exp
        )
        payload = dict(grant.payload)
        if payload.get("granted_at") is None:
            payload["granted_at"] = now
        payload["refreshed_at"] = now
        doc = {**grant.doc, "wraps": wraps, "payload": self._encrypt_payload(grant.dek, gid, payload)}
        self._write_json(self._grant_path(gid), doc)
        return IssuedTokens(access, refresh, access_exp, payload)

    async def exchange_code(self, code: str) -> IssuedTokens | None:
        parsed = parse_token(code, KIND_CODE)
        if parsed is None:
            return None
        async with self._lock(parsed[0]):
            grant = self.open_with_token(code, KIND_CODE)  # re-check under the lock: single use
            if grant is None:
                return None
            return self._issue(grant, drop="code")

    async def rotate_refresh(self, refresh_token: str) -> IssuedTokens | None:
        parsed = parse_token(refresh_token, KIND_REFRESH)
        if parsed is None:
            return None
        async with self._lock(parsed[0]):
            grant = self.open_with_token(refresh_token, KIND_REFRESH)
            if grant is None:
                return None
            return self._issue(grant, drop="refresh")

    async def touch(self, grant: OpenGrant) -> None:
        """Record "last used", at most once per LAST_USED_RESOLUTION seconds."""
        now = int(time.time())
        last = grant.payload.get("last_used_at") or 0
        if now - last < LAST_USED_RESOLUTION:
            return
        async with self._lock(grant.grant_id):
            path = self._grant_path(grant.grant_id)
            doc = self._read_json(path)
            if not doc:
                return  # revoked meanwhile
            try:
                payload = self._decrypt_payload(grant.dek, grant.grant_id, doc)
            except crypto.DecryptionError:
                return
            payload["last_used_at"] = now
            doc["payload"] = self._encrypt_payload(grant.dek, grant.grant_id, payload)
            self._write_json(path, doc)
            grant.payload["last_used_at"] = now

    def delete(self, grant_id: str) -> bool:
        try:
            self._grant_path(grant_id).unlink()
        except FileNotFoundError:
            return False
        self._locks.pop(grant_id, None)
        return True

    def list_for_owner(self, api_key_kek: tuple[str, bytes]) -> list[tuple[str, dict[str, Any]]]:
        """Decrypt all grants belonging to an API key (newest first)."""
        owner, kek = api_key_kek
        result = []
        for path in self.grants_dir.glob("*.json"):
            doc = self._read_json(path)
            if not doc or doc.get("owner") != owner:
                continue
            gid = path.stem
            box = doc.get("wraps", {}).get("apikey")
            if not box or "code" in doc.get("wraps", {}):
                continue  # consent given but never completed: not a usable connection
            try:
                dek = crypto.decrypt(kek, box, crypto.wrap_aad(gid, "apikey"))
                payload = self._decrypt_payload(dek, gid, doc)
            except crypto.DecryptionError:
                continue
            result.append((gid, payload))
        result.sort(key=lambda item: item[1].get("granted_at") or 0, reverse=True)
        return result

    def delete_for_owner(self, api_key_kek: tuple[str, bytes], grant_id: str) -> bool:
        """Revoke a grant, but only if it belongs to (and opens with) this API key."""
        owner, kek = api_key_kek
        try:
            path = self._grant_path(grant_id)
        except ValueError:
            return False
        doc = self._read_json(path)
        if not doc or doc.get("owner") != owner:
            return False
        try:
            crypto.decrypt(kek, doc["wraps"]["apikey"], crypto.wrap_aad(grant_id, "apikey"))
        except (crypto.DecryptionError, KeyError):
            return False
        return self.delete(grant_id)

    # ------------------------------------------------------------------ maintenance

    def sweep(self) -> int:
        """Delete grants that can no longer be used and long-unused client registrations."""
        now = time.time()
        removed = 0
        active_clients: set[str] = set()
        for path in self.grants_dir.glob("*.json"):
            doc = self._read_json(path)
            if doc is None:
                continue
            wraps = doc.get("wraps", {})
            usable = [w for name, w in wraps.items() if name in ("code", "refresh") and w.get("exp", 0) > now]
            if not usable:
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:
                    pass
                continue
            active_clients.add(doc.get("client_id", ""))
        for path in self.grants_dir.glob(".tmp-*"):
            if now - path.stat().st_mtime > 3600:
                path.unlink(missing_ok=True)
        for path in self.clients_dir.glob("*.json"):
            doc = self._read_json(path)
            if doc is None:
                continue
            client_id = doc.get("client_id")
            issued = doc.get("client_id_issued_at") or 0
            if client_id not in active_clients and now - issued > self.config.client_retention:
                path.unlink(missing_ok=True)
        return removed

    # ------------------------------------------------------------------ clients (public data)

    def _client_path(self, client_id: str) -> Path:
        if not _ID_RE.match(client_id):
            raise ValueError("invalid client id")
        return self.clients_dir / f"{client_id}.json"

    def save_client(self, client: OAuthClientInformationFull) -> None:
        assert client.client_id
        self._write_json(self._client_path(client.client_id), client.model_dump(mode="json", exclude_none=True))

    def load_client(self, client_id: str) -> dict[str, Any] | None:
        try:
            return self._read_json(self._client_path(client_id))
        except ValueError:
            return None
