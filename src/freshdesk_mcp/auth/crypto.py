"""Cryptographic primitives for the grant store.

Envelope encryption: every grant has a random 256-bit data key (DEK) that encrypts the
grant payload with AES-256-GCM. The DEK is wrapped (encrypted) separately with a key
derived from each credential that may open the grant: the authorization code, the access
token, the refresh token and the Freshdesk API key itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32
NONCE_LEN = 12

# scrypt parameters for keys derived from a Freshdesk API key (~32 MiB, tens of ms)
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(Exception):
    """Raised when a ciphertext cannot be authenticated with the given key."""


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def random_id(nbytes: int) -> str:
    return b64e(secrets.token_bytes(nbytes))


def new_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def decrypt(key: bytes, box: dict[str, Any], aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), aad)
    except (InvalidTag, KeyError, ValueError, TypeError) as e:
        raise DecryptionError("decryption failed") from e


def encrypt_json(key: bytes, obj: Any, aad: bytes) -> dict[str, str]:
    return encrypt(key, json.dumps(obj, separators=(",", ":")).encode(), aad)


def decrypt_json(key: bytes, box: dict[str, Any], aad: bytes) -> Any:
    return json.loads(decrypt(key, box, aad))


def kek_from_token(server_secret: bytes, token_secret: bytes, purpose: str, grant_id: str) -> bytes:
    """Key-encryption key for a high-entropy token secret (code / access / refresh)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=server_secret,
        info=f"fdm-wrap-v1|{purpose}|{grant_id}".encode(),
    ).derive(token_secret)


def owner_id(server_secret: bytes, domain: str, api_key: str) -> str:
    """Stable, non-reversible identifier of the person owning an API key."""
    msg = f"owner-v1|{domain}|{api_key}".encode()
    return hmac.new(server_secret, msg, hashlib.sha256).hexdigest()


def kek_from_api_key(server_secret: bytes, owner: str, api_key: str) -> bytes:
    """Key-encryption key derived from the Freshdesk API key.

    scrypt slows down guessing; the server secret is mixed in so a copied data
    directory alone is not enough to mount an offline attack. The salt is derived from
    the owner id so one derivation opens all of that user's grants.
    """
    password = hmac.new(server_secret, f"apikey-v1|{api_key}".encode(), hashlib.sha256).digest()
    salt = hashlib.sha256(f"fdm-apikey-salt-v1|{owner}".encode()).digest()[:16]
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password)


def wrap_aad(grant_id: str, purpose: str) -> bytes:
    return f"fdm-dek-v1|{purpose}|{grant_id}".encode()


def payload_aad(grant_id: str) -> bytes:
    return f"fdm-payload-v1|{grant_id}".encode()
