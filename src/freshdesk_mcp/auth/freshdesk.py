"""Verification of Freshdesk API keys against the Freshdesk API."""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

_API_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")


class InvalidApiKey(Exception):
    pass


class FreshdeskUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Agent:
    id: int | None
    name: str
    email: str


def basic_auth_header(api_key: str) -> str:
    return "Basic " + base64.b64encode(f"{api_key}:X".encode()).decode()


def looks_like_api_key(value: str) -> bool:
    return bool(_API_KEY_RE.match(value or ""))


async def verify_api_key(domain: str, api_key: str, *, timeout: float = 10.0) -> Agent:
    """Return the agent owning ``api_key`` or raise InvalidApiKey / FreshdeskUnavailable."""
    if not looks_like_api_key(api_key):
        raise InvalidApiKey("malformed")
    url = f"https://{domain}/api/v2/agents/me"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                url, headers={"Authorization": basic_auth_header(api_key)}, follow_redirects=False
            )
    except httpx.HTTPError as e:
        logger.warning("Freshdesk key verification failed: %s", type(e).__name__)
        raise FreshdeskUnavailable(str(type(e).__name__)) from e

    if response.status_code in (401, 403):
        raise InvalidApiKey(str(response.status_code))
    if response.status_code != 200:
        logger.warning("Unexpected status %s from Freshdesk /agents/me", response.status_code)
        raise FreshdeskUnavailable(f"HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as e:
        raise FreshdeskUnavailable("invalid JSON") from e
    contact = data.get("contact") or {}
    return Agent(
        id=data.get("id"),
        name=str(contact.get("name") or data.get("name") or "Unknown agent"),
        email=str(contact.get("email") or data.get("email") or ""),
    )
