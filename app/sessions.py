# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""HMAC-signed session cookie. No server-side state, so 'logout' just means
'clear the cookie' — fine for a single-server install. If we ever need
revocable sessions, swap this for a sessions table."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

COOKIE_NAME = "pp_session"
DEFAULT_TTL = 60 * 60 * 8       # 8 hours

# Length of the per-session CSRF token. 32 random bytes → 43 base64url
# characters. Stored inside the signed session payload so an attacker
# cannot forge a token without also forging the HMAC.
CSRF_TOKEN_BYTES = 32


def new_csrf_token() -> str:
    """Generate a fresh, URL-safe CSRF token bound to a single session."""
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def _secret() -> bytes:
    s = os.environ.get("APP_SECRET", "")
    if not s or len(s) < 32:
        raise RuntimeError(
            "APP_SECRET is missing or too short. Run ./pentest.sh bootstrap "
            "to regenerate the env file."
        )
    return s.encode()


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload: dict, ttl: int = DEFAULT_TTL) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + ttl
    raw = _b64u_encode(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify(cookie: Optional[str]) -> Optional[dict]:
    if not cookie or "." not in cookie:
        return None
    body, sig = cookie.rsplit(".", 1)
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64u_decode(body))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
