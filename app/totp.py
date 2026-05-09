# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""TOTP (RFC 6238) enrolment and verification.

Per-user opt-in second factor. The flow:

  1. /security GET, no enrolment yet
       → generate_secret() returns a fresh 32-character base32 string and
         the page renders it as a QR (otpauth_uri()) that the user scans
         in Google Authenticator / Authy / 1Password / etc. The secret is
         held in the user's signed session payload (not yet persisted)
         so an abandoned enrolment leaves the database untouched.

  2. /security POST verify
       → user types the 6-digit code their authenticator app shows.
         verify_code() checks it against the in-flight secret with a
         ±1 step (±30 s) skew window. On success, the route persists
         the secret onto the users row and stamps totp_enrolled_at.

  3. Subsequent logins
       → after bcrypt succeeds, server.py:6437 checks
         users.totp_secret. If set, the login flow renders a second
         step asking for a 6-digit code and verify_code() gates the
         actual session-cookie issuance.

This module deliberately does NO database I/O — the route layer does the
persistence. That keeps the helper trivially unit-testable and lets the
caller decide whether to write to `users.totp_secret` (final enrolment)
or just hold it on a signed continuation token (mid-flow).
"""
from __future__ import annotations

import base64
import hmac
import secrets
import struct
import time
from hashlib import sha1
from typing import Optional
from urllib.parse import quote


# 160-bit secret encoded as 32 base32 characters. Matches the size every
# major authenticator app expects; some older devices truncate longer
# secrets, so we deliberately do not push beyond 160 bits.
_SECRET_BYTES = 20

# RFC 6238 step size. 30 seconds is the de-facto standard and what every
# major authenticator app generates against. Verifying against ±1 step
# absorbs both clock drift and the short window where the user starts
# typing toward the end of one window and submits in the next.
_STEP_SECONDS = 30
_VERIFY_SKEW_STEPS = 1


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret, suitable for both QR rendering
    and otpauth:// URIs. Uppercase with no padding — that's the form
    every authenticator app expects in the URI's `secret=` parameter."""
    raw = secrets.token_bytes(_SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def otpauth_uri(secret: str, username: str, issuer: str = "nextgen-dast") -> str:
    """Build the otpauth:// URI an authenticator app encodes from a QR.

    Format follows the Google Authenticator key-uri spec:
      otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>

    Both the path and the issuer query param carry the issuer; older
    authenticator apps read one and newer ones read the other, so we
    populate both for compatibility."""
    label = f"{issuer}:{username}"
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        # The defaults below match RFC 6238 + every authenticator app's
        # default; we emit them explicitly so a non-default app can't
        # silently substitute its own value.
        f"&algorithm=SHA1&digits=6&period={_STEP_SECONDS}"
    )
    return f"otpauth://totp/{quote(label, safe=':')}?{params}"


def _hotp(secret_b32: str, counter: int) -> str:
    """Compute one HOTP value (RFC 4226). Internal helper for verify_code.
    Returns a zero-padded 6-digit string."""
    # Pad the base32 string back to a multiple of 8 chars before decoding.
    # generate_secret() strips padding because authenticator apps prefer
    # the unpadded form, so the verify path has to put it back.
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    try:
        key = base64.b32decode(padded.upper(), casefold=True)
    except (ValueError, base64.binascii.Error):
        return ""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, sha1).digest()
    # Dynamic truncation per RFC 4226 §5.3.
    offset = digest[-1] & 0x0F
    truncated = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(truncated % 1_000_000).zfill(6)


def verify_code(secret_b32: str, code: str,
                at: Optional[float] = None) -> bool:
    """Constant-time compare `code` against the secret over a ±1 step
    window. Returns False on any malformed input rather than raising —
    callers should treat that the same as "wrong code"."""
    if not secret_b32 or not code:
        return False
    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return False
    now = at if at is not None else time.time()
    counter = int(now // _STEP_SECONDS)
    # Verify against the current step plus a small forward/backward
    # skew window. compare_digest avoids timing leaks on a per-digit
    # comparison, even though the attacker has only 30 seconds per
    # window before the answer they're guessing changes.
    for skew in range(-_VERIFY_SKEW_STEPS, _VERIFY_SKEW_STEPS + 1):
        candidate = _hotp(secret_b32, counter + skew)
        if candidate and hmac.compare_digest(candidate, code):
            return True
    return False
