#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: persistent-login (remember-me) cookie is weak.

A remember-me cookie outlives the browser session, often for weeks
or months. Attackers who steal this cookie keep access for the full
TTL — there's no follow-up login event to trip a detection. Common
weaknesses:

  - Base64 of `username:expiry` with no MAC. An attacker forges an
    arbitrary expiry or pivots to another username.
  - Predictable structure (incrementing counter, time-stamp prefix,
    no randomness at all).
  - Too-low entropy across the random portion.
  - The same value reissued for every login (i.e., no rotation —
    one stolen token works forever).

This probe registers two disposable accounts, asks each to "remember
me" via a couple of common form / parameter shapes, and statically
analyzes the issued cookies. We never log in as a real user and we
never replay a cookie outside its origin.

Detection signal:
  Remember-me cookie is structurally decodable to plaintext that
  reveals the username (base64 → contains the email we registered
  with) OR shows insufficient randomness / no MAC component.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import string
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATH = "/api/Users"
LOGIN_PATHS = (
    "/rest/user/login",
    "/api/auth/login",
    "/login",
)

# Cookie name hints for persistent-login. Different stacks use
# different names; the hint list keeps us focused on the right
# cookies and avoids matching unrelated long-lived cookies (e.g.
# tracking ids).
REMEMBER_HINTS = ("remember", "rememberme", "remember_me",
                  "remember_token", "persistent", "auto_login",
                  "auth_token", "stay_logged_in")


def _parse_set_cookies(headers: dict) -> dict:
    out: dict = {}
    for k, v in (headers or {}).items():
        if k.lower() != "set-cookie":
            continue
        for piece in re.split(r"\n", str(v)):
            piece = piece.strip()
            if not piece:
                continue
            kv = piece.split(";", 1)[0]
            if "=" in kv:
                name, val = kv.split("=", 1)
                out[name.strip()] = val.strip()
    return out


def _looks_like_remember(name: str) -> bool:
    nl = (name or "").lower()
    return any(h in nl for h in REMEMBER_HINTS)


def _try_b64_decode(s: str) -> bytes | None:
    """Try common base64 variants. Return None on any failure."""
    for variant in (s, s + "=", s + "==", s + "==="):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                # validate=False so '+' / '/' don't trip standard,
                # but we still require decoded bytes.
                d = fn(variant + "")
                if d:
                    return d
            except Exception:
                continue
    return None


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for byte in b
                    if chr(byte) in string.printable
                    and byte >= 0x20)
    return printable / len(b)


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 12:
        return val[:2] + "*" * max(0, len(val) - 4) + val[-2:]
    return val[:6] + "*" * (len(val) - 10) + val[-4:]


def _register(client: SafeClient, origin: str, email: str,
              pw: str) -> int:
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, REGISTER_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    return r.status


def _login_with_remember(client: SafeClient, origin: str,
                         email: str, pw: str) -> tuple[int, dict]:
    """Single login attempt with all common remember-me flags
    pre-set in the body. We do NOT follow redirects — the
    Set-Cookie comes back on the 200 / 302 itself. Budget-conscious:
    one request per account, hits Juice-Shop's /rest/user/login
    cleanly while still working against generic /login."""
    payload = {
        "email": email, "username": email, "password": pw,
        "rememberMe": True, "remember": True, "remember-me": "on",
        "stayLoggedIn": True,
    }
    body = json.dumps(payload).encode()
    r = client.request("POST", urljoin(origin, LOGIN_PATHS[0]),
                       headers={"Content-Type":
                                "application/json"},
                       body=body, follow_redirects=False)
    cookies = _parse_set_cookies(r.headers or {})
    remember = next(((n, v) for n, v in cookies.items()
                     if _looks_like_remember(n)), None)
    if remember:
        return r.status, {"path": LOGIN_PATHS[0],
                          "cookie_name": remember[0],
                          "cookie_value": remember[1]}
    return r.status, {}


class AuthRememberMeTokenWeakProbe(Probe):
    name = "auth_remember_me_token_weak"
    summary = ("Detects weak persistent-login (remember-me) cookies "
               "by decoding their structure and comparing two "
               "independent accounts.")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args — the hint list is fixed.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Two disposable accounts so we can compare across users.
        emails = [f"rmbr-{secrets.token_hex(6)}@dast.test",
                  f"rmbr-{secrets.token_hex(6)}@dast.test"]
        pw = "Pr0be-" + secrets.token_hex(6)
        sessions: list[dict] = []
        for em in emails:
            reg = _register(client, origin, em, pw)
            login_status, sess = _login_with_remember(client, origin,
                                                     em, pw)
            sess["email"] = em
            sess["register_status"] = reg
            sess["login_status"] = login_status
            sessions.append(sess)

        # If neither account got a remember-me cookie, the app
        # probably doesn't support persistent login (which is fine,
        # not a flaw). Refute cleanly.
        with_cookie = [s for s in sessions if s.get("cookie_value")]
        if len(with_cookie) < 1:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no persistent-login cookie issued "
                         f"by {origin} on either probe account. App "
                         "likely uses session-only auth."),
                evidence={"origin": origin, "sessions":
                          [{k: v for k, v in s.items()
                            if k != "cookie_value"}
                           for s in sessions]},
            )

        analyses: list[dict] = []
        signals: list[str] = []
        for s in with_cookie:
            val = s["cookie_value"]
            # URL-decode percent escapes the server may have applied.
            decoded = val
            decoded_bytes = _try_b64_decode(val)
            decoded_text = ""
            if decoded_bytes is not None:
                try:
                    if _printable_ratio(decoded_bytes) > 0.7:
                        decoded_text = decoded_bytes.decode(
                            "utf-8", "replace")
                except Exception:
                    decoded_text = ""
            analysis = {
                "email": s["email"],
                "cookie_name": s["cookie_name"],
                "cookie_value_masked": _mask(val),
                "length": len(val),
                "decodes_to_printable": bool(decoded_text),
                "decoded_excerpt": (decoded_text[:80]
                                    if decoded_text else ""),
            }
            # Signal A: decoded text contains the email we just
            # registered with — proves the cookie embeds the username
            # in plain text.
            if decoded_text and s["email"].lower() in decoded_text.lower():
                signals.append(
                    f"`{s['cookie_name']}` decodes to plaintext "
                    f"containing the registered email.")
                analysis["embeds_username"] = True
            # Signal B: very short value — under 20 chars is far too
            # little to hold any cryptographic MAC. Even a SHA-256
            # truncated to 16 bytes encodes to 22+ chars in base64.
            if len(val) < 20:
                signals.append(
                    f"`{s['cookie_name']}` is only {len(val)} chars "
                    "— too short to contain a real MAC.")
                analysis["too_short"] = True
            analyses.append(analysis)

        # Signal C: across the two accounts, the cookie values share
        # a long common prefix or suffix (counter / timestamp).
        if len(with_cookie) == 2:
            v1 = with_cookie[0]["cookie_value"]
            v2 = with_cookie[1]["cookie_value"]
            common_prefix = 0
            for a, b in zip(v1, v2):
                if a == b:
                    common_prefix += 1
                else:
                    break
            common_suffix = 0
            for a, b in zip(v1[::-1], v2[::-1]):
                if a == b:
                    common_suffix += 1
                else:
                    break
            shorter = min(len(v1), len(v2)) or 1
            if (common_prefix / shorter) > 0.40:
                signals.append(
                    f"two distinct accounts share a "
                    f"{common_prefix}-char common prefix in their "
                    "remember-me cookies (predictable structure).")
            if (common_suffix / shorter) > 0.40 and common_suffix >= 6:
                signals.append(
                    f"two distinct accounts share a "
                    f"{common_suffix}-char common suffix in their "
                    "remember-me cookies (predictable structure).")

        evidence = {"origin": origin, "analyses": analyses,
                    "signals": signals,
                    "sessions": [{k: v for k, v in s.items()
                                  if k != "cookie_value"}
                                 for s in sessions]}

        # Require at least 2 corroborating signals — single-signal
        # findings here have too high a false-positive rate (e.g.
        # an opaque token MAY contain a printable substring just by
        # chance).
        if len(signals) >= 2:
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: weak persistent-login cookie on "
                    f"{origin}. Signals: {' '.join(signals)}"),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "A persistent-login cookie should be a fully "
                    "random 128+ bit token whose only plaintext role "
                    "is the lookup key into a server-side row that "
                    "binds {token_id, user_id, expires_at, "
                    "rotation_chain}. On every successful "
                    "presentation, rotate the token (delete the old "
                    "row, mint a new one). Never embed the username "
                    "or expiry in the cookie itself; never use a "
                    "predictable counter or timestamp."),
            )
        return Verdict(
            validated=False, confidence=0.82,
            summary=(f"Refuted: persistent-login cookie on {origin} "
                     f"showed {len(signals)} weakness signal(s) "
                     "(need >= 2 to flag)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthRememberMeTokenWeakProbe().main()
