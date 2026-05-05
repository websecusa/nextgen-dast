#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Unicode homoglyph login bypass.

If an app normalises usernames inconsistently between registration
and login (or worse — between authentication and authorization),
an attacker can register a username that looks identical to a
privileged account but uses Cyrillic / Greek / fullwidth code
points in place of one or more ASCII letters. The classic case:
register ``admin`` where the first ``a`` is Cyrillic ``а``
(U+0430). The bytes differ so registration succeeds, but if a
later code path NFKC-normalises the username before
authorization, the imposter inherits admin's privileges.

A weaker variant of the same bug: an existing admin login is
itself reachable via the homoglyph form because the login
endpoint normalises but the password store does not. We probe the
direct login form first — it's the cheapest signal.

Conservative approach: we ONLY flag when the homoglyph form
authenticates successfully. We never assert privileges; the
login-success signal alone is enough to demonstrate the
normalisation bug. We require TWO corroborating signals:

  * HTTP 200 in response.
  * A session cookie OR auth token in the response (matching
    the same patterns ``ldap_injection_login_bypass`` uses).

We additionally require a control: the same probe issues an
attempt with a known-bad username (no homoglyph, no real account)
and confirms it fails. If the control succeeds, the endpoint is
broken in a way unrelated to homoglyphs and we refuse to flag.

Detection signal:
  Homoglyph login → 200 + session/token issuance, AND the control
  attempt fails (no token / non-200).
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGIN_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/login",
    "/auth/login",
    "/user/login",
)

# Homoglyph variants of common privileged usernames. Each entry is
# (label, displayed-username). The visible string looks identical
# to the ASCII form; only the byte sequence differs.
#
# The Cyrillic ``а`` is U+0430. The Cyrillic ``о`` is U+043E.
HOMOGLYPH_USERNAMES = (
    ("cyrillic_a_admin",     "аdmin"),
    ("cyrillic_a_admin_email",
        "аdmin@juice-sh.op"),
    ("cyrillic_o_root",      "rоot"),
    ("cyrillic_administrator",
        "аdministrator"),
)

SESSION_COOKIE_RE = re.compile(
    r"\b(jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|"
    r"sid|sessionid|session|auth|token|access_token)\s*=",
    re.I,
)
TOKEN_BODY_PATTERNS = (
    re.compile(r'"(?:access_)?token"\s*:\s*"[A-Za-z0-9._\-]{20,}"'),
    re.compile(r'"authentication"\s*:\s*\{[^}]*"token"\s*:\s*"'),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\."
                r"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)


def _has_session_cookie(headers: dict) -> bool:
    for k, v in headers.items():
        if k.lower() == "set-cookie" and SESSION_COOKIE_RE.search(v or ""):
            return True
    return False


def _has_auth_token(text: str) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in TOKEN_BODY_PATTERNS)


def _try_login(client: SafeClient, url: str,
               username: str) -> tuple[int, bool, bool]:
    """Returns (status, session_cookie_present, auth_token_present)."""
    body = json.dumps({
        "username": username, "email": username,
        "password": "definitely-not-the-password",
    }).encode()
    r = client.request("POST", url, headers={
        "Content-Type": "application/json"}, body=body)
    return (r.status,
            _has_session_cookie(r.headers),
            _has_auth_token(r.text))


class UnicodeHomoglyphLoginProbe(Probe):
    name = "unicode_homoglyph_login"
    summary = ("Detects username normalisation bugs by attempting "
               "login with Cyrillic homoglyph variants of common "
               "privileged usernames.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--login-path", action="append", default=[],
            help="Additional login endpoint to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(LOGIN_PATHS) + list(args.login_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            # Control: a fully random username that does not exist.
            # We need this to succeed at "fail" — if even this gets
            # a session, the endpoint is degenerate and the
            # comparison is meaningless.
            ctrl_user = "no-such-user-" + secrets.token_hex(6)
            c_status, c_cookie, c_token = _try_login(client, url,
                                                      ctrl_user)
            attempts.append({"path": p, "label": "control",
                              "status": c_status,
                              "session_cookie": c_cookie,
                              "auth_token": c_token})
            if c_status == 200 and (c_cookie or c_token):
                # Endpoint is broken — refuse to compare.
                continue
            for label, uname in HOMOGLYPH_USERNAMES:
                h_status, h_cookie, h_token = _try_login(client, url,
                                                           uname)
                row = {"path": p, "label": label,
                        "username_codepoints":
                            "+".join(f"U+{ord(ch):04X}" for ch in uname),
                        "status": h_status,
                        "session_cookie": h_cookie,
                        "auth_token": h_token}
                if h_status == 200 and (h_cookie or h_token):
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: homoglyph login at {origin}"
                    f"{confirmed['path']}. Username variant "
                    f"`{confirmed['label']}` "
                    f"({confirmed['username_codepoints']}) authenticated "
                    "with a fixed-wrong password while a fully-random "
                    "control username was rejected — the username is "
                    "being normalised between the auth and password "
                    "checks (or the password store is keyed on the "
                    "normalised form)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Normalise usernames CONSISTENTLY at every layer:\n"
                    "  - Before storage (during registration): apply "
                    "Unicode NFKC + casefold + IDN punycode for "
                    "hostnames, then store the canonical form.\n"
                    "  - At login: apply the same normalisation to "
                    "the input before lookup.\n"
                    "  - Reject usernames that contain code points "
                    "from confusable sets (e.g. mixed Cyrillic/Latin) "
                    "via TR-39 / `idna.uts46` checks, OR allow only "
                    "ASCII usernames.\n"
                    "Audit the codebase for any path that compares "
                    "the unnormalised user input to a normalised "
                    "stored value."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried "
                     f"{sum(1 for a in attempts if a.get('label') != 'control')}"
                     f" homoglyph variants on {origin}; none "
                     "authenticated."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UnicodeHomoglyphLoginProbe().main()
