#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Configuration: session cookie missing HttpOnly / Secure / SameSite.

Login flows that issue a session cookie (separate from JWT-in-body)
should set the security flags every browser supports:
  - HttpOnly: prevents `document.cookie` exfiltration via XSS
  - Secure:   prevents transmission over plain http://
  - SameSite=Lax|Strict: prevents most cross-site request attacks

This probe POSTs a known login (any seed account works — we use
admin@juice-sh.op / admin123 with no password assumption; the
endpoint will set the cookie even on success or failure for some
apps, but reliably on success), inspects EVERY Set-Cookie header for
flags, and flags any auth-shaped cookie that's missing one or more.

Tested against:
  + OWASP Juice Shop  doesn't issue session cookies (token in body)
                      → validated=False (no auth-cookie to inspect).
  + sites issuing PHPSESSID / connect.sid / auth-token cookies
                      → validates when flags missing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Cookie names that look like session/auth state (not analytics, not
# CSRF tokens). Case-insensitive substring match.
_AUTH_COOKIE_HINTS = ("session", "sess", "sid", "auth", "token", "jwt",
                      "phpsessid", "connect.sid", "csrf-")  # csrf cookies
                                                            # SHOULD have flags too


def _parse_set_cookie_lines(headers: dict) -> list[str]:
    """urllib's headers dict may flatten multiple Set-Cookie values.
    Return them as separate strings."""
    lines: list[str] = []
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            # Some implementations join with newlines, some with
            # comma-space. The latter is ambiguous (Expires also has
            # commas) so prefer newline split first.
            for piece in str(v).split("\n"):
                piece = piece.strip()
                if piece:
                    lines.append(piece)
    return lines


def _flags_of(cookie_line: str) -> dict:
    """Return {name, httponly, secure, samesite} for a Set-Cookie line."""
    parts = [p.strip() for p in cookie_line.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    out = {"name": name, "httponly": False, "secure": False,
           "samesite": None}
    for p in parts[1:]:
        pl = p.lower()
        if pl == "httponly":
            out["httponly"] = True
        elif pl == "secure":
            out["secure"] = True
        elif pl.startswith("samesite="):
            out["samesite"] = p.split("=", 1)[1].strip()
    return out


def _looks_like_auth_cookie(name: str) -> bool:
    nl = (name or "").lower()
    return any(h in nl for h in _AUTH_COOKIE_HINTS)


class SessionCookieFlagsProbe(Probe):
    name = "config_session_cookie_flags"
    summary = ("Detects session/auth cookies missing HttpOnly, Secure, "
               "or SameSite flags.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--login-email", default="admin@juice-sh.op",
            help="Email for the trigger login.")
        parser.add_argument(
            "--login-password", default="admin123",
            help="Password for the trigger login.")
        parser.add_argument(
            "--login-path", default="/rest/user/login",
            help="Login endpoint to POST against.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        is_https = parsed.scheme == "https"

        # Trigger login. If the credential is wrong the server may not
        # set an auth cookie — that's OK; the probe correctly returns
        # "no auth cookie to inspect". On a hit the probe genuinely
        # found the issue.
        body = json.dumps({"email": args.login_email,
                           "password": args.login_password}).encode()
        r = client.request("POST", urljoin(origin, args.login_path),
                           headers={"Content-Type": "application/json"},
                           body=body)
        cookies = _parse_set_cookie_lines(r.headers or {})
        # Also try a GET on / — some apps issue a session cookie on the
        # first visit, not on login.
        r2 = client.request("GET", origin + "/")
        cookies += _parse_set_cookie_lines(r2.headers or {})

        cookie_rows: list[dict] = [_flags_of(c) for c in cookies]
        # De-dupe by cookie name (latest wins)
        by_name: dict[str, dict] = {}
        for row in cookie_rows:
            if row["name"]:
                by_name[row["name"]] = row
        cookie_rows = list(by_name.values())

        problems: list[dict] = []
        for row in cookie_rows:
            if not _looks_like_auth_cookie(row["name"]):
                continue
            issues = []
            if not row["httponly"]:
                issues.append("HttpOnly")
            if is_https and not row["secure"]:
                issues.append("Secure")
            if not row["samesite"]:
                issues.append("SameSite")
            if issues:
                problems.append({**row, "missing_flags": issues})

        evidence = {"origin": origin, "is_https": is_https,
                    "login_status": r.status, "index_status": r2.status,
                    "cookies_seen": cookie_rows}
        if problems:
            return Verdict(
                validated=True, confidence=0.92,
                summary=("Confirmed: auth-shaped cookie(s) on "
                         f"{origin} missing security flag(s). "
                         + "; ".join(f"{p['name']!r} → "
                                     + "/".join(p['missing_flags'])
                                     for p in problems)),
                evidence={**evidence, "problems": problems},
                severity_uplift="medium",
                remediation=(
                    "Set HttpOnly, Secure (when serving HTTPS), and "
                    "SameSite=Lax (or Strict) on every auth/session "
                    "cookie. Express `cookie-session`/`express-session`: "
                    "`{ httpOnly: true, secure: true, sameSite: 'lax' }`. "
                    "If a cookie genuinely needs to be readable from JS "
                    "(e.g. the CSRF double-submit pattern), document "
                    "WHY and harden the surrounding code path."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: no auth-shaped cookie on {origin} "
                     "missing required security flags."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SessionCookieFlagsProbe().main()
