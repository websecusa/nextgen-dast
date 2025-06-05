#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: a privileged account is reachable with widely-known
default credentials.

Default-credential checks aren't just "is there a /login page" — the
high-fidelity finding is that a SPECIFIC pair grants admin access. We
log in, decode the issued session token (JWT), and assert the role
claim is administrative. That's three orthogonal signals: response is
200, response carries a session, the session encodes admin authority.
A scanner that stops at "POST returned 200" gets fooled by every login
form that issues a guest cookie on bad creds.

Detection signal:
  POST /rest/user/login {email: <admin@host>, password: <default>} →
    HTTP 200 with body containing `authentication.token` (JWT) AND
    decoded payload's `role` claim is administrative.

Default catalogue:
  - Juice Shop's seeded admin: admin@juice-sh.op / admin123
  - Common patterns: admin/admin, administrator/password
  - The catalogue stays SHORT on purpose — exhaustive default-cred
    fuzzing belongs in a separate brute-force probe with anti-lockout
    safeguards. This probe is for "the project's documented default."

Safety: each attempt is one POST to a login endpoint. The probe stops
on first success and the issued token is discarded immediately. We do
NOT use the token to reach other endpoints. POST is required by the
login protocol, so the caller MUST pass `allow_destructive: True` in
the stdin config — the orchestrator does this automatically based on
the probe's manifest, but standalone callers (tests, manual runs)
need to set it explicitly. The probe's `safety_class` stays
`read-only` because no application state changes; the
`allow_destructive` flag is the framework's way of saying "I know
this probe issues non-GET methods, that's expected."
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# Login endpoint candidates. Most Express / Rails / Django apps mount
# at one of these; tested in order, first 200 is used.
LOGIN_PATHS = (
    "/rest/user/login",     # Juice Shop and many Express apps
    "/api/auth/login",
    "/api/login",
    "/login",
    "/auth/login",
)

# Generic-backbone catalogue. These pairs are documented industry
# defaults that have been responsible for billions of dollars of
# losses: stale appliance setups, forgotten dev accounts, default
# CMS installs, "we'll change it later" deploys. Each pair adds one
# POST per login path tested.
#
# Sourced from CIRT.net default-password DB + the OWASP Top-10
# default-credential examples + per-vendor research. Vendor-specific
# pairs (cisco/cisco, weblogic/weblogic1, etc.) live in the SEPARATE
# auth_vendor_default_credentials probe — that one fingerprints the
# stack first to avoid hammering 80 cred pairs at every host.
#
# Safety controls:
#  - the probe stops on first success; subsequent pairs are skipped.
#  - if any login path returns 429 or `Retry-After`, the probe aborts
#    that path and moves on rather than risk lockout cascades.
#  - the {host} template is substituted at runtime so admin@<target>
#    works without a hard-coded domain.
DEFAULT_CREDENTIALS = (
    # --- Juice Shop / known seeded ---
    ("admin@juice-sh.op", "admin123"),
    # --- email-shaped, generic ---
    ("admin@{host}",      "admin123"),
    ("admin@{host}",      "admin"),
    ("admin@{host}",      "password"),
    ("admin@admin.com",   "admin"),
    ("admin@example.com", "admin"),
    ("admin@example.com", "password"),
    # --- bare-username, generic ---
    ("admin",             "admin"),
    ("admin",             "password"),
    ("admin",             "admin123"),
    ("admin",             "changeme"),
    ("admin",             "letmein"),
    ("admin",             "Admin@123"),
    ("admin",             ""),               # empty password
    ("administrator",     "administrator"),
    ("administrator",     "password"),
    ("administrator",     "admin"),
    # --- root variants (rare on web apps but devastating when present) ---
    ("root",              "root"),
    ("root",              "toor"),
    ("root",              "password"),
    ("root",              ""),
    # --- developer / staging leftovers ---
    ("test",              "test"),
    ("test",              "test123"),
    ("guest",             "guest"),
    ("demo",              "demo"),
    ("user",              "user"),
    ("user",              "password"),
)

# Role-claim names that indicate administrative authority. Different
# apps spell this differently; we look for any of them in the JWT
# payload. Boolean equivalents (`is_admin: true`, `superuser: true`)
# also count.
_ADMIN_ROLE_VALUES = {"admin", "administrator", "root", "superuser",
                      "superadmin", "owner"}


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode the middle segment of a JWT to a dict. Returns None for
    anything that isn't shaped like a JWT — keeps the probe quiet on
    opaque cookies / random tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_bytes = _b64url_decode(parts[1])
        return json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None


def _looks_admin(payload: dict) -> tuple[bool, str | None]:
    """Walk a JWT payload looking for an admin role claim. Returns
    (is_admin, claim_seen). Recurses one level so Juice Shop's
    `data.role` shape is found alongside top-level `role`."""
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
    # one-level nested (Juice Shop nests inside `data`)
    for v in payload.values():
        if isinstance(v, dict):
            ok, why = _check(v)
            if ok:
                return True, why
    return False, None


def _expand_creds(host: str) -> list[tuple[str, str]]:
    """Substitute {host} into email templates."""
    out = []
    for email, pw in DEFAULT_CREDENTIALS:
        out.append((email.replace("{host}", host), pw))
    # de-dupe while preserving order
    seen, ordered = set(), []
    for email, pw in out:
        key = (email, pw)
        if key in seen: continue
        seen.add(key); ordered.append((email, pw))
    return ordered


class DefaultAdminCredentialsProbe(Probe):
    name = "auth_default_admin_credentials"
    summary = ("Detects privileged accounts reachable with documented "
               "default credentials.")
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
        host = parsed.hostname or ""
        creds = _expand_creds(host)
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None

        # Lockout-awareness: if a path responds 429 or sends a
        # `Retry-After`, abort that path immediately. Hammering after a
        # rate-limit kick can extend lockouts to hours and (worse) lock
        # out a real admin who happens to be using the same endpoint.
        # We back off the whole path rather than just the cred — the
        # rate-limit applies to the endpoint, not the user.
        path_aborted: set[str] = set()

        for path in login_paths:
            url = urljoin(origin, path)
            for email, pw in creds:
                if path in path_aborted:
                    break
                # one POST per (path, cred) pair. The body shape that
                # works for ~all Express/Rails/Django login endpoints
                # is JSON with email+password keys.
                body = json.dumps({"email": email, "password": pw}).encode()
                r = client.request(
                    "POST", url,
                    headers={"Content-Type": "application/json"},
                    body=body,
                )
                row: dict = {
                    "login_path": path, "email": email,
                    "status": r.status, "size": r.size,
                }
                # Rate-limit signal — abort this path so we don't pile
                # on while the server is already telling us to back off.
                if r.status == 429 or r.headers.get("Retry-After") \
                        or r.headers.get("retry-after"):
                    row["aborted_reason"] = "rate-limited (429 / Retry-After)"
                    attempts.append(row)
                    path_aborted.add(path)
                    break
                if r.status == 200 and r.body:
                    try:
                        doc = json.loads(r.text)
                    except json.JSONDecodeError:
                        attempts.append(row); continue
                    # Find the JWT in the response. Juice Shop nests it
                    # under data.authentication.token; some apps use
                    # `token` at root or `access_token`.
                    token = None
                    if isinstance(doc, dict):
                        candidates: list = []
                        for k in ("token", "access_token", "id_token"):
                            if isinstance(doc.get(k), str):
                                candidates.append(doc[k])
                        # one level nesting
                        for v in doc.values():
                            if isinstance(v, dict):
                                for k in ("token", "access_token"):
                                    if isinstance(v.get(k), str):
                                        candidates.append(v[k])
                                # data.authentication.token
                                auth = v.get("authentication")
                                if isinstance(auth, dict):
                                    if isinstance(auth.get("token"), str):
                                        candidates.append(auth["token"])
                        token = candidates[0] if candidates else None
                    if token:
                        payload = _decode_jwt_payload(token) or {}
                        is_admin, why = _looks_admin(payload)
                        if is_admin:
                            row.update({"jwt_admin_claim": why,
                                        "credentials_succeeded": True})
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
                summary=(f"Confirmed: default administrative credentials "
                         f"({confirmed['email']!r}) granted an admin "
                         f"session at {origin}{confirmed['login_path']} "
                         f"(JWT claim: {confirmed['jwt_admin_claim']})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Rotate the password for this account immediately. "
                    "If the account is a documented default that ships "
                    "with the application (Juice Shop's admin@juice-sh.op "
                    "is intentional and this finding is noise on the "
                    "test target), either delete the account in production "
                    "or rotate it to a long random password as part of "
                    "deploy. Add a deploy-time gate that fails the build "
                    "if any user record still carries the seeded password."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} default-cred attempts "
                     f"across {len(login_paths)} paths on {origin}; "
                     "no admin session was issued."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DefaultAdminCredentialsProbe().main()
