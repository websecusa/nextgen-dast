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
    # ----- Documented application seeds -----
    # Apps that ship with a known admin account documented in the
    # README / quickstart guides. These get tried FIRST because they
    # have the highest hit-rate on test/staging environments where
    # the seed wasn't replaced.
    ("admin@juice-sh.op",     "admin123"),       # OWASP Juice Shop
    ("admin@dvwa.local",      "admin"),          # DVWA-style installs
    ("admin@example.com",     "admin"),
    ("admin@example.com",     "password"),
    ("admin@example.com",     "Admin@123"),
    ("admin@example.org",     "admin"),
    ("admin@admin.com",       "admin"),
    ("admin@admin.local",     "admin"),
    ("admin@localhost",       "admin"),
    # ----- Email-shaped @ target host -----
    # The {host} template is filled with the assessment's hostname,
    # catching deploys where the seeded admin email follows the app's
    # own domain (admin@<the app>).
    ("admin@{host}",          "admin"),
    ("admin@{host}",          "admin123"),
    ("admin@{host}",          "password"),
    ("admin@{host}",          "Admin@123"),
    ("admin@{host}",          "Welcome1"),
    ("admin@{host}",          "P@ssw0rd"),
    ("admin@{host}",          "changeme"),
    ("administrator@{host}",  "administrator"),
    ("administrator@{host}",  "password"),
    # ----- Bare-username admin variants -----
    # Most internal back-office apps still use bare usernames rather
    # than emails. The password list mixes the historical CIRT.net
    # defaults with the top entries from the rockyou / SecLists
    # admin-password set; ordering puts the historically-most-found
    # pairs first so the probe stops fast on common cases.
    ("admin",                 "admin"),
    ("admin",                 "admin123"),
    ("admin",                 "password"),
    ("admin",                 "P@ssw0rd"),
    ("admin",                 "Password1"),
    ("admin",                 "Welcome1"),
    ("admin",                 "Admin@123"),
    ("admin",                 "admin@123"),
    ("admin",                 "changeme"),
    ("admin",                 "letmein"),
    ("admin",                 "qwerty"),
    ("admin",                 "12345"),
    ("admin",                 "123456"),
    ("admin",                 "12345678"),
    ("admin",                 "iloveyou"),
    ("admin",                 ""),                # empty password
    ("administrator",         "administrator"),
    ("administrator",         "password"),
    ("administrator",         "admin"),
    ("administrator",         "P@ssw0rd"),
    # ----- Root-style accounts -----
    # Web apps with shell-style admin accounts (typically forgotten
    # dev installs). Devastating when present because root access
    # implies pivot capability.
    ("root",                  "root"),
    ("root",                  "toor"),
    ("root",                  "password"),
    ("root",                  "admin"),
    ("root",                  ""),
    # ----- Developer / staging leftovers -----
    # Accounts that get created during local development and survive
    # to staging or even prod when the deploy doesn't strip them.
    ("test",                  "test"),
    ("test",                  "test123"),
    ("test",                  "password"),
    ("dev",                   "dev"),
    ("developer",             "developer"),
    ("qa",                    "qa"),
    ("staging",               "staging"),
    ("ci",                    "ci"),
    ("build",                 "build"),
    ("deploy",                "deploy"),
    ("backup",                "backup"),
    # ----- Generic operator accounts -----
    # Vendor-neutral roles that show up across appliances and
    # frameworks. A real hit here typically means a forgotten
    # service account.
    ("manager",               "manager"),
    ("manager",               "manager123"),
    ("operator",              "operator"),
    ("service",               "service"),
    ("sysadmin",              "sysadmin"),
    ("support",               "support"),
    ("guest",                 "guest"),
    ("guest",                 ""),
    ("demo",                  "demo"),
    ("user",                  "user"),
    ("user",                  "password"),
    ("info",                  "info"),
    ("default",               "default"),
    # ----- Vendor pairs not covered by the fingerprint-first probe -----
    # The companion auth_vendor_default_credentials probe handles
    # Tomcat, WordPress, phpMyAdmin, Jenkins, Grafana, JBoss, Adminer,
    # and Kibana via stack fingerprinting first. Pairs below are for
    # vendors that don't fingerprint cleanly via path/header alone.
    ("weblogic",              "weblogic"),
    ("weblogic",              "weblogic1"),
    ("oracle",                "oracle"),
    ("oracle",                "oracle123"),
    ("elastic",               "changeme"),       # Elasticsearch default
    ("neo4j",                 "neo4j"),
    ("kong",                  "kong"),
    ("redmine",               "redmine"),
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

        # If the first request returns connection-failed (status 0),
        # the host:port has no listener — every subsequent attempt
        # would fail the same way, burning the request budget. Mark
        # every path aborted so the outer loop exits. Set once on
        # first observation rather than per-path because a single
        # connection refusal proves the target is unreachable.
        host_unreachable = False

        for path in login_paths:
            if host_unreachable:
                break
            url = urljoin(origin, path)
            for email, pw in creds:
                if path in path_aborted or host_unreachable:
                    break
                # If a previous attempt against this path already
                # returned 404, the endpoint doesn't exist on this
                # host — no point burning budget on the rest of the
                # cred list. (path_aborted handles the 429/Retry-After
                # case; this is the same idea for not-found.)
                if attempts and attempts[-1].get("login_path") == path \
                        and attempts[-1].get("status") == 404:
                    path_aborted.add(path)
                    break
                # one POST per (path, cred) pair. The body shape that
                # works for ~all Express/Rails/Django login endpoints
                # is JSON with email+password keys.
                req_body = json.dumps({"email": email, "password": pw})
                body = req_body.encode()
                r = client.request(
                    "POST", url,
                    headers={"Content-Type": "application/json"},
                    body=body,
                )
                # Record the full attempt — including the password we
                # tried and the request body we sent — so the analyst
                # reading the finding can reproduce the exact request
                # without inferring it from the probe source. These
                # are documented public default credentials, NOT user
                # secrets, so storing them in evidence is appropriate.
                # Response body is clipped to keep evidence rows small;
                # 1.5 KB is enough to show a JWT and any error envelope.
                row: dict = {
                    "login_path": path,
                    "url": url,
                    "method": "POST",
                    "email": email,
                    "password": pw,
                    "status": r.status,
                    "size": r.size,
                    "request_body": req_body,
                    "response_body_excerpt": (r.text or "")[:1536],
                }
                # Connection-failed (status 0): SafeClient signals an
                # unreachable target this way. No HTTP server means
                # every cred×path combination would fail identically,
                # so we record one attempt and bail out of the entire
                # probe rather than burning the request budget on
                # certainties.
                if r.status == 0:
                    row["aborted_reason"] = "target unreachable (connection failed)"
                    attempts.append(row)
                    host_unreachable = True
                    break
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
            # Mask the password in the user-visible summary — the
            # rendered PDF gets shared widely. The unmasked value still
            # lives in `evidence.confirmed.password` so the toolkit and
            # an analyst working from the findings table can replay.
            pw = confirmed["password"]
            masked_pw = (pw[0] + "*" * (len(pw) - 2) + pw[-1]
                         if pw and len(pw) >= 3 else "*" * len(pw or ""))
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: default administrative credentials "
                         f"({confirmed['email']!r} / "
                         f"{masked_pw!r}) granted an admin "
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
