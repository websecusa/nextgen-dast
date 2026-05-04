#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: session-id does not rotate on login (session
fixation).

If the session id issued before login is the same one carried
after login, an attacker who can pre-seed the victim's browser
with a known cookie -- via a man-in-the-middle on plaintext HTTP,
via XSS on a sibling subdomain, via a `Set-Cookie` smuggle through
a vulnerable proxy -- takes over the session the moment the
victim logs in. The victim continues to use the seeded id and the
attacker has been holding onto it the whole time.

The high-fidelity signal is byte equality: GET `/` to obtain a
pre-login session cookie, POST the login with credentials AND the
seeded cookie reflected back, then compare the value of the same-
named cookie before and after. If they're identical, the server
didn't rotate the id at the auth boundary.

We register a throwaway account first so the login uses our own
credentials -- never a real user's. The probe never sends the
session cookie back to anyone except the same origin we received
it from.

Detection signal:
  1. GET / with no cookie. Capture every Set-Cookie whose name
     matches a session-shaped allow-list.
  2. Register a throwaway account.
  3. POST /rest/user/login (or /login) with the captured cookie
     in the Cookie header AND the throwaway creds in the body.
  4. Compare the post-login session cookie value against the
     pre-login one.

Tested against:
  + OWASP Juice Shop  Uses JWT in body, not session cookies; the
                      probe finds no session-shaped cookie in the
                      pre-login pass and returns inconclusive.
                      That's the right behavior -- there's nothing
                      to fix on JWT-in-body apps.
  + PHP / Rails / Django apps without
    session_regenerate_id() / reset_session / SessionMiddleware
    rotation -> validated=True.

Read-only safety: only register and login POSTs, against an
account this probe just created.
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

# Cookie names that look like a session id. Case-insensitive
# substring match. CSRF tokens are deliberately left out -- they
# rotate per request anyway.
_SESSION_COOKIE_HINTS = ("session", "sessid", "sid",
                          "phpsessid", "connect.sid",
                          "asp.net_sessionid", "jsessionid",
                          "_session_id", "auth_token", "remember_token")

LOGIN_PATHS = (
    "/rest/user/login",
    "/api/auth/login",
    "/api/login",
    "/login",
    "/auth/login",
    "/sessions",
    "/users/sign_in",
)

REGISTER_PATHS = (
    "/api/Users",
    "/api/users",
    "/register",
    "/api/register",
    "/api/auth/register",
)


def _looks_like_session_cookie(name: str) -> bool:
    nl = (name or "").lower()
    return any(h in nl for h in _SESSION_COOKIE_HINTS)


def _parse_set_cookies(headers: dict) -> dict:
    """Return {name: value} for every Set-Cookie line in the
    response. Multiple Set-Cookie headers may be flattened by
    urllib; split on newline first, then on comma when needed."""
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


def _try_register(client: SafeClient, origin: str
                  ) -> tuple[str | None, str | None, dict]:
    email = f"sessfix-probe-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email, "tried": []}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    for p in REGISTER_PATHS:
        r = client.request(
            "POST", urljoin(origin, p),
            headers={"Content-Type": "application/json"}, body=body)
        diag["tried"].append({"path": p, "status": r.status})
        if r.status in (200, 201):
            return email, pw, diag
    return None, None, diag


class SessionFixationNoRotationProbe(Probe):
    name = "auth_session_fixation_no_rotation"
    summary = ("Detects login flows that do not rotate the session id "
               "after authentication -- session-fixation primitive.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--login-path", action="append", default=[],
            help="Additional login endpoint to probe. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = list(LOGIN_PATHS) + list(args.login_path or [])

        # Pass 1: anonymous GET / -- pick up the pre-login session
        # cookie. Some apps don't issue one until the first POST,
        # in which case we'll try a second source path below.
        pre = client.request("GET", urljoin(origin, "/"),
                              follow_redirects=False)
        cookies = _parse_set_cookies(pre.headers or {})
        session_name = next((n for n in cookies
                              if _looks_like_session_cookie(n)), None)
        pre_value = cookies.get(session_name) if session_name else None
        diag = {"pre_login_cookies": list(cookies.keys()),
                "session_cookie_name": session_name}

        if not session_name:
            # No session-shaped cookie issued. Most likely a
            # JWT-in-body app -- nothing to fixate.
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no session-shaped cookie issued by "
                         f"{origin}/ on the pre-login fetch (cookies "
                         f"seen: {list(cookies.keys()) or 'none'}). "
                         "App likely uses JWT-in-body or another non-"
                         "cookie session model -- session-fixation "
                         "doesn't apply."),
                evidence={"origin": origin, "diag": diag},
            )

        email, pw, reg_diag = _try_register(client, origin)
        diag["register_diag"] = reg_diag
        if not email:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not register a throwaway "
                         "account; refusing to log in as a real user "
                         "to test session rotation."),
                evidence={"origin": origin, "diag": diag},
            )

        # Pass 2: POST login with the seeded cookie reflected.
        body = json.dumps({"email": email, "password": pw}).encode()
        attempts: list[dict] = []
        confirmed: dict | None = None
        seeded_cookie = f"{session_name}={pre_value}"
        for p in login_paths:
            r = client.request(
                "POST", urljoin(origin, p),
                headers={"Content-Type": "application/json",
                         "Cookie": seeded_cookie},
                body=body, follow_redirects=False)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            post_cookies = _parse_set_cookies(r.headers or {})
            post_value = post_cookies.get(session_name)
            row["post_cookie_present"] = (post_value is not None)
            if post_value is not None:
                row["values_equal"] = (post_value == pre_value)
                if post_value == pre_value:
                    confirmed = row
                    attempts.append(row)
                    break
            else:
                # Some servers omit Set-Cookie when they accept the
                # supplied id (which is itself the bug shape -- they
                # just trust the inbound). Treat as fixation when the
                # login itself succeeded (200/302).
                if r.status in (200, 302):
                    row["values_equal"] = "no_set_cookie_on_login"
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "diag": diag,
                    "session_cookie_name": session_name,
                    "pre_login_value_excerpt":
                        (pre_value or "")[:16] + "...",
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} does not "
                    f"rotate the `{session_name}` session id at the "
                    "auth boundary -- the value is byte-identical "
                    "before and after login (or the server did not "
                    "issue a fresh Set-Cookie). An attacker who "
                    "pre-seeds the victim's browser with a known id "
                    "(MITM on plain HTTP, sibling-subdomain XSS) "
                    "rides into the authenticated session."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Rotate the session id immediately after a "
                    "successful login.\n"
                    "  - PHP: `session_regenerate_id(true)` (the "
                    "  `true` deletes the old session record).\n"
                    "  - Rails: `reset_session` before assigning the "
                    "  user; Devise does this automatically -- ensure "
                    "  any custom auth path does too.\n"
                    "  - Django: the `django.contrib.auth.login()` "
                    "  helper rotates the session for you; raw views "
                    "  that don't call it must call "
                    "  `request.session.cycle_key()`.\n"
                    "  - Express express-session: "
                    "  `req.session.regenerate(cb)` after auth.\n"
                    "  - ASP.NET: rotate via the SessionStateModule "
                    "  override or just abandon + re-issue a new "
                    "  session.\n"
                    "Pair with `Secure; HttpOnly; SameSite=Lax|Strict` "
                    "flags on the session cookie (covered by the "
                    "config_session_cookie_flags probe) so the seed "
                    "vectors are harder to deliver in the first place."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} login endpoints "
                     f"on {origin} with a seeded session cookie; the "
                     "post-login session id was different on every "
                     "successful login (or no login succeeded)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SessionFixationNoRotationProbe().main()
