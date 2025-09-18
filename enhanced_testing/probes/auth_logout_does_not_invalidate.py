#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: logout does not invalidate the JWT.

Stateless JWT auth has the well-known footgun that "logout" only
clears the cookie/localStorage on the client; without a server-side
revocation list the token itself stays valid until exp. Apps that
DON'T maintain a revocation list, AND advertise a /logout that
appears to do something, are giving users false security.

Detection signal:
  Register and log in, capture token. Whoami → 200 (sanity).
  Hit /rest/user/logout (or /api/auth/logout). Whoami again with the
  SAME token → 200 (the token is still valid). The third response
  proves logout didn't kill the token.

This is technically a "by-design" finding for vanilla JWT, but it's
worth flagging because remediation is meaningful (add a revocation
table or rotate keys).
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGOUT_PATHS = (
    "/rest/user/logout",
    "/api/auth/logout",
    "/api/logout",
    "/logout",
)
WHOAMI_PATH = "/rest/user/whoami"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"logout-test-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
        except json.JSONDecodeError:
            pass
    return out


class LogoutDoesNotInvalidateProbe(Probe):
    name = "auth_logout_does_not_invalidate"
    summary = ("Detects /logout endpoints that don't revoke the JWT — "
               "token continues working after the user 'logged out'.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--logout-path", action="append", default=[],
            help="Additional logout path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        whoami_url = urljoin(origin, WHOAMI_PATH)
        auth_h = {"Authorization": f"Bearer {token}"}

        # Sanity: whoami works pre-logout.
        r1 = client.request("GET", whoami_url, headers=auth_h)
        if r1.status != 200:
            return Verdict(
                validated=False, confidence=0.6,
                summary=("Inconclusive: pre-logout whoami didn't "
                         f"return 200 (got {r1.status})."),
                evidence={"origin": origin, "pre_status": r1.status},
            )

        # Hit logout. Try GET first (Juice Shop's shape), fall back
        # to POST. We're not picky — the test is about the after.
        logout_attempt: dict | None = None
        for p in list(LOGOUT_PATHS) + list(args.logout_path or []):
            url = urljoin(origin, p)
            r = client.request("GET", url, headers=auth_h)
            if r.status in (200, 204, 302):
                logout_attempt = {"path": p, "method": "GET",
                                  "status": r.status}
                break
            r = client.request("POST", url, headers={
                **auth_h, "Content-Type": "application/json",
            }, body=b"{}")
            if r.status in (200, 204, 302):
                logout_attempt = {"path": p, "method": "POST",
                                  "status": r.status}
                break

        # Whoami AFTER logout with the SAME token.
        r2 = client.request("GET", whoami_url, headers=auth_h)
        post_logout = {"status": r2.status, "size": r2.size,
                       "body_excerpt": (r2.text or "")[:200]}

        evidence = {"origin": origin,
                    "session_email": sess.get("email"),
                    "pre_logout_status": r1.status,
                    "logout_attempt": logout_attempt,
                    "post_logout": post_logout}

        if r2.status == 200 and r2.body:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(f"Confirmed: same JWT continues to authorize "
                         f"requests against {origin}{WHOAMI_PATH} after "
                         "calling logout. Server-side revocation is not "
                         "in place."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Maintain a server-side revocation list (a Redis "
                    "set keyed on jti, or a 'tokenVersion' counter on "
                    "the user record). On logout, push the jti to the "
                    "revocation set; on every request, the verifier "
                    "checks the set. Alternatively, switch to short-"
                    "lived tokens (≤5 min) plus a refresh-token flow "
                    "where logout invalidates the refresh row."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: post-logout whoami on {origin} "
                     f"returned status {r2.status} — token appears to "
                     "have been revoked."),
            evidence=evidence,
        )


if __name__ == "__main__":
    LogoutDoesNotInvalidateProbe().main()
