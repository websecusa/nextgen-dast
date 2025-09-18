#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: change-password endpoint accepts new password
without requiring the current one.

A correctly-implemented "change password" flow requires the user to
prove they still know their current password. Skipping that check
turns a stolen session cookie / leaked JWT into a permanent account
takeover — the attacker rotates the password and locks the rightful
user out.

Detection signal:
  Register a throwaway user, log in. GET (or POST) the change-
  password endpoint with `new` and `repeat` set, no `current`
  parameter. Server returns 200/204 → vulnerable.

Destructive in the strict sense (we do change the throwaway user's
password) but the user is throwaway and the password is random, so
no real-world data is touched. Off by default.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

CHANGE_PATHS = (
    "/rest/user/change-password",
    "/api/user/change-password",
    "/api/auth/change-password",
)


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"chgpw-{secrets.token_hex(6)}@dast.test"
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


class PasswordChangeNoCurrentProbe(Probe):
    name = "auth_password_change_no_current"
    summary = ("Detects change-password endpoints that accept a new "
               "password without verifying the current one.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — probe rotates the throwaway user's "
                 "password.")
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional change-password path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: probe rotates the throwaway user's "
                         "password. Re-run with --allow-destroy."),
                evidence={"origin": origin, "safety_skipped": True},
            )
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
        new_pw = "rotated-" + secrets.token_hex(6)
        paths = list(CHANGE_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            # Try GET-with-query (Juice Shop's literal shape) and
            # POST-with-JSON. Either succeeds → vuln.
            qs = urlencode({"new": new_pw, "repeat": new_pw})
            url_get = urljoin(origin, f"{p}?{qs}")
            r = client.request("GET", url_get, headers={
                "Authorization": f"Bearer {token}",
            })
            row = {"path": p, "method": "GET", "status": r.status,
                   "size": r.size, "body_excerpt": (r.text or "")[:200]}
            if r.status in (200, 204):
                row["change_succeeded"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }, body=json.dumps({"new": new_pw, "repeat": new_pw}).encode())
            row = {"path": p, "method": "POST", "status": r.status,
                   "size": r.size, "body_excerpt": (r.text or "")[:200]}
            if r.status in (200, 204):
                row["change_succeeded"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: change-password endpoint on "
                         f"{origin}{confirmed['path']} accepted a new "
                         "password with no `current` parameter — "
                         "stolen-session-equals-account-takeover."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Require the current password on every change-"
                    "password call (server-side verify with bcrypt). "
                    "If the endpoint is hit during a token-based reset "
                    "flow instead of a logged-in change, gate it on a "
                    "single-use reset token rather than a session JWT."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: change-password without `current` was "
                     f"refused at all {len(paths)} candidate paths on "
                     f"{origin}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PasswordChangeNoCurrentProbe().main()
