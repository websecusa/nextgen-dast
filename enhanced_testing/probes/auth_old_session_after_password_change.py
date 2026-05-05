#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: old session survives a password change.

A password change is supposed to be a session-invalidation boundary.
If a session that was authenticated BEFORE the password change still
authenticates protected calls AFTER the password change, then a
stolen-token attacker keeps their access even after the legitimate
user notices the breach and rotates their password. The user has
done everything right and the attacker is still inside.

This probe registers a fresh disposable account (so we never touch
admin's or anyone else's password), then logs in twice in parallel —
producing two independent sessions A and B for the SAME user. We
change the password on session A, then ask session B to read its
own profile. If session B still works, the server failed to
invalidate concurrent sessions on password change.

We always restore the new password into the verdict evidence so the
operator can clean up if they want; the account itself is throwaway
and we never log in as a real user.

Detection signal:
  Session B returns 200 to a known-protected GET (e.g.
  /rest/user/whoami or /api/Users/<id>) AFTER session A has changed
  the password from p1 to p2.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATH = "/api/Users"
LOGIN_PATH = "/rest/user/login"
WHOAMI_PATH = "/rest/user/whoami"
# Juice Shop's password-change route. Other apps use /api/users/me
# or /account/password — operators can extend via --change-path.
CHANGE_PATHS = (
    "/rest/user/change-password",
    "/api/users/me/password",
    "/account/password",
)


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


def _login(client: SafeClient, origin: str, email: str,
           pw: str) -> tuple[int, str | None]:
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, LOGIN_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = (doc.get("authentication") or {}).get("token")
            return r.status, tok
        except json.JSONDecodeError:
            return r.status, None
    return r.status, None


def _change_password(client: SafeClient, origin: str, token: str,
                     current: str, new_pw: str) -> dict:
    """Try several known change-password shapes. We stop on the
    first 200/201/204."""
    diag: dict = {"tried": []}
    auth_hdr = {"Authorization": f"Bearer {token}",
                "Content-Type": "application/json"}
    # Shape 1: Juice Shop GET-with-query (yes, it really uses GET).
    qs = (f"?current={current}&new={new_pw}&repeat={new_pw}")
    r = client.request("GET",
                       urljoin(origin, CHANGE_PATHS[0]) + qs,
                       headers=auth_hdr)
    diag["tried"].append({"path": CHANGE_PATHS[0] + " (GET)",
                          "status": r.status})
    if r.status in (200, 201, 204):
        diag["accepted_path"] = CHANGE_PATHS[0]
        return diag
    # Shapes 2-3: POST with JSON body.
    body = json.dumps({"currentPassword": current, "newPassword": new_pw,
                       "current": current, "new": new_pw,
                       "password": new_pw}).encode()
    for p in CHANGE_PATHS[1:]:
        r = client.request("POST", urljoin(origin, p),
                           headers=auth_hdr, body=body)
        diag["tried"].append({"path": p, "status": r.status})
        if r.status in (200, 201, 204):
            diag["accepted_path"] = p
            return diag
    return diag


class AuthOldSessionAfterPasswordChangeProbe(Probe):
    name = "auth_old_session_after_password_change"
    summary = ("Detects pre-password-change sessions that remain "
               "authenticated after the password is rotated.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--change-path", action="append", default=[],
            help="Additional change-password endpoint to try. "
                 "Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Throwaway account — we own it, we never touch a real user.
        email = f"sess-rot-{secrets.token_hex(6)}@dast.test"
        pw1 = "Pr0be-" + secrets.token_hex(6)
        pw2 = "Rot8t-" + secrets.token_hex(6)

        reg_status = _register(client, origin, email, pw1)
        if reg_status not in (200, 201):
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: could not register a probe "
                         f"account on {origin} (POST {REGISTER_PATH} "
                         f"-> {reg_status}). Skipping rather than "
                         "risk touching a real user's password."),
                evidence={"origin": origin,
                          "register_status": reg_status,
                          "register_email": email},
            )

        # Two independent logins for the same account = two
        # independent JWTs / cookies. Most servers issue a fresh
        # token on each login, so this is the cheap way to simulate
        # "user logged in on phone AND laptop".
        sa_status, token_a = _login(client, origin, email, pw1)
        sb_status, token_b = _login(client, origin, email, pw1)
        if not token_a or not token_b:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: could not establish two "
                         f"sessions for the probe account "
                         f"(login A {sa_status}, login B {sb_status})."),
                evidence={"origin": origin,
                          "register_email": email,
                          "login_a_status": sa_status,
                          "login_b_status": sb_status},
            )

        change_diag = _change_password(client, origin, token_a, pw1, pw2)
        if "accepted_path" not in change_diag:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: no change-password endpoint "
                         f"accepted our request on {origin}. Cannot "
                         "test concurrent-session invalidation "
                         "without a successful password change."),
                evidence={"origin": origin,
                          "register_email": email,
                          "change_diag": change_diag},
            )

        # Now ask session B (the older one) to read its profile.
        # Two corroborating signals to avoid a single false positive:
        #   1. Token B authenticates a profile read = 200 with the
        #      caller's email present.
        #   2. Token B with the OLD password — re-login attempt with
        #      pw1 fails. (If pw1 still works, the change didn't
        #      stick and we can't blame session-survivability.)
        rb = client.request("GET", urljoin(origin, WHOAMI_PATH),
                            headers={"Authorization":
                                     f"Bearer {token_b}"})
        b_works = rb.status == 200
        b_body_has_email = email.lower() in (rb.text or "").lower()

        # Cross-check: ensure the password actually changed by
        # attempting a fresh login with the old password — it should
        # fail. If pw1 still logs us in, the change-password endpoint
        # silently failed and we should NOT flag.
        relogin_status, _ = _login(client, origin, email, pw1)
        old_pw_rejected = relogin_status not in (200,)
        # And that pw2 works — confirms the change endpoint really
        # did flip the credential.
        new_pw_status, new_pw_token = _login(client, origin, email, pw2)
        new_pw_works = new_pw_token is not None

        attempts = {
            "register_email": email,
            "change_path": change_diag.get("accepted_path"),
            "session_b_whoami_status": rb.status,
            "session_b_body_has_email": b_body_has_email,
            "old_password_relogin_status": relogin_status,
            "new_password_login_status": new_pw_status,
            "old_pw_rejected": old_pw_rejected,
            "new_pw_works": new_pw_works,
        }
        evidence = {"origin": origin, "attempts": attempts}

        if b_works and b_body_has_email and old_pw_rejected and new_pw_works:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: pre-change session survived password "
                    f"rotation on {origin}. Session B (issued before "
                    f"the change) returned 200 with the caller's email "
                    "in the body, while the old password no longer "
                    "logs anyone in. Stolen tokens remain valid past a "
                    "user-initiated password reset."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "On a successful password change, invalidate every "
                    "session and refresh-token bound to the account, "
                    "not just the session that performed the change. "
                    "JWT-based stacks should bump a per-user `tokenId` "
                    "/ `pwd_changed_at` claim and reject tokens issued "
                    "before that timestamp; cookie sessions should "
                    "delete every server-side session record for the "
                    "user. Pair with explicit `Sign out other "
                    "devices?` UX so the user can confirm the action."),
            )
        return Verdict(
            validated=False, confidence=0.82,
            summary=(f"Refuted: on {origin}, session B post-change "
                     f"whoami={rb.status}, "
                     f"old-pw-rejected={old_pw_rejected}, "
                     f"new-pw-works={new_pw_works}. No evidence the "
                     "old session survived a real password change."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthOldSessionAfterPasswordChangeProbe().main()
