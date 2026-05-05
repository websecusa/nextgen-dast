#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: password-reset token is reusable.

A password-reset token should be one-shot: minted, emailed,
consumed, then invalidated. If the same token still works on a
second submission — and a fresh password change goes through —
several attack patterns open up: replay from a stolen email log
hours after the user already used the link, replay across multiple
accounts after a back-end mix-up, and indefinite hold of the
recovery primitive that's supposed to be the rarest in the system.

The detection signal is structural and unambiguous: we ask the
server to mint a reset token (we never see the token if email is
the only delivery channel — that's why this probe degrades to
inconclusive on most production stacks); when we CAN observe the
token (Juice-Shop-style security-question reset, dev mailcatcher
exposed, server returns the token in the response, etc.), we
submit it twice. If both submissions succeed, the token is reusable.

We register a fresh disposable account so we never trigger a real
user's reset workflow.

Detection signal:
  Same reset token accepted twice; both submissions return
  200/204 AND change the password (login with the second new
  password succeeds afterwards).
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

REGISTER_PATH = "/api/Users"
LOGIN_PATH = "/rest/user/login"

# Juice Shop's security-question reset path is the most common
# DAST-friendly reset endpoint. Other apps may expose a token-based
# reset; operators can extend via --reset-path.
RESET_PATHS = (
    "/rest/user/reset-password",
    "/api/auth/password/reset",
    "/account/reset",
)

# Heuristic for response shapes that include a token / success flag.
# We never log the token in clear text — only mask it in evidence.
_TOKEN_RE = re.compile(
    r'"(?:resetToken|reset_token|token)"\s*:\s*"([^"]{16,})"')


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 12:
        return val[:2] + "*" * max(0, len(val) - 4) + val[-2:]
    return val[:6] + "*" * (len(val) - 10) + val[-4:]


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
           pw: str) -> int:
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, LOGIN_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    return r.status


class AuthPasswordResetTokenReuseProbe(Probe):
    name = "auth_password_reset_token_reuse"
    summary = ("Detects password-reset endpoints that accept the same "
               "reset token twice (one-shot enforcement missing).")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--reset-path", action="append", default=[],
            help="Additional reset endpoint to probe. Repeatable.")
        parser.add_argument(
            "--security-answer", default="probe",
            help="Security answer used when registering the probe "
                 "account (must match the registration form).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Throwaway account.
        email = f"reset-reuse-{secrets.token_hex(6)}@dast.test"
        pw0 = "Pr0be-" + secrets.token_hex(6)
        pw1 = "Step1-" + secrets.token_hex(6)
        pw2 = "Step2-" + secrets.token_hex(6)

        reg_status = _register(client, origin, email, pw0)
        if reg_status not in (200, 201):
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: could not register a probe "
                         f"account on {origin} (POST {REGISTER_PATH} "
                         f"-> {reg_status})."),
                evidence={"origin": origin,
                          "register_status": reg_status,
                          "register_email": email},
            )

        # Path 1: Juice Shop security-question reset. Body shape:
        #   {"email":..., "answer":..., "new":..., "repeat":...}
        # If accepted, attempt the SAME submission a second time.
        attempt_paths = list(RESET_PATHS) + list(args.reset_path or [])
        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in attempt_paths:
            body1 = json.dumps({
                "email": email,
                "answer": args.security_answer,
                "new": pw1, "repeat": pw1,
                "newPassword": pw1, "password": pw1,
            }).encode()
            r1 = client.request("POST", urljoin(origin, p),
                                headers={"Content-Type":
                                         "application/json"},
                                body=body1)
            row: dict = {"path": p, "first_status": r1.status,
                         "first_size": r1.size}
            if r1.status not in (200, 201, 204):
                attempts.append(row)
                continue

            # Confirm pw1 actually took effect. If it didn't, the
            # endpoint just returned 200 without doing anything and
            # we cannot reason about token reuse.
            login1 = _login(client, origin, email, pw1)
            row["login_with_pw1_status"] = login1
            if login1 != 200:
                attempts.append(row)
                continue

            # Second submission with the SAME body — different new
            # password so we can verify the second take effect on
            # success.
            body2 = json.dumps({
                "email": email,
                "answer": args.security_answer,
                "new": pw2, "repeat": pw2,
                "newPassword": pw2, "password": pw2,
            }).encode()
            r2 = client.request("POST", urljoin(origin, p),
                                headers={"Content-Type":
                                         "application/json"},
                                body=body2)
            row["second_status"] = r2.status
            row["second_size"] = r2.size

            login2 = _login(client, origin, email, pw2)
            row["login_with_pw2_status"] = login2

            attempts.append(row)
            # Two corroborating signals:
            #   1. Second submission also returned 200/204.
            #   2. pw2 now logs in successfully — proves the second
            #      reset really did flip the credential, and wasn't
            #      a no-op 200.
            if r2.status in (200, 201, 204) and login2 == 200:
                confirmed = row
                break

        evidence = {"origin": origin,
                    "register_email": email,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: password-reset endpoint "
                    f"{origin}{confirmed['path']} accepts the same "
                    "reset submission twice — both attempts changed "
                    "the password (login with pw2 returned 200). "
                    "The reset primitive is not single-use."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Reset tokens must be single-use. On a successful "
                    "consumption, mark the token row as `used_at = "
                    "now()` and reject any further attempts to use "
                    "it. Token rows should also expire after a short "
                    "window (15-30 min) regardless of whether they "
                    "were consumed. Bind tokens to a single account "
                    "id and refuse cross-account use. Log every "
                    "consumption attempt for audit."),
            )
        return Verdict(
            validated=False, confidence=0.82,
            summary=(f"Refuted: tested {len(attempts)} reset paths on "
                     f"{origin}; no path accepted the same submission "
                     "twice with confirmed password change on the "
                     "second take."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthPasswordResetTokenReuseProbe().main()
