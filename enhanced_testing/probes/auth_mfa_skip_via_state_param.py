#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: MFA enrollment / second factor can be skipped by
re-using the partially-authenticated session against protected
endpoints.

A correct two-factor flow looks like:

  POST /login (username + password)
    -> 200 with a "step-up required" indicator and a session cookie
       OR a short-lived `mfa_token` that is NOT a full auth token.
  POST /login/mfa (TOTP / SMS code)
    -> 200 issuing the full session cookie / JWT.

Several common bugs collapse this to a single factor:

  - The session cookie issued at step 1 is the SAME cookie issued
    at step 2 (some apps just flip a `mfa_passed = true` field
    server-side, but the cookie is already valid for protected
    routes).
  - Step 1 issues a JWT with `aud=full` instead of `aud=mfa-pending`,
    so attempts to skip step 2 succeed.
  - The "MFA required" check lives on the MFA verification endpoint
    only, not on the protected business endpoints — an attacker who
    has the password skips the verify call entirely.

We register a fresh disposable account, enroll MFA only if the app
demands it for our test account, perform the first-factor login,
and then call known protected endpoints with the resulting token.
If those calls return 200 with shape that proves identity (whoami,
profile, etc.), the MFA gate is bypassable.

Detection signal:
  Two-step login API exists (step 1 returns a token / cookie AND
  body contains an MFA hint) AND that step-1 token authenticates a
  protected GET (whoami / profile / orders) without ever calling
  step 2.
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
WHOAMI_PATH = "/rest/user/whoami"

# Body-shape strings that indicate "first factor passed, second
# factor required". Strict allow-list — we don't want to match the
# word "mfa" in unrelated text.
_MFA_HINT_RE = re.compile(
    r"\b(?:mfa[_ -]?required"
    r"|two[_ -]?factor"
    r"|2fa[_ -]?required"
    r"|otp[_ -]?required"
    r"|totp[_ -]?required"
    r"|verify[_ -]?code"
    r"|step[_ -]?up"
    r"|challenge[_ -]?required)\b",
    re.IGNORECASE,
)

# Endpoints that should require FULL auth, not MFA-pending. We
# probe these with the first-factor token to see if the gate holds.
PROTECTED_PROBE_PATHS = (
    WHOAMI_PATH,
    "/api/Users/me",
    "/rest/user/profile",
)


def _register(client: SafeClient, origin: str, email: str,
              pw: str) -> int:
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe",
                       "totpSecret": "JBSWY3DPEHPK3PXP"}).encode()
    r = client.request("POST", urljoin(origin, REGISTER_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    return r.status


def _first_factor_login(client: SafeClient, origin: str,
                        email: str, pw: str) -> dict:
    """POST step 1; return the response body, status, and any
    token/cookie issued."""
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, LOGIN_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body, follow_redirects=False)
    out = {"status": r.status, "body_excerpt": (r.text or "")[:300]}
    token = None
    if r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            token = auth.get("token") or doc.get("token") \
                or doc.get("mfa_token") or doc.get("mfaToken")
        except json.JSONDecodeError:
            pass
    out["token"] = token
    return out


class AuthMfaSkipViaStateParamProbe(Probe):
    name = "auth_mfa_skip_via_state_param"
    summary = ("Detects MFA flows that issue a token after first "
               "factor that already authenticates protected "
               "endpoints (MFA gate bypass).")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--target-email", default="admin@juice-sh.op",
            help="Email used to test MFA-shape responses if the "
                 "registration path doesn't exist on the target. "
                 "Defaults to admin@juice-sh.op (matches the seed-"
                 "account convention).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Always test against a freshly registered account so we
        # never knowingly trigger MFA on a real user. If
        # registration fails (e.g. the app gates the seed account),
        # we report inconclusive rather than fall back to the seed
        # email — exposing a real user's MFA flow to repeated probes
        # would generate noisy security alerts.
        email = f"mfa-skip-{secrets.token_hex(6)}@dast.test"
        pw = "Pr0be-" + secrets.token_hex(6)
        reg_status = _register(client, origin, email, pw)
        if reg_status not in (200, 201):
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: could not register a probe "
                         f"account on {origin} (POST {REGISTER_PATH} "
                         f"-> {reg_status}). Skipping rather than "
                         f"prod a real user's MFA workflow."),
                evidence={"origin": origin,
                          "register_status": reg_status,
                          "register_email": email},
            )

        first = _first_factor_login(client, origin, email, pw)
        body_excerpt = first.get("body_excerpt") or ""
        mfa_hinted = bool(_MFA_HINT_RE.search(body_excerpt))
        token = first.get("token")
        attempts: list[dict] = []
        evidence_base = {
            "origin": origin,
            "register_email": email,
            "first_factor_status": first.get("status"),
            "first_factor_token_present": token is not None,
            "first_factor_mfa_hint": mfa_hinted,
            "first_factor_body_excerpt": body_excerpt,
        }

        # If the server didn't issue any token AND didn't hint at
        # MFA, there's nothing to skip — refute cleanly.
        if not token or not mfa_hinted:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: first-factor login on {origin} did "
                         "not produce both a token AND an MFA hint "
                         f"(token_present={token is not None}, "
                         f"mfa_hint={mfa_hinted}). MFA-bypass-by-"
                         "state-skip does not apply here."),
                evidence=evidence_base,
            )

        # The MFA-skip test: walk the protected endpoints with the
        # first-factor token. If any of them returns 200 with the
        # caller's email present, the MFA gate is bypassable.
        confirmed: dict | None = None
        for p in PROTECTED_PROBE_PATHS:
            r = client.request("GET", urljoin(origin, p),
                               headers={"Authorization":
                                        f"Bearer {token}"})
            row = {"path": p, "status": r.status, "size": r.size,
                   "echoes_email": False}
            if r.status == 200 and r.body:
                if email.lower() in (r.text or "").lower():
                    row["echoes_email"] = True
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {**evidence_base, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: first-factor token from {origin} "
                    f"authenticated {confirmed['path']} (status 200, "
                    "response body includes the caller's email) "
                    "WITHOUT a step-up MFA verification call. MFA "
                    "is enforced on the verify endpoint only, not on "
                    "protected business endpoints."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "The MFA gate must live on every protected "
                    "endpoint, not only on the MFA-verify route. "
                    "Make the first-factor token a short-lived "
                    "single-purpose `mfa_pending` credential whose "
                    "ONLY accepted use is calling the MFA verify "
                    "endpoint; it must not authenticate any other "
                    "route. Issue the full session token only after "
                    "the second factor is verified. Mark each token "
                    "with an explicit `auth_level` claim and reject "
                    "any token whose level is below what the "
                    "endpoint requires."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: first-factor token on {origin} did not "
                     f"authenticate any of {len(PROTECTED_PROBE_PATHS)} "
                     "protected endpoints — the MFA gate appears to "
                     "hold."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthMfaSkipViaStateParamProbe().main()
