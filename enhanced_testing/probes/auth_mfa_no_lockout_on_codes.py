#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: MFA verification endpoint has no lockout on
incorrect codes.

A 6-digit TOTP code has 1,000,000 possible values. With unlimited
attempts an attacker brute-forces the second factor in seconds and
the password-stolen attack chain completes. Correctly-configured
MFA endpoints lock the account (or apply a per-IP / per-account
exponential backoff) after a small number of bad codes — typically
5 — and surface that lockout to the client via 429 / Retry-After.

This probe registers a fresh disposable account with TOTP enrolled,
performs the first-factor login, and then submits N (default 20)
intentionally-wrong codes against the verify endpoint. It declares
the endpoint unprotected when:

  - all N submissions return the same generic "wrong code" status
    (typically 401);
  - no 429 / Retry-After / lockout-shaped response appears at any
    point in the sequence;
  - a follow-up first-factor login still works — the account
    itself wasn't locked.

We never log in as a real user. The probe budget is capped at 30
requests so even on a no-lockout server the impact is bounded.

Detection signal:
  20 sequential bad MFA codes for the probe account all return
  the same wrong-code status; no rate-limit headers; account stays
  reachable.
"""
from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REGISTER_PATH = "/api/Users"
LOGIN_PATH = "/rest/user/login"
DEFAULT_TRIALS = 20

# MFA verify endpoints across common stacks. We try the first one
# that gives a non-404 response with a "code" / "token" field
# acknowledged by the server.
MFA_VERIFY_PATHS = (
    "/rest/2fa/verify",
    "/api/auth/mfa/verify",
    "/api/auth/2fa",
    "/login/mfa",
)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _register_with_totp(client: SafeClient, origin: str, email: str,
                        pw: str) -> int:
    """Register a fresh account and request TOTP enrollment in one
    body — Juice Shop honors a `totpSecret` field at registration.
    Apps that don't recognize the field will still create the
    account; the MFA endpoint test below simply finds nothing to
    bind and returns inconclusive.
    """
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
        "totpSecret": "JBSWY3DPEHPK3PXP",
    }).encode()
    r = client.request("POST", urljoin(origin, REGISTER_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    return r.status


def _first_factor(client: SafeClient, origin: str, email: str,
                  pw: str) -> tuple[int, str | None]:
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, LOGIN_PATH),
                       headers={"Content-Type": "application/json"},
                       body=body)
    if r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            tok = (auth.get("token") or doc.get("token")
                   or doc.get("mfa_token") or doc.get("mfaToken"))
            return r.status, tok
        except json.JSONDecodeError:
            return r.status, None
    return r.status, None


class AuthMfaNoLockoutOnCodesProbe(Probe):
    name = "auth_mfa_no_lockout_on_codes"
    summary = ("Detects MFA verify endpoints that accept unlimited "
               "incorrect codes (no per-account lockout).")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--trials", type=int, default=DEFAULT_TRIALS,
            help=f"Number of bad-code submissions (default "
                 f"{DEFAULT_TRIALS}, capped by request budget).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        email = f"mfa-lock-{secrets.token_hex(6)}@dast.test"
        pw = "Pr0be-" + secrets.token_hex(6)

        reg_status = _register_with_totp(client, origin, email, pw)
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

        login_status, token = _first_factor(client, origin, email, pw)
        if not token:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: first-factor login on {origin} "
                         f"returned {login_status} with no recoverable "
                         "token; cannot exercise MFA verify endpoint "
                         "without one."),
                evidence={"origin": origin,
                          "register_email": email,
                          "first_factor_status": login_status},
            )

        # Find an MFA verify path that isn't a 404. We're picking
        # whichever path the app actually has; if none, abort.
        chosen_path = None
        path_diag: list[dict] = []
        for p in MFA_VERIFY_PATHS:
            body = json.dumps({"totpToken": "000000",
                               "code": "000000"}).encode()
            r = client.request("POST", urljoin(origin, p),
                               headers={"Content-Type":
                                        "application/json",
                                        "Authorization":
                                        f"Bearer {token}"},
                               body=body)
            path_diag.append({"path": p, "status": r.status})
            # 4xx other than 404 means "endpoint exists, my body
            # was wrong" — that's exactly what we want.
            if r.status in (400, 401, 403, 422):
                chosen_path = p
                break

        if not chosen_path:
            return Verdict(
                validated=None, ok=True, confidence=0.5,
                summary=(f"Inconclusive: no MFA verify endpoint found "
                         f"on {origin} (tried "
                         f"{len(MFA_VERIFY_PATHS)} known paths)."),
                evidence={"origin": origin,
                          "register_email": email,
                          "first_factor_status": login_status,
                          "path_diag": path_diag},
            )

        # Brute-force loop. Generate distinct wrong codes (so the
        # server can't no-op-cache identical submissions).
        verify_url = urljoin(origin, chosen_path)
        statuses: list[int] = []
        retry_after_seen = False
        ratelimit_seen = False
        t_start = time.monotonic()
        n = max(2, int(args.trials))
        for i in range(n):
            # Wrong code that won't randomly hit the live TOTP value.
            # 000000-000099 covers a vanishingly small fraction of
            # the keyspace — well under 0.01% of being correct.
            code = f"{i:06d}"
            body = json.dumps({"totpToken": code, "code": code}).encode()
            r = client.request("POST", verify_url,
                               headers={"Content-Type":
                                        "application/json",
                                        "Authorization":
                                        f"Bearer {token}"},
                               body=body)
            statuses.append(r.status)
            if _hdr(r.headers or {}, "Retry-After"):
                retry_after_seen = True
            if any(_hdr(r.headers or {}, h) for h in
                   ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                    "RateLimit-Limit", "RateLimit-Remaining")):
                ratelimit_seen = True
            if r.status == 429:
                # Lockout IS in place; we can stop early.
                break
        elapsed_total_ms = int((time.monotonic() - t_start) * 1000)

        # Cross-check: account itself should still be reachable. If
        # the account got locked entirely (rather than the verify
        # endpoint being rate-limited), we don't flag — that's a
        # different shape of behavior we shouldn't conflate.
        relogin_status, _ = _first_factor(client, origin, email, pw)

        all_same = (len(set(statuses)) == 1
                    and statuses[0] in (400, 401, 403, 422))
        attempts = {
            "verify_path": chosen_path,
            "trials_attempted": len(statuses),
            "statuses": statuses,
            "all_same_status": all_same,
            "retry_after_seen": retry_after_seen,
            "ratelimit_header_seen": ratelimit_seen,
            "elapsed_total_ms": elapsed_total_ms,
            "post_run_first_factor_status": relogin_status,
        }
        evidence = {"origin": origin,
                    "register_email": email,
                    "attempts": attempts,
                    "path_diag": path_diag}

        if all_same and not retry_after_seen and not ratelimit_seen \
                and 429 not in statuses and relogin_status == 200:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: {len(statuses)} sequential incorrect "
                    f"MFA codes against {origin}{chosen_path} all "
                    f"returned {statuses[0]} within "
                    f"{elapsed_total_ms} ms; no 429, no Retry-After, "
                    "no lockout. Account remained reachable on "
                    "follow-up login. The TOTP keyspace (~10^6) is "
                    "brute-forceable in seconds."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Apply per-account and per-IP rate limits on the "
                    "MFA verify endpoint. A common policy: 5 "
                    "incorrect codes within 15 minutes triggers a "
                    "30-minute lockout AND notifies the user. Pair "
                    "with `Retry-After` headers so legitimate "
                    "clients can back off cleanly. Log every "
                    "incorrect code to a dedicated audit channel; "
                    "trigger account-takeover alerts on >10 "
                    "incorrect codes within an hour."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: MFA verify on {origin}{chosen_path} "
                     f"appears protected (429 in statuses="
                     f"{429 in statuses}, retry_after="
                     f"{retry_after_seen}, ratelimit="
                     f"{ratelimit_seen}, post-run login="
                     f"{relogin_status})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthMfaNoLockoutOnCodesProbe().main()
