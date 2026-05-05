#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: self-referral credit — a user can sign up using their
OWN referral / invite / affiliate code and receive the referrer
credit, effectively printing money in a tight loop.

A correctly-implemented referral program checks at credit time that
the referee and referrer are different identities (different emails,
different payment fingerprints, different device fingerprints, ideally
all three). When the only check is "is the code valid", a single
attacker registers, learns their own code, registers a second account
with that code, and gets the credit. Combined with the trivially-
disposable email + the lack of a per-user ban list, the cycle is
unbounded.

This probe:
  1. Registers account A.
  2. Reads account A's referral code from its profile / referral
     endpoint.
  3. Registers account B using account A's code as the referrer.
  4. Reads account A's credit/balance — if it increased, the program
     has no self-referral guard.

Detection signal:
  Validated=True only when ALL of:
    1. Account A's credit/balance value AFTER B's registration is
       strictly greater than its value BEFORE, AND
    2. Account A's email/fingerprint matched account B's referrer-
       code claim (we used the same code we read from A).

Both gates required so we don't false-positive on a referral
program that simply credits everyone a signup bonus.
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

REFERRAL_PATHS = (
    "/api/users/me/referral",
    "/api/user/referral",
    "/api/referral",
    "/api/affiliate/code",
    "/rest/user/referral",
)
BALANCE_PATHS = (
    "/api/users/me",
    "/api/user/profile",
    "/api/wallet",
    "/rest/user/whoami",
)


def _register(client: SafeClient, origin: str,
              referrer_code: str | None = None) -> dict:
    """Create an account, optionally tagging the referrer code so the
    server's referral logic runs. Returns the email/password/token
    so the caller can log in and inspect state."""
    email = f"selfref-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    body = {"email": email, "password": pw,
            "passwordRepeat": pw,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe"}
    # Tag every plausible referrer-shaped field; harmless when unknown.
    if referrer_code:
        body["referralCode"] = referrer_code
        body["referrerCode"] = referrer_code
        body["affiliate"] = referrer_code
        body["referredBy"] = referrer_code
    out = {"email": email, "password": pw, "token": None}
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=json.dumps(body).encode())
    out["register_status"] = r.status
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=json.dumps({"email": email,
                                        "password": pw}).encode())
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
        except json.JSONDecodeError:
            pass
    return out


def _read_referral_code(client: SafeClient, origin: str,
                        token: str) -> tuple[str, str | None]:
    """Walk known referral endpoints; return (path, code) on first hit.
    Code shape varies wildly (UUID, base32 short, email-prefix); we
    accept any non-empty alphanumeric string."""
    for path in REFERRAL_PATHS:
        r = client.request("GET", urljoin(origin, path),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        for src in (doc, doc.get("data") if isinstance(doc, dict) else None):
            if not isinstance(src, dict):
                continue
            for key in ("code", "referralCode", "referrerCode",
                        "affiliate", "inviteCode"):
                v = src.get(key)
                if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_-]{4,64}", v or ""):
                    return path, v
    return "", None


def _read_balance(client: SafeClient, origin: str, token: str) -> float | None:
    for path in BALANCE_PATHS:
        r = client.request("GET", urljoin(origin, path),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        for src in (doc, doc.get("data") if isinstance(doc, dict) else None):
            if not isinstance(src, dict):
                continue
            for key in ("balance", "credit", "wallet", "referralCredit",
                        "rewardBalance"):
                v = src.get(key)
                if isinstance(v, (int, float)):
                    return float(v)
    return None


class BizLogicSelfReferralCreditProbe(Probe):
    name = "bizlogic_self_referral_credit"
    summary = ("Detects referral-program self-credit — same user can "
               "register a second account using their own referral code "
               "and receive the referrer credit.")
    safety_class = "probe"

    def add_args(self, parser):
        # No probe-specific args; runs end-to-end with defaults.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1 — register account A (referrer-to-be).
        a = _register(client, origin)
        if not a.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: account A could not be "
                         f"established on {origin}."),
                evidence={"origin": origin,
                          "session_a": {k: v for k, v in a.items()
                                        if k != "password"}},
            )

        # Step 2 — read A's referral code. If the program doesn't
        # exist, the probe is conclusively refuted.
        ref_path, code = _read_referral_code(client, origin, a["token"])
        if not code:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no referral-code endpoint on "
                         f"{origin}; nothing to self-refer to."),
                evidence={"origin": origin, "tried": list(REFERRAL_PATHS),
                          "session_a_email": a["email"]},
            )

        # Step 3 — measure A's balance BEFORE B registers.
        balance_before = _read_balance(client, origin, a["token"])

        # Step 4 — register account B using A's code.
        b = _register(client, origin, referrer_code=code)
        if not b.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: account B (with referrer "
                         f"code) could not be established on {origin}."),
                evidence={"origin": origin, "session_a_email": a["email"],
                          "session_b": {k: v for k, v in b.items()
                                        if k != "password"}},
            )

        # Step 5 — measure A's balance AFTER B registers.
        balance_after = _read_balance(client, origin, a["token"])

        attempt = {
            "referral_endpoint": ref_path,
            "code_observed": code,
            "balance_before": balance_before,
            "balance_after": balance_after,
            "account_a_email": a["email"],
            "account_b_email": b["email"],
        }
        evidence = {"origin": origin, "attempt": attempt}

        credit_observed = (
            isinstance(balance_before, float)
            and isinstance(balance_after, float)
            and balance_after > balance_before + 0.001
        )
        if credit_observed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: self-referral credit on {origin}. "
                         f"Account {a['email']} balance moved from "
                         f"{balance_before} to {balance_after} after "
                         f"second account ({b['email']}) registered "
                         f"using the same user's referral code."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "At credit time, refuse the referral when:\n"
                    "  - referee.email == referrer.email, or\n"
                    "  - referee.normalized_email matches referrer's "
                    "(strip plus-aliasing, lowercase, dotless gmail), "
                    "or\n"
                    "  - referee and referrer share device fingerprint "
                    "/ payment instrument / IP within a short window.\n"
                    "Apply the credit ONLY after referee meets a real "
                    "engagement threshold (first paid order, identity "
                    "verification) — not at signup."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: account A's balance did not increase "
                     f"after a second account registered with their "
                     f"referral code (before={balance_before}, "
                     f"after={balance_after})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicSelfReferralCreditProbe().main()
