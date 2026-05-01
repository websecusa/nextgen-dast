#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization (BFLA): regular user fetches every user's order history.

`GET /rest/order-history/orders` should return only orders owned by
the caller. When the controller skips the per-user filter, every
order in the database comes back — emails, line items, addresses.

Detection signal:
  Authenticated GET /rest/order-history/orders → 200 with a JSON
  envelope where MORE THAN ONE distinct `email` (or UserId) appears.

Tested against:
  + OWASP Juice Shop  endpoint returns the full table → validated=True.
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

ORDERS_PATH = "/rest/order-history/orders"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"order-history-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None,
                 "user_email": email}
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


class OrderHistoryViewAllProbe(Probe):
    name = "authz_order_history_view_all"
    summary = ("Detects /rest/order-history/orders returning every "
               "user's orders to a non-admin caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=f"Inconclusive: no probe session on {origin}.",
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        own_email = sess["user_email"]
        url = urljoin(origin, ORDERS_PATH)
        r = client.request("GET", url, headers={
            "Authorization": f"Bearer {token}",
        })
        attempt = {"path": url, "status": r.status, "size": r.size}
        evidence = {"origin": origin, "session_email": own_email,
                    "attempt": attempt}

        if r.status != 200 or not r.body:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: order-history endpoint returned "
                         f"status {r.status}."),
                evidence=evidence,
            )
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            return Verdict(
                validated=False, confidence=0.6,
                summary="Inconclusive: response not JSON.",
                evidence=evidence,
            )
        rows = doc.get("data") if isinstance(doc, dict) else doc
        if not isinstance(rows, list):
            return Verdict(
                validated=False, confidence=0.6,
                summary="Inconclusive: response not a list of orders.",
                evidence=evidence,
            )

        # Walk the rows looking at the per-row owner key. Different
        # apps spell it differently; we accept email | UserId | userId.
        owners: set[str] = set()
        sample: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            for k in ("email", "Email", "userEmail", "UserId", "userId"):
                v = row.get(k)
                if v is not None:
                    owners.add(str(v))
                    if str(v) not in sample:
                        sample.append(str(v))
                    break
        attempt["row_count"]      = len(rows)
        attempt["distinct_owners"] = len(owners)
        attempt["sample_owners"]  = sample[:6]

        # We need at least two distinct owners — and at least one of
        # them must NOT be ours — to call this a leak. A single-owner
        # response could legitimately be the caller's own history.
        foreign = [o for o in owners if o != own_email and o != "0"]
        if len(owners) >= 2 and foreign:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: order-history at {origin} "
                         f"returned {len(rows)} orders spanning "
                         f"{len(owners)} distinct owners. Caller "
                         f"({own_email}) sees foreign owners — "
                         + ", ".join(foreign[:3]) + "."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Filter the orders query by `req.user.email` (or "
                    "`req.user.id`). The order-history view should "
                    "return ONLY the calling user's rows; admins use a "
                    "separate, role-gated endpoint for cross-tenant "
                    "views."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: order-history endpoint at {origin} "
                     f"returned {len(rows)} rows; no foreign owners "
                     "observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    OrderHistoryViewAllProbe().main()
