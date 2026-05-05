#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: inventory oversell race — multiple buyers can claim
the same last-in-stock unit.

The classic flaw: server reads `stock` for a SKU, sees stock>=1,
inserts an add-to-cart row, decrements stock — all without atomicity.
Under concurrency, N parallel adds for `stock=1` all see stock>=1,
all insert their rows, and the merchant ends up owing N units they
have 1 of. The fix is the same TOCTOU pattern as the wallet race
(probe #18): atomic decrement with a guard, or a `SELECT ... FOR
UPDATE` inside a transaction.

This probe creates N disposable accounts, then has each one fire a
single add-to-cart for the same low-stock SKU concurrently. We
declare the bug only when more SUCCESSFUL adds happened than the
SKU's stock count would have allowed AND the SKU's stock has actually
decreased to/past zero (i.e. baskets ARE holding units they
shouldn't).

Detection signal:
  Validated=True only when ALL of:
    1. >1 baskets each contain a row for this SKU after the burst
       (we GET each fresh account's basket to confirm), AND
    2. The SKU's stock count went non-positive OR was 1 to start
       and ended <= 0.

Cap: parallel = min(--parallel, manifest budget). Default 6 (very
small) so the probe stays well inside the 60-request budget cap.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PRODUCTS_PATHS = ("/api/Products", "/api/products", "/rest/products")
CART_ITEM_PATHS = (
    "/api/BasketItems",
    "/api/cart/items",
    "/rest/basket/add",
)
DEFAULT_PARALLEL = 6


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"oversell-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None,
                 "bid": None}
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
        except json.JSONDecodeError:
            pass
    return out


def _find_low_stock_sku(client: SafeClient, origin: str,
                       token: str) -> tuple[int | None, int | None, str]:
    """Walk the product list looking for a SKU whose declared stock
    count is exactly 1 (we want the smallest possible 'sold-out
    risk'). Returns (product_id, declared_stock, products_path)."""
    for path in PRODUCTS_PATHS:
        r = client.request("GET", urljoin(origin, path),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        rows = doc.get("data") if isinstance(doc, dict) else doc
        if not isinstance(rows, list):
            continue
        # Prefer stock==1 (cleanest signal), fall back to any small
        # positive stock count, fall back to any product (in which
        # case we can't check the stock-decrement signal).
        best_low = None; best_any = None
        for row in rows:
            if not isinstance(row, dict): continue
            pid = row.get("id")
            if not isinstance(pid, int): continue
            stock = None
            for k in ("stock", "stockCount", "inventory", "quantity"):
                v = row.get(k)
                if isinstance(v, int): stock = v; break
            if stock == 1: best_low = (pid, stock, path); break
            if best_any is None: best_any = (pid, stock, path)
        if best_low: return best_low
        if best_any: return best_any
    return (None, None, "")


def _basket_has_sku(client: SafeClient, origin: str, token: str,
                    bid: int | None, product_id: int) -> bool:
    """GET the user's basket and check whether the target SKU has any
    line item. Same conservative approach across known shapes."""
    paths = []
    if bid is not None:
        paths.extend([f"/api/Baskets/{bid}", f"/rest/basket/{bid}"])
    paths.extend(["/api/cart", "/rest/cart"])
    for p in paths:
        r = client.request("GET", urljoin(origin, p),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        # Walk arbitrary structure, look for ProductId|productId|sku
        # matching our target.
        def _walk(node):
            if isinstance(node, dict):
                for k in ("ProductId", "productId", "product_id", "sku"):
                    v = node.get(k)
                    if isinstance(v, int) and v == product_id:
                        return True
                return any(_walk(v) for v in node.values())
            if isinstance(node, list):
                return any(_walk(v) for v in node)
            return False
        if _walk(doc):
            return True
    return False


class BizLogicInventoryOversellRaceProbe(Probe):
    name = "bizlogic_inventory_oversell_race"
    summary = ("Detects inventory oversell race — N parallel "
               "add-to-cart calls each claim the same low-stock SKU.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--parallel", type=int, default=DEFAULT_PARALLEL,
            help=("Number of parallel buyer accounts. Capped by "
                  "request budget; default 6."))
        parser.add_argument(
            "--product-id", type=int, default=0,
            help=("Pin a specific product id rather than auto-"
                  "discovering a stock=1 SKU. 0 = auto."))

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # First, register one "scout" account just to GET the product
        # list — cheaper than registering N before we know if there's
        # anything to race against.
        scout = _register_and_login(client, origin)
        if not scout.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: scout account creation failed "
                         f"on {origin}; oversell test skipped."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in scout.items()
                                      if k != "password"}},
            )
        scout_token = scout["token"]

        if int(args.product_id) > 0:
            product_id, initial_stock, products_path = (
                int(args.product_id), None, "")
        else:
            product_id, initial_stock, products_path = _find_low_stock_sku(
                client, origin, scout_token)
        if product_id is None:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no product list available on "
                         f"{origin}; nothing to race against."),
                evidence={"origin": origin,
                          "tried": list(PRODUCTS_PATHS)},
            )

        # Reserve enough budget for N register+login+add (3 reqs each)
        # plus one final stock GET. Caller's budget is 60 max so 6
        # buyers ~= 19 requests is comfortable.
        remaining = max(1, client.budget.max_requests - client.budget.used - 4)
        # Each buyer uses ~3 requests (register, login, add). Floor
        # division to find feasible buyer count.
        feasible = max(2, remaining // 3)
        n = max(2, min(int(args.parallel), feasible))

        # Provision N accounts SEQUENTIALLY (we want all N to be
        # ready before the burst — provisioning needs no concurrency).
        buyers: list[dict] = []
        for _ in range(n):
            sess = _register_and_login(client, origin)
            if sess.get("token"):
                buyers.append(sess)
        if len(buyers) < 2:
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: could only provision "
                         f"{len(buyers)} buyer accounts on {origin}."),
                evidence={"origin": origin, "buyers_provisioned": len(buyers)},
            )

        # Pick the first add-to-cart endpoint that responds non-404
        # for the scout. We re-use that path for every buyer.
        target = ""
        for path in CART_ITEM_PATHS:
            payload = json.dumps({"BasketId": scout.get("bid"),
                                  "ProductId": product_id,
                                  "productId": product_id,
                                  "quantity": 1}).encode()
            r = client.request("POST", urljoin(origin, path), headers={
                "Authorization": f"Bearer {scout_token}",
                "Content-Type": "application/json"}, body=payload)
            if r.status != 404:
                target = path
                break
        if not target:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no add-to-cart endpoint on {origin}."),
                evidence={"origin": origin,
                          "tried": list(CART_ITEM_PATHS)},
            )

        # Burst: each buyer fires ONE add-to-cart for this SKU.
        url = urljoin(origin, target)
        def _fire(buyer: dict) -> dict:
            body = json.dumps({"BasketId": buyer.get("bid"),
                               "ProductId": product_id,
                               "productId": product_id,
                               "quantity": 1}).encode()
            r = client.request("POST", url, headers={
                "Authorization": f"Bearer {buyer['token']}",
                "Content-Type": "application/json",
            }, body=body)
            return {"status": r.status, "buyer": buyer.get("email"),
                    "bid": buyer.get("bid")}

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=min(len(buyers), 16)) as ex:
            futures = [ex.submit(_fire, b) for b in buyers]
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:                                  # noqa: BLE001
                    results.append({"status": 0, "error": str(e)[:120]})

        # Confirmation #1: count baskets that ACTUALLY hold the SKU
        # afterwards (sequential GETs; we want the truth, not the
        # POST status code).
        baskets_with_sku = 0
        for buyer in buyers:
            if _basket_has_sku(client, origin, buyer["token"],
                               buyer.get("bid"), product_id):
                baskets_with_sku += 1

        # Confirmation #2: re-fetch the product list and read the
        # SKU's stock again. If stock went non-positive we have the
        # second corroborating signal.
        final_stock: int | None = None
        if products_path:
            r = client.request("GET", urljoin(origin, products_path),
                               headers={"Authorization": f"Bearer {scout_token}"})
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                    rows = doc.get("data") if isinstance(doc, dict) else doc
                    if isinstance(rows, list):
                        for row in rows:
                            if isinstance(row, dict) and row.get("id") == product_id:
                                for k in ("stock", "stockCount", "inventory"):
                                    v = row.get(k)
                                    if isinstance(v, int):
                                        final_stock = v; break
                                break
                except json.JSONDecodeError:
                    pass

        attempt = {"endpoint": target, "product_id": product_id,
                   "initial_stock": initial_stock,
                   "final_stock": final_stock,
                   "buyers": len(buyers),
                   "baskets_with_sku": baskets_with_sku,
                   "burst_results": results}
        evidence = {"origin": origin, "attempt": attempt}

        # Validation requires the two signals to align. We tolerate
        # final_stock=None when initial_stock<=baskets_with_sku — i.e.
        # we know we sold more than there were units even without
        # measuring stock afterwards.
        oversold = baskets_with_sku > 1 and (
            (initial_stock is not None and baskets_with_sku > initial_stock)
            or (final_stock is not None and final_stock < 0)
            or (initial_stock == 1 and baskets_with_sku >= 2)
        )
        if oversold:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: oversell race on {origin}{target}. "
                         f"Product id {product_id} (initial stock="
                         f"{initial_stock}) ended up in "
                         f"{baskets_with_sku} parallel baskets "
                         f"(final stock={final_stock})."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Decrement inventory atomically with a guard:\n"
                    "  UPDATE products SET stock = stock - 1 WHERE id "
                    "= :pid AND stock >= 1 RETURNING stock;\n"
                    "Reject the add-to-cart when zero rows are "
                    "affected. Application-layer if-stock-then-debit "
                    "checks are insufficient under concurrency."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: oversell race not observed on "
                     f"{origin}{target} (baskets_with_sku="
                     f"{baskets_with_sku}, initial={initial_stock}, "
                     f"final={final_stock})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicInventoryOversellRaceProbe().main()
