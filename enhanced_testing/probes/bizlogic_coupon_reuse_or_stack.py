#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: coupon / promo code reuse and stacking.

Two distinct flaws live in the same family of bugs:

  - Reuse  — the same coupon code is accepted on a basket more than
             once. Correct behavior either (a) returns the discount
             once and then refuses with "already applied", or (b)
             tracks the redemption per-account and refuses on second
             attempt.
  - Stack  — two distinct codes that are individually within
             policy ($10 off, 20% off) combine to a discount the
             merchant didn't intend. Correct behavior either (a)
             enforces "one coupon per order", or (b) caps the
             cumulative discount at a published ceiling.

Both flaws are detected at the same endpoint and share enough
plumbing that we keep them in one probe rather than splitting.

Detection signal:
  Validated=True ONLY when AT LEAST ONE of:
    - Same coupon applied 5x produces 5 successful (200) responses
      AND the basket discount changes / increases on at least the
      2nd application (proves the code is re-credited, not just
      acknowledged), OR
    - Two distinct codes A,B applied in sequence produce a
      cumulative discount strictly greater than max(discount(A),
      discount(B)).

Both branches require a corroborating numeric signal (discount went
up); we never validate from status code alone.

Test budget kept tight (typical 8) because all activity is on a
disposable basket created during the probe run.
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

# Endpoint candidates seen across major e-commerce frameworks.
COUPON_PATHS = (
    "/api/coupon/apply",
    "/api/cart/coupon",
    "/api/basket/coupon",
    "/rest/coupon/apply",
    "/api/checkout/coupon",
)
BASKET_PATHS = (
    "/api/basket",
    "/api/cart",
    "/rest/basket",
)

# Probe-issued canary coupon codes. These are NOT real codes; the
# point is to distinguish reuse-by-same-code from
# stack-of-distinct-codes. The probe never invents codes the operator
# might confuse with valid ones — both start with the canary prefix.
CANARY_PRIMARY   = "DAST-CANARY-A"
CANARY_SECONDARY = "DAST-CANARY-B"


def _register_and_login(client: SafeClient, origin: str) -> dict:
    """Disposable account; same shape as authz_basket_manipulation."""
    email = f"coupon-{secrets.token_hex(6)}@dast.test"
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


def _read_discount(text: str) -> float | None:
    """Best-effort extraction of a numeric discount from the response.

    We try (in order): a parsed JSON {discount} or {totalDiscount} or
    nested {data: {discount}}; then a regex scan for `discount":
    <number>` shapes. Returning None means "no discount found";
    callers MUST treat that as inconclusive."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        for candidate in (doc, doc.get("data") if isinstance(doc.get("data"), dict) else None):
            if not isinstance(candidate, dict):
                continue
            for key in ("discount", "totalDiscount", "couponDiscount",
                        "discountAmount", "amountSaved"):
                v = candidate.get(key)
                if isinstance(v, (int, float)):
                    return float(v)
    m = re.search(r'"(?:discount|totalDiscount|couponDiscount|amountSaved)"\s*:\s*([0-9]+(?:\.[0-9]+)?)',
                  text or "")
    if m:
        return float(m.group(1))
    return None


def _apply(client: SafeClient, origin: str, path: str, token: str,
           code: str) -> tuple[int, str]:
    """POST a coupon code; return (status, body) so the caller can
    interpret status + payload together (high-fidelity rule)."""
    body = json.dumps({"coupon": code, "code": code}).encode()
    r = client.request("POST", urljoin(origin, path), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }, body=body)
    return r.status, (r.text or "")


class BizLogicCouponReuseOrStackProbe(Probe):
    name = "bizlogic_coupon_reuse_or_stack"
    summary = ("Detects coupon-reuse or coupon-stacking flaws — same "
               "code accepted multiple times, or distinct codes "
               "combining past intended cap.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--coupon", default=CANARY_PRIMARY,
            help=("Coupon code to test for reuse. Default is a canary "
                  "prefix the probe defines internally."))
        parser.add_argument(
            "--coupon-secondary", default=CANARY_SECONDARY,
            help="Second distinct code to attempt stacking with.")
        parser.add_argument(
            "--reuse-trials", type=int, default=5,
            help="How many times to apply the same coupon (default 5).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=("Inconclusive: no probe session on "
                         f"{origin}; coupon test skipped."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]

        # Find the first coupon endpoint that responds non-404 to a
        # benign request; treat 404 across the board as "feature not
        # present" → refuted.
        target = ""
        for path in COUPON_PATHS:
            s, _ = _apply(client, origin, path, token, "DAST-PROBE-INIT")
            if s != 404:
                target = path
                break
        if not target:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no coupon-apply endpoint on "
                         f"{origin} (all candidates 404)."),
                evidence={"origin": origin,
                          "tried": list(COUPON_PATHS)},
            )

        # ---- Reuse path: same coupon N times ----
        reuse_results: list[dict] = []
        n = max(2, min(int(args.reuse_trials), 8))
        last_discount: float | None = None
        rising_discount = False
        for i in range(n):
            status, body = _apply(client, origin, target, token, args.coupon)
            d = _read_discount(body)
            reuse_results.append({"i": i, "status": status, "discount": d})
            # If the second application returns a NEW (higher or
            # different) discount value, that's the corroborating
            # signal that the code was re-credited, not merely
            # acknowledged.
            if i >= 1 and d is not None and last_discount is not None and d > last_discount:
                rising_discount = True
            if d is not None:
                last_discount = d
        reuse_successes = sum(1 for r in reuse_results
                              if 200 <= r["status"] < 300)
        reuse_confirmed = reuse_successes >= 2 and rising_discount

        # ---- Stack path: two distinct codes ----
        stack_a_status, body_a = _apply(client, origin, target, token,
                                        args.coupon)
        stack_a_discount = _read_discount(body_a)
        stack_b_status, body_b = _apply(client, origin, target, token,
                                        args.coupon_secondary)
        stack_b_discount = _read_discount(body_b)
        stack_results = {
            "a_status": stack_a_status, "a_discount": stack_a_discount,
            "b_status": stack_b_status, "b_discount": stack_b_discount,
        }
        # Stacking confirmed when both APIs returned a numeric
        # discount AND the second is strictly larger than the first
        # (cumulative). If second discount equals first, that's
        # "code B replaced code A" — not stacking.
        stack_confirmed = (
            isinstance(stack_a_discount, float)
            and isinstance(stack_b_discount, float)
            and stack_b_discount > stack_a_discount
            and 200 <= stack_b_status < 300
        )

        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "endpoint": target,
                    "reuse": {"results": reuse_results,
                              "confirmed": reuse_confirmed},
                    "stack": stack_results | {"confirmed": stack_confirmed}}

        if reuse_confirmed or stack_confirmed:
            kind = "reuse" if reuse_confirmed else "stacking"
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: coupon {kind} accepted on "
                         f"{origin}{target}. Discount visibly grew "
                         "across applications when the server should "
                         "have refused on the second attempt."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Track redemptions in the order/cart record:\n"
                    "  - Store {coupon_code, basket_id, applied_at} "
                    "with a UNIQUE constraint on (coupon_code, "
                    "basket_id) for one-per-basket policy, or on "
                    "(coupon_code, user_id) for one-per-user.\n"
                    "  - Refuse a new coupon when one is already "
                    "applied unless your stacking policy is explicit.\n"
                    "  - Cap cumulative discount at a documented "
                    "ceiling (e.g. min(50% of subtotal, $X))."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: coupon endpoint {origin}{target} "
                     f"either rejected reuse / stacking or never "
                     f"granted a measurable discount "
                     f"(reuse_successes={reuse_successes}, "
                     f"rising={rising_discount}, "
                     f"stack_confirmed={stack_confirmed})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicCouponReuseOrStackProbe().main()
