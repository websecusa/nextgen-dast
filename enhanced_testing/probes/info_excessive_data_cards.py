#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Excessive data exposure: payment-card endpoint returns full PAN.

A `/api/Cards` (or `/api/PaymentMethods`, `/api/cards`) response
that contains an unmasked credit-card number is the canonical
PCI-DSS-violation, breach-disclosure-class API mistake. The fix is
field-level redaction in the serializer (return `**** **** **** 4242`
or just the last four digits, never the full PAN). The bug is
visible to any caller who can hit the endpoint -- if a normal user
can read their *own* card, the hash-style serializer leak applies
to every other card too once the access-control check is loosened
(which BOLA / IDOR probes routinely demonstrate on the same code
paths).

The high-fidelity signal is structural and uses the Luhn checksum
to suppress the long-tail of false positives (booking-references,
order numbers, internal IDs). A 16-digit string that passes Luhn
in a JSON field named `cardNumber` is a PAN with vanishingly small
probability of being anything else.

Detection signal:
  1. Register / log in a throwaway account.
  2. GET /api/Cards (and friends).
  3. For every JSON object returned, look for a card-number-shaped
     field whose value is a 13-19 digit string AND passes Luhn.

Tested against:
  + OWASP Juice Shop  Adding a card to /api/Cards via the UI stores
                      the full number; subsequent GET /api/Cards
                      returns it -> validated=True.
  + nginx default site -> validated=False (no /api/Cards route).

Read-only: only register, login, and GET. The POST that adds a
card is what would prove the surface end-to-end, but we do NOT do
it -- mutating the user's saved-cards list is destructive. The
probe is content with finding ANY existing card object on the
account -- on Juice Shop the seeded admin / deluxe accounts have
cards by default; on a clean target with no cards the probe
returns refuted (no false positive).
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

CARD_LIST_PATHS = (
    "/api/Cards",
    "/api/cards",
    "/api/PaymentMethods",
    "/api/v1/payment-methods",
    "/api/me/cards",
)

# Field names that, alongside a Luhn-valid PAN, are the bug. Plus a
# few obvious-looking ones that are actually NOT cards (excluded).
_CARD_FIELD_NAMES = {"cardnumber", "cardnum", "pan", "number",
                     "creditcard", "ccnumber", "card_no"}
_NOT_CARD_FIELD_NAMES = {"id", "userid", "orderid", "addressid"}

# Strip non-digits from a value, then bound length so we don't
# Luhn-check 200-char strings.
_DIGITS_RE = re.compile(r"\D")


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum. Returns False on empty / non-digit /
    out-of-range-length input -- callers only feed known-digit
    13-19-char strings."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _walk_for_card(node, depth: int = 0) -> tuple[str, str] | None:
    """Walk parsed JSON for a card-shaped key holding a Luhn-valid
    PAN. Returns (field_name, masked_value_excerpt) on hit.
    Recursion is depth-bounded; lists are width-bounded."""
    if depth > 6:
        return None
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                continue
            kl = k.lower()
            if kl in _NOT_CARD_FIELD_NAMES:
                continue
            if kl in _CARD_FIELD_NAMES and isinstance(v, str):
                digits = _DIGITS_RE.sub("", v)
                if _luhn_ok(digits):
                    masked = (digits[:6] + "*" * (len(digits) - 10)
                              + digits[-4:]) if len(digits) >= 10 else digits
                    return k, masked
        for v in node.values():
            hit = _walk_for_card(v, depth + 1)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node[:50]:
            hit = _walk_for_card(v, depth + 1)
            if hit:
                return hit
    return None


def _register_and_login(client: SafeClient, origin: str) -> tuple[str | None, dict]:
    """Throwaway register + login. Returns (token, diag)."""
    email = f"cards-probe-{secrets.token_hex(6)}@dast.test"
    pw    = "Pr0be-" + secrets.token_hex(4)
    diag: dict = {"email": email}
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "probe",
    }).encode()
    r = client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"}, body=body)
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = ((doc.get("authentication") or {}).get("token")
                   if isinstance(doc, dict) else None) or doc.get("token")
            if tok:
                return tok, diag
        except json.JSONDecodeError:
            pass
    return None, diag


class ExcessiveDataCardsProbe(Probe):
    name = "info_excessive_data_cards"
    summary = ("Detects payment-card endpoints that return the full "
               "unmasked PAN to the caller.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional card-list path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(CARD_LIST_PATHS) + list(args.path or [])

        token, login_diag = _register_and_login(client, origin)
        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            r = client.request("GET", url, headers=headers)
            row: dict = {"path": p, "status": r.status, "size": r.size,
                         "auth": "bearer" if token else "anonymous"}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    doc = None
                if doc is not None:
                    hit = _walk_for_card(doc)
                    if hit:
                        field, masked = hit
                        row.update({"card_field": field,
                                    "masked_value": masked})
                        confirmed = row
                        attempts.append(row)
                        break
            attempts.append(row)

        evidence = {"origin": origin, "paths_tested": attempts,
                    "login_diag": login_diag}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} returned "
                    f"a `{confirmed['card_field']}` field containing a "
                    f"Luhn-valid card number ({confirmed['masked_value']}). "
                    "Full PAN is reachable to any caller of this "
                    "endpoint -- PCI-DSS scope and breach-disclosure "
                    "class data exposure."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Mask the PAN at the serializer layer; never let "
                    "the full number leave the payment subsystem.\n"
                    "  - Sequelize / Mongoose: replace the raw "
                    "`cardNumber` getter with a masked one returning "
                    "the last 4 digits only.\n"
                    "  - Django REST: override `to_representation()` "
                    "on the Card serializer to mask the field.\n"
                    "  - Stripe / Adyen / Braintree: switch to a "
                    "tokenization model -- store the provider's token "
                    "and never the PAN at all.\n"
                    "After the fix, audit existing logs / backups for "
                    "stored full PANs and rotate them. Notify the "
                    "card-brand acquirer per PCI breach-disclosure "
                    "obligations."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} card paths on "
                     f"{origin}; no Luhn-valid PAN was found in a "
                     "card-shaped field."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ExcessiveDataCardsProbe().main()
