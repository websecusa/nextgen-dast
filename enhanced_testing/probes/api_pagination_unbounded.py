#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
API misdesign: list endpoints honour an arbitrarily large `?limit=`.

A list endpoint that lets the caller dictate the page size with no
upper bound is two bugs at once: (a) every row in the table is
exfiltrable in one request -- excessive data exposure -- and (b)
the database does the unbounded scan, which is a denial-of-service
primitive against shared back-ends. Most apps "cap the limit"
client-side in the UI but ship a server-side handler that doesn't.

The high-fidelity signal is comparative: request the same endpoint
twice -- once with `?limit=10`, once with `?limit=10000` -- and
count the rows in each JSON response. A 10,000-row response on the
high-limit side AND > 10 rows AND exactly the count requested (or
> 1000) means the limit was honoured.

Detection signal:
  1. Pull a small list of candidate list-endpoints (`/api/Users`,
     `/api/Products`, `/api/Orders`, etc.).
  2. GET `<endpoint>?limit=10` and `<endpoint>?limit=10000`.
  3. Validate when the high-limit response carries >= 1000 rows AND
     more rows than the low-limit response.

Tested against:
  + OWASP Juice Shop  /api/Products?limit=10000 returns the full
                      product catalogue (~50 products) -- not
                      enough rows to validate (>1000 threshold);
                      may or may not fire depending on data volume.
  + nginx default site -> validated=False (no JSON list responses).

Read-only: GET only; no payload manipulation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints we expect to be paginated lists. The Juice Shop literals
# come first; followed by common REST scaffolding patterns.
LIST_PATHS = (
    "/api/Users",
    "/api/Products",
    "/api/Reviews",
    "/api/Feedbacks",
    "/api/Addresss",            # Juice Shop's intentional typo
    "/api/Cards",
    "/rest/products",
    "/api/products",
    "/api/orders",
    "/api/v1/users",
)

# Threshold above which "the server clearly honoured the limit" --
# 1000 rows in one response is well above any plausible legitimate
# default page size.
ROW_THRESHOLD = 1000


def _row_count(text: str) -> int | None:
    """Return the row count in the JSON list response, or None when
    the response isn't a list-shaped JSON. Looks at top-level array,
    `data` array, `items` array, `results` array, and `rows` array
    (covers the three or four conventional REST-paginator shapes)."""
    try:
        doc = json.loads(text or "")
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(doc, list):
        return len(doc)
    if isinstance(doc, dict):
        for key in ("data", "items", "results", "rows", "records"):
            v = doc.get(key)
            if isinstance(v, list):
                return len(v)
    return None


class ApiPaginationUnboundedProbe(Probe):
    name = "api_pagination_unbounded"
    summary = ("Detects list endpoints that honour an unbounded "
               "`?limit=` query parameter.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional list path to probe (repeatable).")
        parser.add_argument(
            "--high-limit", type=int, default=10000,
            help="The large limit value to test (default 10000). The "
                 "probe validates only when >= 1000 rows come back.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(LIST_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        high = int(args.high_limit or 10000)
        for p in paths:
            url_low  = urljoin(origin, p) + "?" + urlencode({"limit": 10})
            url_high = urljoin(origin, p) + "?" + urlencode({"limit": high})
            r_low  = client.request("GET", url_low)
            if r_low.status != 200 or not r_low.body:
                attempts.append({"path": p, "status_low": r_low.status,
                                  "skipped": True})
                continue
            count_low = _row_count(r_low.text)
            if count_low is None:
                attempts.append({"path": p, "status_low": r_low.status,
                                  "non_list": True})
                continue
            r_high = client.request("GET", url_high)
            count_high = (_row_count(r_high.text)
                          if r_high.status == 200 else None)
            row = {"path": p,
                   "status_low": r_low.status, "rows_low": count_low,
                   "status_high": r_high.status, "rows_high": count_high}
            if (count_high is not None
                    and count_high >= ROW_THRESHOLD
                    and count_high > count_low):
                row["unbounded"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "high_limit": high,
                    "row_threshold": ROW_THRESHOLD,
                    "paths_tested": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} returned "
                    f"{confirmed['rows_high']} rows for ?limit={high} "
                    f"vs {confirmed['rows_low']} for ?limit=10. The "
                    "server honours an unbounded page size -- one "
                    "request can exfiltrate every row of the underlying "
                    "table and load-test the back-end into a soft DoS."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Cap the `limit` parameter server-side at a small "
                    "number (50-100 is typical).\n"
                    "  - Express / Sequelize: `Math.min(parseInt(req.\n"
                    "    query.limit ?? 20, 10), 100)` before the "
                    "`findAll({ limit })` call.\n"
                    "  - Django REST: set "
                    "`REST_FRAMEWORK['DEFAULT_PAGINATION_CLASS']` and "
                    "the paginator's `max_page_size` attribute.\n"
                    "  - Rails: `params[:limit].to_i.clamp(1, 100)`.\n"
                    "  - GraphQL: refuse `first` / `last` arguments "
                    "above a per-type maximum at the resolver layer.\n"
                    "Then add a regression test that requests "
                    f"?limit={high} and asserts <= 100 rows."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} list paths on "
                     f"{origin}; none returned >= {ROW_THRESHOLD} rows "
                     f"for ?limit={high}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiPaginationUnboundedProbe().main()
