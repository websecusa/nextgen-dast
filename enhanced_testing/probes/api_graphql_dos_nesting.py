#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
GraphQL DoS via deeply-nested queries — depth-limit middleware
absent.

A GraphQL schema where ``Author -> Books -> Author -> Books -> ...``
recurses across types lets a single query expand exponentially.
A depth-6 query can already pull tens of thousands of rows,
saturating the database / serializer.

Defensive servers ship a ``graphql-depth-limit`` (or equivalent)
middleware that rejects queries past a configured depth (commonly
5 or 7). When that middleware is absent, the server happily plans
and executes the deeply-nested query.

CRITICAL safety constraint: we cap our test query at depth 6.
Going deeper risks actually impacting the target. Even at 6, the
query is bounded by the schema's natural fan-out — most schemas
return a manageable result. We pick the depth-6 boundary because
it is the most common default for ``graphql-depth-limit`` (5)
plus one — a server that rejects depth 6 is configured; one that
accepts depth 6 has no depth limit at all.

Detection signal:
  POST a depth-6 nested query → response is 200 AND the JSON
  body contains a fully nested structure (proves the server
  planned and executed it). If the server rejects with a
  GraphQL error, we refute.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
)

# Depth cap. NEVER raise this — the safety contract for this probe
# is that we don't fire deeper than depth 6.
MAX_DEPTH = 6


def _build_nested_query(depth: int) -> str:
    """Build a recursive query of the requested depth using
    introspection-only fields. ``__schema { types }`` exists on
    every spec-compliant GraphQL server, so we don't need to know
    the actual schema. Each level requests `kind` and recurses
    into `ofType` — a built-in chain of every GraphQL type.
    Depth-N here is N nested `ofType` selections."""
    inner = "name kind"
    for _ in range(depth):
        inner = "kind ofType { " + inner + " }"
    return ("{ __schema { types { fields { type { " + inner +
            " } } } } }")


def _measures_nesting(text: str, target_depth: int
                       ) -> tuple[bool, int]:
    """Returns (server_executed_to_target, observed_depth). We
    decode the JSON and count the maximum chain of `ofType`
    nestings actually present in the response. The server
    executed the full query iff observed_depth >= target_depth
    in at least one path."""
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return False, 0
    if not isinstance(doc, dict):
        return False, 0
    if doc.get("errors"):
        # Likely a depth-limit error — refute.
        return False, 0
    data = doc.get("data") or {}
    schema = (data.get("__schema") or {}) if isinstance(data, dict) else {}
    types = schema.get("types")
    if not isinstance(types, list):
        return False, 0

    # Walk the structure looking for the deepest ofType chain.
    def chain_depth(node) -> int:
        d = 0
        cur = node
        while isinstance(cur, dict):
            of = cur.get("ofType")
            if of is None and "ofType" not in cur:
                break
            cur = of
            if cur is None:
                break
            d += 1
        return d

    deepest = 0
    for t in types[:200]:
        if not isinstance(t, dict):
            continue
        for f in (t.get("fields") or [])[:50]:
            if not isinstance(f, dict):
                continue
            ty = f.get("type")
            d = chain_depth(ty) if isinstance(ty, dict) else 0
            if d > deepest:
                deepest = d
                if deepest >= target_depth:
                    return True, deepest
    return False, deepest


class ApiGraphqlDosNestingProbe(Probe):
    name = "api_graphql_dos_nesting"
    summary = ("Detects absence of GraphQL depth-limit middleware by "
               "submitting a depth-6 introspection query and "
               "verifying full execution.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional GraphQL endpoint to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(GRAPHQL_PATHS) + list(args.path or [])

        query = _build_nested_query(MAX_DEPTH)
        body = json.dumps({"query": query}).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request(
                "POST", urljoin(origin, p),
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"},
                body=body)
            row: dict = {"path": p, "status": r.status,
                          "size": r.size, "depth_attempted": MAX_DEPTH}
            if r.status == 200 and r.body:
                full, observed = _measures_nesting(r.text, MAX_DEPTH)
                row["observed_chain_depth"] = observed
                if full:
                    row["depth_limit_present"] = False
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "max_depth_tested": MAX_DEPTH,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: GraphQL endpoint at {origin}"
                    f"{confirmed['path']} executed a depth-"
                    f"{MAX_DEPTH} nested query without rejection. "
                    f"Observed chain depth in response: "
                    f"{confirmed['observed_chain_depth']}. The server "
                    "has no depth-limit middleware — an attacker can "
                    "submit deeper queries to amplify load."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Install a depth-limit plugin in the GraphQL "
                    "server:\n"
                    "  - Apollo Server: "
                    "`graphql-depth-limit` plugin, capped at 7 or 8.\n"
                    "  - express-graphql / graphql-yoga: "
                    "`createComplexityLimitRule({maximumComplexity: ...})`.\n"
                    "  - Hasura: set "
                    "`HASURA_GRAPHQL_QUERY_PLAN_CACHE_SIZE` and the "
                    "depth limits via metadata.\n"
                    "Combine with a complexity-limit plugin "
                    "(`graphql-cost-analysis`) — depth-limit alone "
                    "does not stop wide queries with large fan-out."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} GraphQL paths "
                     f"on {origin} with a depth-{MAX_DEPTH} query; "
                     "none executed the full nested structure."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiGraphqlDosNestingProbe().main()
