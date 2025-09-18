#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: GraphQL endpoint exposed (with introspection).

GraphQL apps tend to expose a single `/graphql` endpoint that both
serves queries and answers introspection. Production deployments
should disable introspection (Apollo: `introspection: false`); when
they don't, an attacker downloads the full schema and walks every
declared type / field, including admin-only mutations.

Detection signal:
  POST /graphql with the introspection query
  `{__schema{types{name}}}` → 200 with `__schema` populated. The
  presence of `__schema` is unambiguous — nothing else returns it.

Tested against:
  + OWASP Juice Shop  /graphql is not exposed → validated=False
                      (control test for the probe — proves we don't
                      false-positive on apps without GraphQL).
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
    "/query",
    "/api",
)

INTROSPECTION_QUERY = (
    "query { __schema { types { name kind } } }"
)


class GraphqlEndpointProbe(Probe):
    name = "info_graphql_endpoint"
    summary = ("Detects /graphql exposing the introspection query "
               "without authentication.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional GraphQL path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(GRAPHQL_PATHS) + list(args.path or [])

        body = json.dumps({"query": INTROSPECTION_QUERY}).encode()
        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Content-Type": "application/json"}, body=body)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and "__schema" in r.text:
                # Verify the JSON envelope actually contains the
                # introspection result rather than just the substring.
                try:
                    doc = json.loads(r.text)
                    data = doc.get("data") if isinstance(doc, dict) else None
                    schema = (data or {}).get("__schema") \
                             if isinstance(data, dict) else None
                    if isinstance(schema, dict) and schema.get("types"):
                        row["introspection_open"] = True
                        row["type_count"] = len(schema["types"])
                        confirmed = row
                        attempts.append(row)
                        break
                except json.JSONDecodeError:
                    pass
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: GraphQL introspection open at "
                         f"{origin}{confirmed['path']} — full schema "
                         f"retrievable ({confirmed['type_count']} types)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Disable introspection in production. Apollo: "
                    "`new ApolloServer({ introspection: false })`. "
                    "graphql-yoga / express-graphql: gate the query "
                    "validator on a NODE_ENV check. If introspection "
                    "is required for partner integrations, expose it "
                    "behind a separate auth-protected endpoint."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(paths)} GraphQL endpoints "
                     f"on {origin}; none returned an introspection "
                     "response."),
            evidence=evidence,
        )


if __name__ == "__main__":
    GraphqlEndpointProbe().main()
