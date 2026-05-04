#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
GraphQL: full introspection enabled.

GraphQL servers ship with introspection on by default in development
and many teams forget to disable it before production. With
introspection on, an unauthenticated attacker pulls the entire
schema -- every Query, every Mutation, every type, every field
name -- in a single request. That's a complete map of the application's
attack surface: which mutations call which back ends, which fields
contain PII, which parts of the API are reachable without auth.

Different from the existing `info_graphql_endpoint` probe (which
only fingerprints whether `/graphql` exists). This probe goes one
step further: POSTs the introspection query and asserts the
response contains a real schema (>=5 named types).

Detection signal:
  POST `{ "query": "{ __schema { queryType { name } mutationType
  { name } types { name kind } } }" }` to candidate paths; response
  is JSON with `data.__schema.types` of length >= 5 AND each entry
  has a `name` field.

Tested against:
  + OWASP Juice Shop  -- no GraphQL endpoint; validated=False.
  + Apollo Server / Hasura / express-graphql with introspection on
                      -> validated=True.

Read-only: a single POST per path with a query that has no side
effects (introspection runs against the schema metadata, not the
data layer).
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
    "/api/query",
)

INTROSPECTION_QUERY = (
    "{ __schema { queryType { name } mutationType { name } "
    "subscriptionType { name } types { name kind description } } }"
)


def _looks_like_schema(text: str) -> tuple[bool, list[str], dict]:
    """Returns (is_schema, sample_type_names, structure_summary).
    Validates only when the response is JSON with `data.__schema.types`
    of length >= 5 and each entry has a `name` string."""
    try:
        doc = json.loads(text or "")
    except (ValueError, json.JSONDecodeError):
        return False, [], {}
    if not isinstance(doc, dict):
        return False, [], {}
    data = doc.get("data") or {}
    if not isinstance(data, dict):
        return False, [], {}
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return False, [], {}
    types = schema.get("types")
    if not isinstance(types, list) or len(types) < 5:
        return False, [], {"types_count": (len(types) if isinstance(types, list)
                                            else None)}
    names: list[str] = []
    for t in types[:200]:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            names.append(t["name"])
    if len(names) < 5:
        return False, names, {"types_count": len(types)}
    summary = {
        "types_count": len(types),
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
    }
    return True, names[:10], summary


class GraphqlIntrospectionSchemaProbe(Probe):
    name = "info_graphql_introspection_schema"
    summary = ("Detects GraphQL endpoints with full schema "
               "introspection enabled to anonymous callers.")
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

        body = json.dumps({"query": INTROSPECTION_QUERY}).encode()

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            }, body=body)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                ok, sample, schema_summary = _looks_like_schema(r.text)
                if ok:
                    row.update({"schema_present": True,
                                "type_sample": sample,
                                "schema_summary": schema_summary})
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "paths_tested": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: {origin}{confirmed['path']} returns a "
                    f"complete GraphQL schema to anonymous callers "
                    f"({confirmed['schema_summary'].get('types_count')}"
                    f" types). Sample type names: "
                    + ", ".join(confirmed["type_sample"][:5]) + ". "
                    "Every Query / Mutation / type / field is "
                    "enumerable in one request -- complete attack-"
                    "surface map for free."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable introspection in production -- the typical "
                    "config is one switch per server.\n"
                    "  - Apollo Server: pass `introspection: false` to "
                    "  the constructor (or rely on NODE_ENV=production).\n"
                    "  - express-graphql: `graphqlHTTP({ schema, "
                    "graphiql: false })` AND wrap the schema with "
                    "`disableIntrospection()` from "
                    "graphql-disable-introspection.\n"
                    "  - Hasura: set "
                    "`HASURA_GRAPHQL_DISABLE_INTROSPECTION_ROLES` to the "
                    "list of roles that must not introspect.\n"
                    "  - graphql-ruby: register "
                    "`GraphQL::Schema::AlwaysVisible` only for trusted "
                    "callers; refuse `__schema` for the rest.\n"
                    "Pair with a /graphql endpoint allowlist on the "
                    "edge proxy so only known Operations are accepted."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} GraphQL paths on "
                     f"{origin}; none returned a usable schema response "
                     "to an introspection query."),
            evidence=evidence,
        )


if __name__ == "__main__":
    GraphqlIntrospectionSchemaProbe().main()
