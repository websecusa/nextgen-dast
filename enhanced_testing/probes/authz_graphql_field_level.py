#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: GraphQL field-level access control missing on
sensitive fields.

GraphQL servers commonly authorize at the resolver/object level
(can this caller see the User type?) without an extra check on
individually sensitive fields (passwordHash, ssn, internalNotes).
The result: a low-privilege caller queries `users { passwordHash }`
and gets every user's hash back.

The probe is two-step on purpose:
  1. Confirm `/graphql` exists and answers a benign introspection-
     adjacent query (`{ __typename }`). If that fails (404/405/non-
     JSON), the target almost certainly is not a GraphQL endpoint
     and we refute cleanly with no follow-up requests.
  2. Only then do we issue the sensitive-field probe, asking for a
     small set of fields whose names (passwordHash, ssn,
     internalNotes) are unambiguously privileged. We require at
     least one such field to be returned with a non-null value
     before we declare a finding — a server that returns the field
     definition but always-null values is not actually leaking.

Detection signal:
  /graphql returns 200 + valid JSON for `{ __typename }` AND a
  follow-up query for an explicitly-sensitive field returns the
  same field with a non-null value in `data`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common GraphQL mount points. Most stacks use /graphql; a few
# (Hasura, Apollo Federation gateways) use /v1/graphql or /api/graphql.
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")

# Fields whose names are unambiguously privileged. If any of these
# come back populated to an unauthenticated caller, the server is
# missing field-level authz. Generic-sounding names ("email", "name")
# are excluded on purpose to avoid false positives.
SENSITIVE_FIELDS = (
    "passwordHash",
    "password_hash",
    "ssn",
    "socialSecurityNumber",
    "internalNotes",
    "internal_notes",
    "creditCardNumber",
    "apiKey",
    "totpSecret",
)

# Containers we'll try to probe. The probe queries the singular form
# (`user`) and the plural list form (`users`) — most schemas expose
# at least one of those at the root. We deliberately don't try
# arbitrary names; a GraphQL schema we know nothing about will not
# resolve to a useful query and we'd rather refute than guess.
USER_CONTAINERS = ("users", "allUsers", "user", "me")


def _post_graphql(client: SafeClient, url: str, query: str) -> dict | None:
    """POST a GraphQL query body, return the parsed JSON or None on any
    structural failure (non-200, non-JSON, network)."""
    body = json.dumps({"query": query}).encode()
    r = client.request("POST", url, headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
    }, body=body)
    if r.status != 200 or not r.body:
        return None
    try:
        return json.loads(r.text)
    except (ValueError, json.JSONDecodeError):
        return None


def _walk_for_field(node, field_name: str) -> list[object]:
    """Recursively walk a JSON tree, collecting non-null values of any
    key matching `field_name`. Returns a list of (sample-bounded) values.
    The walk caps recursion implicitly via JSON nesting depth — a real
    GraphQL response is shallow."""
    found: list[object] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == field_name and v is not None:
                found.append(v)
            else:
                found.extend(_walk_for_field(v, field_name))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_for_field(item, field_name))
    return found


def _mask(value: object) -> str:
    """Truncate any leaked value before adding it to evidence so audit
    logs never store the full secret. Keep first-6 / last-4."""
    s = str(value)
    if len(s) <= 12:
        return s
    return s[:6] + "*" * max(0, len(s) - 10) + s[-4:]


class GraphqlFieldLevelProbe(Probe):
    name = "authz_graphql_field_level"
    summary = ("Detects GraphQL servers missing field-level authz: "
               "sensitive fields like passwordHash and ssn returned to "
               "anonymous queries.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--graphql-path", action="append", default=[],
            help="Additional GraphQL endpoint path to try (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = list(GRAPHQL_PATHS) + list(args.graphql_path or [])

        # Step 1 — locate a working GraphQL endpoint by sending the
        # cheapest possible query. Anything that returns a `__typename`
        # value confirms we're talking to GraphQL.
        endpoint: str | None = None
        endpoint_typename: str | None = None
        attempts: list[dict] = []
        for path in candidates:
            url = urljoin(origin, path)
            doc = _post_graphql(client, url, "{ __typename }")
            row: dict = {"path": path, "ok": bool(doc)}
            if doc and isinstance(doc, dict):
                data = doc.get("data") or {}
                if isinstance(data, dict) and isinstance(
                        data.get("__typename"), str):
                    endpoint = url
                    endpoint_typename = data["__typename"]
                    row["typename"] = endpoint_typename
                    attempts.append(row)
                    break
            attempts.append(row)

        if not endpoint:
            return Verdict(
                validated=False, confidence=0.9,
                summary=(f"Refuted: no GraphQL endpoint responding to a "
                         f"benign `{{ __typename }}` query under "
                         f"{origin} (tried {len(candidates)} paths)."),
                evidence={"origin": origin, "attempts": attempts},
            )

        # Step 2 — only now do we ask for sensitive fields. We bundle
        # them per-container in a single request so we don't burn budget.
        fields_block = " ".join(SENSITIVE_FIELDS)
        leaks: list[dict] = []
        sensitive_attempts: list[dict] = []
        for container in USER_CONTAINERS:
            query = "{ %s { %s } }" % (container, fields_block)
            doc = _post_graphql(client, endpoint, query)
            row: dict = {"container": container,
                         "responded": bool(doc)}
            if not doc:
                sensitive_attempts.append(row)
                continue
            errors = doc.get("errors") if isinstance(doc, dict) else None
            data = doc.get("data") if isinstance(doc, dict) else None
            row["had_errors"] = bool(errors)
            # If the server rejected the query as malformed (unknown
            # field, no such root) the data tree is null and we move on.
            if not data:
                sensitive_attempts.append(row)
                continue
            # Walk the tree for each sensitive field. We require an
            # actual non-null value — a schema that *defines* the field
            # but always returns null is not leaking.
            for field in SENSITIVE_FIELDS:
                values = _walk_for_field(data, field)
                if values:
                    sample = values[0]
                    leaks.append({
                        "container": container,
                        "field": field,
                        "value_count": len(values),
                        "sample_excerpt": _mask(sample),
                    })
            row["leaks_in_container"] = sum(
                1 for l in leaks if l["container"] == container)
            sensitive_attempts.append(row)
            if leaks:
                break

        evidence = {"origin": origin, "endpoint": endpoint,
                    "endpoint_typename": endpoint_typename,
                    "discovery_attempts": attempts,
                    "sensitive_attempts": sensitive_attempts}

        # High-fidelity gate: confirmed GraphQL endpoint AND at least
        # one sensitive field returned non-null. Both signals must be
        # true.
        if leaks:
            top = leaks[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: GraphQL field-level authz missing "
                         f"on {endpoint} — `{top['container']} "
                         f"{{ {top['field']} }}` returned "
                         f"{top['value_count']} non-null value(s) to a "
                         "non-privileged caller."),
                evidence={**evidence, "leaks": leaks},
                severity_uplift="high",
                remediation=(
                    "Add field-level authorization to the GraphQL "
                    "schema. Concrete options:\n"
                    "  - Annotate sensitive fields with a directive "
                    "(`@auth(requires: ADMIN)`) that the resolver "
                    "framework enforces before the field is read.\n"
                    "  - In Apollo / GraphQL Yoga, attach a "
                    "fieldMiddleware that inspects the parent type "
                    "and the caller's claims, returning null + a "
                    "GraphQL error for unauthorized reads.\n"
                    "  - Never expose password/secret fields in the "
                    "schema at all — strip them at the data-access "
                    "layer. A field that isn't in the schema cannot "
                    "be queried."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: GraphQL endpoint at {endpoint} did not "
                     "return any of the explicitly-sensitive fields "
                     f"({len(SENSITIVE_FIELDS)} probed) to an "
                     "anonymous caller."),
            evidence=evidence,
        )


if __name__ == "__main__":
    GraphqlFieldLevelProbe().main()
