#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
GraphQL alias amplification — same field aliased N times in one
query, multiplying server-side cost.

GraphQL aliases let a client request the same field multiple
times under different names: ``a1: __typename a2: __typename ...``.
Without an alias-count or complexity limit, an attacker can
submit a single 200-byte query with 50+ aliases on a heavy field
(``user(id: ...)``) and force the server to do 50× the work. This
is the canonical brute-force vector against rate-limited GraphQL
APIs (e.g. password-checking via aliased login mutations).

We send a small (50-alias) query against the same lightweight
introspection field. Two corroborating signals required before
flagging:

  * The response is 200 with all 50 aliased keys present in the
    JSON body — no alias-limit middleware caught it.
  * The response time is sub-linear in alias count vs a
    single-alias baseline, indicating the server amortised the
    cost rather than rate-limiting each alias as a separate call.
    (If the server treats each alias as a separate operation
    with its own rate-limit token, time scales linearly and the
    response time is high.) We require the 50-alias response to
    have completed faster than 50× the single-alias baseline —
    this is structurally always true for amplification, and not
    true for endpoints that genuinely pay per-alias.

The 50-alias cap is intentional. We never exceed 50 — anything
larger risks legitimately overloading a target.

Detection signal:
  Response is 200 + all 50 alias keys present in JSON body AND
  the elapsed time is < 50× the single-alias baseline (i.e. the
  server multiplexed the aliases instead of treating them as
  independent operations).
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

# Cap. NEVER raise this — see safety constraint in module docstring.
ALIAS_COUNT = 50

# Aliased field. ``__typename`` is the safest, lightest field we
# can call — it is required by the GraphQL spec on every type and
# returns a small constant string. We use it as the canary so the
# server can never claim we tried to read sensitive data.
FIELD = "__typename"


def _build_aliased_query(n: int) -> str:
    """Build a single GraphQL query that aliases the same field N
    times: ``{ a0: __typename a1: __typename ... }``."""
    inner = " ".join(f"a{i}: {FIELD}" for i in range(n))
    return "{ " + inner + " }"


def _all_aliases_present(text: str, n: int) -> tuple[bool, int]:
    """Return (all_present, count_present). Counts how many aliased
    keys appear in the response JSON's `data` object."""
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return False, 0
    if not isinstance(doc, dict):
        return False, 0
    data = doc.get("data")
    if not isinstance(data, dict):
        return False, 0
    count = sum(1 for i in range(n) if f"a{i}" in data)
    return count == n, count


class ApiGraphqlAliasAmplificationProbe(Probe):
    name = "api_graphql_alias_amplification"
    summary = ("Detects GraphQL alias amplification — submits a "
               "50-alias query and verifies the server processed all "
               "of them sub-linearly relative to a single-alias "
               "baseline.")
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

        # Single-alias baseline.
        baseline_query = _build_aliased_query(1)
        amp_query = _build_aliased_query(ALIAS_COUNT)

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            r0 = client.request(
                "POST", url,
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"},
                body=json.dumps({"query": baseline_query}).encode())
            if r0.status != 200 or not r0.body:
                attempts.append({"path": p,
                                  "phase": "baseline",
                                  "status": r0.status,
                                  "size": r0.size})
                continue
            ok0, _ = _all_aliases_present(r0.text, 1)
            if not ok0:
                attempts.append({"path": p, "phase": "baseline",
                                  "status": r0.status,
                                  "baseline_ok": False})
                continue
            baseline_ms = max(1, r0.elapsed_ms)

            # Now the amplified query.
            r = client.request(
                "POST", url,
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"},
                body=json.dumps({"query": amp_query}).encode())
            row: dict = {"path": p, "phase": "amplified",
                          "status": r.status, "size": r.size,
                          "alias_count": ALIAS_COUNT,
                          "baseline_ms": baseline_ms,
                          "amp_ms": r.elapsed_ms}
            if r.status == 200 and r.body:
                ok_n, count = _all_aliases_present(r.text, ALIAS_COUNT)
                row["aliases_returned"] = count
                # Sub-linear test: amp_ms should be substantially less
                # than ALIAS_COUNT * baseline_ms. We use 50% as the
                # gate — if amp_ms is more than half of N*baseline,
                # the server is plausibly serializing per-alias and
                # rate-limiting works as intended.
                threshold = (ALIAS_COUNT * baseline_ms) // 2
                row["sub_linear_threshold_ms"] = threshold
                if ok_n and r.elapsed_ms <= threshold:
                    row["amplified"] = True
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "alias_count": ALIAS_COUNT,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: GraphQL alias amplification at "
                    f"{origin}{confirmed['path']}. A 50-alias query "
                    f"returned all {confirmed['aliases_returned']} "
                    f"aliases in {confirmed['amp_ms']} ms vs "
                    f"{confirmed['baseline_ms']} ms for a 1-alias "
                    "baseline — well below the linear-cost threshold. "
                    "No alias-count limit is enforced."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Cap alias count and total query complexity:\n"
                    "  - Apollo Server: install "
                    "`graphql-no-alias` plugin (caps aliases per "
                    "operation, default 8) AND "
                    "`graphql-cost-analysis` for per-field cost.\n"
                    "  - Hasura: set "
                    "`HASURA_GRAPHQL_NODE_LIMIT` and "
                    "`HASURA_GRAPHQL_QUERY_DEPTH_LIMIT`.\n"
                    "Defence in depth: rate-limit on the resolved "
                    "operation cost (sum of field weights) rather "
                    "than per-HTTP-request — otherwise a single "
                    "request with 50 aliases counts as one call."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} GraphQL paths "
                     f"on {origin} with a {ALIAS_COUNT}-alias query; "
                     "none returned the full alias set within the "
                     "sub-linear cost threshold."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiGraphqlAliasAmplificationProbe().main()
