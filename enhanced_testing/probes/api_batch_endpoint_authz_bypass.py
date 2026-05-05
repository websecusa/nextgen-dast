#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
API batch / bulk endpoints: rate-limit and authz checks applied to
the wrapper request only, not per-sub-request.

GraphQL servers and REST aggregator endpoints (``/api/batch``,
``/api/v1/multi``, ``/$batch`` on OData) accept an array of
sub-requests in a single HTTP call. Many implementations check
auth and rate-limits against the OUTER request: the bearer token
is checked once, then each sub-request runs in the privileged
context. The same blind spot lets attackers make N
authorization-sensitive operations in a single request, evading
any per-call rate limiter at the edge.

We send a small batch (3 sub-requests) hitting an
authentication-required endpoint anonymously, then watch the
responses. The signal is structurally precise:

  * Outer HTTP status is 200.
  * The response body decomposes into N sub-responses. Some of
    them are 200 with data — even though no auth was provided.

If the outer wrapper returns 200 but EACH sub-response is 401 /
403 individually, that's the correct behaviour and we refute.
If the outer is 401 because the wrapper itself is gated, also
refute. We only flag when the wrapper accepts an unauthenticated
batch AND at least one sub-call returns data.

Detection signal:
  Outer 200 + response array contains at least one sub-response
  that returned 200 with data while no auth was provided.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# REST-style batch endpoints. Each entry is (path, request-shape).
REST_BATCH_TARGETS = (
    ("/api/batch",
        {"requests": [
            {"method": "GET", "url": "/api/users/me"},
            {"method": "GET", "url": "/api/users"},
            {"method": "GET", "url": "/api/admin"},
        ]}),
    ("/api/v1/batch",
        {"requests": [
            {"method": "GET", "path": "/api/v1/users/me"},
            {"method": "GET", "path": "/api/v1/users"},
        ]}),
    ("/api/$batch",
        {"requests": [
            {"id": "1", "method": "GET", "url": "/users"},
            {"id": "2", "method": "GET", "url": "/users('me')"},
        ]}),
)

# GraphQL batch protocol — Apollo defaults plus a few common
# reasonable fields. We don't need the schema to fire the test;
# servers that disable batching reject the array shape outright.
GRAPHQL_BATCH_TARGETS = (
    ("/graphql",
        [
            {"query": "{ __typename }"},
            {"query": "{ users { id email } }"},
        ]),
    ("/api/graphql",
        [
            {"query": "{ __typename }"},
            {"query": "{ me { id email } }"},
        ]),
)


def _decode_rest_batch(text: str) -> list[dict] | None:
    """Decode a REST-batch response. Tolerates the common shapes:
    `{"responses":[...]}`, `{"results":[...]}`, raw array."""
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(doc, list):
        return [d for d in doc if isinstance(d, dict)]
    if isinstance(doc, dict):
        for k in ("responses", "results", "data"):
            v = doc.get(k)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
    return None


def _decode_gql_batch(text: str) -> list[dict] | None:
    """Decode a GraphQL-batch response. The wire shape is a bare
    JSON array of `{"data": {...}}` / `{"errors": [...]}` envelopes."""
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(doc, list) and all(isinstance(d, dict) for d in doc):
        return doc
    return None


class ApiBatchEndpointAuthzBypassProbe(Probe):
    name = "api_batch_endpoint_authz_bypass"
    summary = ("Detects batch/bulk endpoints that authenticate at the "
               "wrapper level only — sub-requests run unauthenticated.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--rest-path", action="append", default=[],
            help="Additional REST batch path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: dict | None = None

        # ------ REST batch attempts ------
        for path, payload in REST_BATCH_TARGETS:
            r = client.request("POST", urljoin(origin, path),
                                headers={"Content-Type":
                                          "application/json"},
                                body=json.dumps(payload).encode())
            row: dict = {"flavor": "rest", "path": path,
                         "outer_status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                subs = _decode_rest_batch(r.text)
                if subs:
                    # A "leaked" sub is one where status >= 200 < 300
                    # AND the body has >0 bytes of content (not the
                    # empty-error reply some servers emit).
                    leaked = [s for s in subs
                              if (200 <= int(s.get("status",
                                                   s.get("statusCode", 0)
                                                   ) or 0) < 300)
                              and bool(s.get("body") or s.get("data")
                                        or s.get("response"))]
                    row["sub_count"] = len(subs)
                    row["leaked_count"] = len(leaked)
                    if leaked:
                        # Capture a tiny excerpt for evidence — at
                        # most 200 chars, so we don't persist large
                        # data payloads.
                        row["leaked_excerpt"] = (
                            json.dumps(leaked[0])[:200])
                        confirmed = row
                        attempts.append(row)
                        break
            attempts.append(row)

        # ------ GraphQL batch attempts (only if REST didn't fire) ------
        if not confirmed:
            for path, payload in GRAPHQL_BATCH_TARGETS:
                r = client.request("POST", urljoin(origin, path),
                                    headers={"Content-Type":
                                              "application/json"},
                                    body=json.dumps(payload).encode())
                row = {"flavor": "graphql", "path": path,
                        "outer_status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    subs = _decode_gql_batch(r.text)
                    if subs:
                        # Sub-response is "leaked" when it has
                        # `data` populated and no top-level
                        # auth-error.
                        leaked = [s for s in subs
                                  if isinstance(s.get("data"), dict)
                                  and s["data"]]
                        row["sub_count"] = len(subs)
                        row["leaked_count"] = len(leaked)
                        if leaked and len(subs) >= 2:
                            row["leaked_excerpt"] = (
                                json.dumps(leaked[0])[:200])
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: batch endpoint at {origin}"
                    f"{confirmed['path']} accepts unauthenticated "
                    f"requests with {confirmed.get('leaked_count', 0)} "
                    f"of {confirmed.get('sub_count', 0)} sub-responses "
                    "returning data. The auth gate runs at the "
                    "wrapper layer only — sub-requests bypass it."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Apply auth and rate-limit checks at the SUB-"
                    "request level, not just the wrapper:\n"
                    "  - GraphQL: if you need batching, run each "
                    "operation through the same context-resolver "
                    "and auth middleware as a stand-alone request. "
                    "Better still: disable batching when not strictly "
                    "needed (Apollo Server 3+ ships with batching "
                    "off by default).\n"
                    "  - REST batch endpoints: forward each sub-"
                    "request through the same router pipeline as a "
                    "normal request — never bypass middleware just "
                    "because the call originated from a batch.\n"
                    "Defence in depth: cap the number of sub-requests "
                    "per batch (typical: 10) and emit a per-sub-"
                    "request rate-limit token, not one for the wrapper."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} batch endpoint "
                     f"variants on {origin}; none accepted "
                     "unauthenticated batches that returned data."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiBatchEndpointAuthzBypassProbe().main()
