#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: Swagger / OpenAPI documentation reachable
without authentication.

When an application's API documentation is publicly served, anyone can
enumerate every endpoint, every parameter, every response shape — and
crucially every privileged route the developer never intended to
expose. Generic crawlers may flag the *path* but rarely confirm that
the response is a real OpenAPI document; this probe parses the
response and asserts that the structure matches.

Detection signal: a GET against any of the canonical doc paths returns
HTTP 200 with a JSON body whose root has either a `swagger` or
`openapi` key. That's the unambiguous marker — these keys appear at
the top level of every OpenAPI 2.0 / 3.x document and nowhere else.

Tested against:
  + OWASP Juice Shop  /api-docs/swagger.json  →  validated=True
                      /swagger.json
                      /openapi.json (all three return 200 with valid JSON)
  + nginx default site                         →  validated=False
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEFAULT_PATHS = (
    "/api-docs/swagger.json",   # the canonical swagger-ui location
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",             # springdoc / springfox
    "/v3/api-docs",
    "/api/swagger.json",
    "/docs/swagger.json",
)


class SwaggerExposedProbe(Probe):
    name = "info_swagger_exposed"
    summary = ("Detects Swagger/OpenAPI documentation reachable without "
               "authentication.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional doc path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            return Verdict(ok=False, error=f"--url is not a URL: {args.url!r}")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        paths = list(DEFAULT_PATHS) + list(args.path or [])
        tested: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except json.JSONDecodeError:
                    tested.append(row); continue
                # Top-level swagger/openapi key is the deterministic
                # marker — neither key appears in unrelated JSON apis.
                kind = None
                if isinstance(doc, dict):
                    if "swagger" in doc:
                        kind = f"swagger-{doc['swagger']}"
                    elif "openapi" in doc:
                        kind = f"openapi-{doc['openapi']}"
                if kind:
                    title = ((doc.get("info") or {}).get("title")
                             if isinstance(doc, dict) else None)
                    paths_count = (len(doc.get("paths") or {})
                                   if isinstance(doc, dict) else 0)
                    row.update({"is_openapi": True, "spec_version": kind,
                                "doc_title": title,
                                "endpoints_in_spec": paths_count})
                    confirmed.append(row)
            tested.append(row)

        evidence = {"origin": origin, "paths_tested": tested}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: OpenAPI specification reachable "
                         f"without authentication at {origin}{top['path']} "
                         f"({top['spec_version']}, "
                         f"{top['endpoints_in_spec']} endpoints declared"
                         + (f", title: {top['doc_title']!r}"
                            if top.get("doc_title") else "") + ")."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Move the API documentation behind authentication, "
                    "or strip it from production builds entirely. The "
                    "spec enumerates every endpoint, parameter, and "
                    "response shape — handy for legitimate consumers, "
                    "but a turn-by-turn map for an attacker. If keeping "
                    "it public is a deliberate choice (some OSS APIs do "
                    "this), at minimum redact internal/admin routes "
                    "from the rendered spec."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(tested)} canonical doc "
                     f"paths on {origin}; none returned an OpenAPI / "
                     "Swagger document."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SwaggerExposedProbe().main()
