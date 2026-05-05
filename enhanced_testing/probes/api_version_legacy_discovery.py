#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
API version discovery: legacy version reachable without auth that
the current version requires.

Many APIs support multiple versions concurrently for backwards
compatibility. The newest version typically has the strictest auth
posture; older / beta versions are commonly forgotten — left
exposed without auth, with weaker authz, or with the original
mass-assignment defects fixed only in the new version. We sweep
the same logical resource across version segments and flag when
an older version returns 200 unauthenticated where the current
version requires auth (401 / 403).

Generalises the existing
``authz_api_legacy_v1_auth_bypass`` (single endpoint) — this
probe systematically discovers the version axis across a small
set of common endpoints.

False-positive control:
  We only flag when BOTH conditions are true:
    1. The "current" version (v2 / v3 / no version segment) for
       the same logical endpoint returns 401 / 403 (i.e. it
       requires auth).
    2. An older version (v0 / v1 / beta) for the SAME endpoint
       returns 200 with non-trivial JSON-shaped content.
  Both signals together prove the auth posture differs by version.

Detection signal:
  ``GET /api/vN/<resource>`` returns 200 + JSON body where
  ``GET /api/<resource>`` (or vN+1 of same resource) returns
  401/403.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Logical resources to sweep. Each entry is the path segment AFTER
# the version slot. We test these against a deliberate set of
# version-prefix templates.
RESOURCES = (
    "users",
    "orders",
    "products",
    "accounts",
    "admin/users",
)

# Version slot templates. The {res} placeholder is replaced with
# each resource at runtime.
LEGACY_TEMPLATES = (
    "/api/v0/{res}",
    "/api/v1/{res}",
    "/api/beta/{res}",
    "/api/legacy/{res}",
    "/v1/{res}",
    "/v0/{res}",
)
CURRENT_TEMPLATES = (
    "/api/v2/{res}",
    "/api/v3/{res}",
    "/api/{res}",
    "/{res}",
)


def _looks_like_data(text: str) -> bool:
    """Return True when the body looks like JSON-shaped data
    (list of objects or object with a `data`/`items`/`results`
    array). We require structure — empty objects or HTML pages
    don't count as legacy-leak content."""
    if not text:
        return False
    text = text.strip()
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return False
    if isinstance(doc, list) and len(doc) >= 1 and isinstance(
            doc[0], dict):
        return True
    if isinstance(doc, dict):
        for k in ("data", "items", "results", "users", "records",
                   "rows"):
            v = doc.get(k)
            if isinstance(v, list) and len(v) >= 1:
                return True
    return False


class ApiVersionLegacyDiscoveryProbe(Probe):
    name = "api_version_legacy_discovery"
    summary = ("Detects legacy API versions that return data without "
               "auth where the current version requires auth.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--resource", action="append", default=[],
            help="Additional resource path segment to sweep "
                 "(e.g. 'tenants').")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        resources = list(RESOURCES) + list(args.resource or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for res in resources:
            # First, find the auth posture of the "current"
            # version. Pick the strictest answer across CURRENT
            # candidates — if any current variant requires auth,
            # we treat the resource as gated.
            current_status: int | None = None
            current_path: str | None = None
            for t in CURRENT_TEMPLATES:
                p = t.format(res=res)
                r = client.request("GET", urljoin(origin, p))
                attempts.append({"path": p, "role": "current",
                                  "status": r.status, "size": r.size})
                if r.status in (401, 403):
                    current_status = r.status
                    current_path = p
                    break
            # No gated current version — comparison is meaningless.
            if current_status is None:
                continue

            # Now sweep the legacy candidates for the same resource.
            for t in LEGACY_TEMPLATES:
                p = t.format(res=res)
                r = client.request("GET", urljoin(origin, p))
                row: dict = {"path": p, "role": "legacy",
                              "status": r.status, "size": r.size}
                if r.status == 200 and _looks_like_data(r.text or ""):
                    row.update({"data_shape": True,
                                 "compared_with": current_path,
                                 "current_status": current_status})
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: legacy API version exposed at "
                    f"{origin}{confirmed['path']}. The endpoint "
                    f"returns 200 + JSON data unauthenticated, while "
                    f"the current version "
                    f"({confirmed['compared_with']}) returns "
                    f"{confirmed['current_status']} (requires auth)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Either remove the legacy version or apply the "
                    "current auth gate to it.\n"
                    "  - If the version was deprecated, return "
                    "410 Gone for every request and unmount the "
                    "router.\n"
                    "  - If the version is still in use by clients, "
                    "wrap the entire `/api/v0`, `/api/v1`, "
                    "`/api/beta` mount points with the same auth "
                    "middleware that protects the current version.\n"
                    "Maintain a release-gate test: for each new "
                    "endpoint added to `/api/vN`, fail CI unless the "
                    "matching `/api/vK` (K<N) endpoint either has a "
                    "compatible auth posture or returns 410."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} version "
                     f"variants on {origin}; no legacy version "
                     "returned data where the current version "
                     "required auth."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiVersionLegacyDiscoveryProbe().main()
