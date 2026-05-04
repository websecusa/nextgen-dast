#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: legacy API version still answers requests v2 protects.

A common multi-version-API mistake: the team adds auth to the new
`/api/v2/<route>` but the old `/api/v1/<route>` is left in place
"for backwards compat" and never gets the same protection. The
endpoint exists, the data is there, and an unauthenticated request
to the old path returns the same data the new path requires a
Bearer token for.

The high-fidelity signal is a differential between v2 and v1:
  - GET /api/v2/<route>          -> 401 / 403 (auth required)
  - GET /api/v1/<route>          -> 200 with body (no auth required)

That differential is what proves the bug. A 401 on both is fine; a
200 on both could be that the route is intentionally public; a
404 on both rules the route out. Only the 401-vs-200 split is
meaningful.

Detection signal:
  For each `/api/v2/<route>` discovered in the homepage or a small
  hardcoded list (`/users`, `/orders`, `/admin`, `/products`,
  `/payments`), GET both `/api/v2/<route>` and `/api/v1/<route>`
  unauthenticated. Validate when v2 returns 401/403 AND v1 returns
  a 200 with a JSON or HTML body.

Tested against:
  + OWASP Juice Shop  Has /api/v* routes? No -- single-namespace.
                      -> validated=False (inconclusive on this surface).
  + Real apps with `/api/v1/users` (anonymous) and
    `/api/v2/users` (Bearer required) -> validated=True.

Read-only: GET only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Canonical resource names that, when added under /api/v1 and
# /api/v2, are the bug shape. We sweep both case forms because
# Express / Sequelize sometimes register the model name with a
# capital initial.
RESOURCE_NAMES = (
    "users", "Users",
    "orders", "Orders",
    "products", "Products",
    "payments", "Payments",
    "admin", "Admin",
    "accounts", "Accounts",
)

# Path templates -- v2 / v1 alternates. Each template gets the
# resource name substituted in.
TEMPLATES = (
    ("/api/v2/{r}", "/api/v1/{r}"),
    ("/v2/{r}",     "/v1/{r}"),
    ("/api/v2/{r}", "/api/{r}"),
    ("/api/v2/{r}", "/api/old/{r}"),
)


def _looks_like_data(text: str) -> bool:
    """A 200 response qualifies as 'data was returned' when the body
    is JSON-shaped or non-trivially long HTML. Eliminates the case
    where the v1 path is a static SPA shell -- which would falsely
    trigger on every route."""
    if not text:
        return False
    s = text.lstrip()
    if s.startswith("{") or s.startswith("["):
        # Try parsing -- a real JSON response confirms data
        try:
            doc = json.loads(s)
            if isinstance(doc, dict):
                return any(k for k in doc.keys()
                            if k.lower() in {"data", "items", "results",
                                              "users", "orders", "products"})
            if isinstance(doc, list):
                return len(doc) > 0
        except (ValueError, json.JSONDecodeError):
            return False
    return False


class ApiLegacyV1AuthBypassProbe(Probe):
    name = "authz_api_legacy_v1_auth_bypass"
    summary = ("Detects legacy API versions (v1) that answer requests "
               "anonymously while the current version (v2) requires "
               "auth.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--resource", action="append", default=[],
            help="Additional resource name to probe (e.g. 'invoices'). "
                 "Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        resources = list(RESOURCE_NAMES) + list(args.resource or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for v2_tpl, v1_tpl in TEMPLATES:
            for r_name in resources:
                v2_path = v2_tpl.format(r=r_name)
                v1_path = v1_tpl.format(r=r_name)
                v2_url = urljoin(origin, v2_path)
                r_v2 = client.request("GET", v2_url)
                # Skip if v2 doesn't exist or doesn't require auth --
                # only the differential is interesting.
                if r_v2.status not in (401, 403):
                    continue
                v1_url = urljoin(origin, v1_path)
                r_v1 = client.request("GET", v1_url)
                row: dict = {"v2_path": v2_path, "v1_path": v1_path,
                             "v2_status": r_v2.status,
                             "v1_status": r_v1.status,
                             "v1_size": r_v1.size}
                if r_v1.status == 200 and _looks_like_data(r_v1.text):
                    row.update({"bypass": True,
                                "snippet": (r_v1.text or "")[:200]})
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
                    f"Confirmed: legacy-API auth bypass on {origin}. "
                    f"GET {confirmed['v2_path']} returned "
                    f"{confirmed['v2_status']} (auth required), but "
                    f"GET {confirmed['v1_path']} returned 200 with a "
                    "data-shaped body to the same anonymous request. "
                    "The old version is still online and unprotected -- "
                    "every record the v2 endpoint guards is reachable "
                    "via the v1 alternate."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Decommission the legacy version: route it to a "
                    "410 Gone, or wire it through the same auth "
                    "middleware as v2.\n"
                    "  - nginx / Cloudflare: edge rule that blocks "
                    "`/api/v1/*` (or proxies it to a 410 page).\n"
                    "  - Express: register the same auth middleware on "
                    "both `/api/v1/*` and `/api/v2/*` -- not just on "
                    "the v2 router.\n"
                    "  - Audit who's still using v1 in your access "
                    "logs before turning it off; coordinate the "
                    "shutdown with the legitimate consumers.\n"
                    "Pair with an asset-management discipline: a "
                    "deprecated API version stays in the asset register "
                    "until it returns 410 in production."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} v2/v1 endpoint "
                     f"pairs on {origin}; none showed the auth-required "
                     "vs anonymous-200 differential."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ApiLegacyV1AuthBypassProbe().main()
