#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: tenant isolation bypass via header / query-param
override.

Multi-tenant SaaS apps commonly route requests with a tenant
identifier carried in `X-Tenant-ID`, `X-Org-ID`, `?tenant_id=`, or
similar. If the tenant id is taken from the request header rather
than the authenticated session/JWT, an attacker can simply set the
header to a different tenant's id and read or modify their data.

The probe:
  1. Establishes a baseline by GETting a tenant-aware endpoint
     (`/api/orders`, `/api/users/me`, `/api/billing`, etc.) without
     any tenant override and records the response shape.
  2. Re-issues the same request with a forged tenant id (numeric
     and short-string variants — short to avoid creating noise in
     the target's logs) supplied via the candidate headers and
     query params.
  3. Declares a finding only when (a) the override response is 200,
     (b) the body is non-trivially different from the baseline, AND
     (c) the override body still looks like real tenant data
     (JSON dict / array, non-error). Three signals must align.

Detection signal:
  baseline 200 + tenant-id-overridden 200 + bodies differ but both
  look like valid tenant data shapes.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that are commonly tenant-scoped. We test each in turn
# and stop on the first one that produces a clean baseline. Listing
# multiple lets us cover the variation in REST conventions without
# requiring the operator to know the exact path.
TENANT_AWARE_PATHS = (
    "/api/orders",
    "/api/users",
    "/api/billing",
    "/api/invoices",
    "/api/projects",
    "/api/tenants/current",
    "/api/organization",
)

# Header names servers commonly read for the tenant id. Order is by
# decreasing prevalence — first hit wins.
TENANT_HEADERS = (
    "X-Tenant-ID",
    "X-Tenant-Id",
    "X-Org-ID",
    "X-Organization-Id",
    "X-Account-Id",
    "X-Workspace-Id",
)

# Query-param variants to layer on as a separate signal.
TENANT_QUERY_PARAMS = ("tenant_id", "org_id", "account_id", "workspace_id")

# Forged tenant ids. Numeric-2 is the most likely "another tenant"
# id on a system where tenant 1 is the caller's. We avoid large
# integers (less likely to exist) and avoid SQL-meta strings.
FORGED_TENANT_IDS = ("2", "1")


def _body_signature(text: str) -> str:
    """A coarse signature of a JSON-ish body for shape comparison.
    We don't compare full bodies — that's noisy because of
    timestamps. Instead we hash the SORTED set of top-level keys
    plus the array length / dict size class."""
    try:
        doc = json.loads(text or "")
    except (ValueError, json.JSONDecodeError):
        return "non-json:" + hashlib.sha256(
            (text or "")[:512].encode()).hexdigest()[:12]
    if isinstance(doc, dict):
        keys = sorted(doc.keys())
        return f"dict:{len(keys)}:" + ",".join(keys[:12])
    if isinstance(doc, list):
        # Hash the sorted top-level keys of the first element to
        # represent the row shape.
        if doc and isinstance(doc[0], dict):
            keys = sorted(doc[0].keys())
            return f"list:{len(doc)}:" + ",".join(keys[:12])
        return f"list:{len(doc)}:scalar"
    return "scalar"


def _looks_like_tenant_data(text: str) -> bool:
    """Sanity check: an overridden response that's an HTML error page
    or an empty array is NOT a tenant-leak signal. We require the
    body to parse as JSON dict or non-empty list."""
    try:
        doc = json.loads(text or "")
    except (ValueError, json.JSONDecodeError):
        return False
    if isinstance(doc, dict):
        # An error envelope ({"error": ...}) is not tenant data.
        if any(k in doc for k in ("error", "errors", "message",
                                   "Error", "errorCode")) \
                and len(doc) <= 3:
            return False
        return len(doc) > 0
    if isinstance(doc, list):
        return len(doc) > 0
    return False


class TenantIdHeaderSwapProbe(Probe):
    name = "authz_tenant_id_header_swap"
    summary = ("Detects tenant isolation bypass: forged X-Tenant-ID / "
               "?tenant_id= overrides return another tenant's data.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--tenant-path", action="append", default=[],
            help="Additional tenant-aware path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: find a tenant-aware endpoint that gives a stable
        # 200 baseline. We don't authenticate (per probe spec) — many
        # multi-tenant SaaS apps set the tenant from a header even on
        # public read endpoints, which is exactly the bug we hunt.
        candidate_paths = (list(TENANT_AWARE_PATHS)
                           + list(args.tenant_path or []))
        baseline_path: str | None = None
        baseline_text = ""
        baseline_sig = ""
        baseline_attempts: list[dict] = []
        for path in candidate_paths:
            url = urljoin(origin, path)
            r = client.request("GET", url)
            row = {"path": path, "status": r.status, "size": r.size}
            if r.status == 200 and r.body and _looks_like_tenant_data(
                    r.text):
                baseline_path = path
                baseline_text = r.text or ""
                baseline_sig = _body_signature(baseline_text)
                row["baseline_signature"] = baseline_sig
                baseline_attempts.append(row)
                break
            baseline_attempts.append(row)

        if not baseline_path:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no tenant-aware endpoint on {origin} "
                         "returned a usable baseline (no anonymous "
                         "JSON dict / list). Cannot evaluate header "
                         "override safely without one."),
                evidence={"origin": origin,
                           "baseline_attempts": baseline_attempts},
            )

        # Phase 2: replay with each candidate override. We only probe
        # one forged id per channel to keep the request budget bounded.
        confirmed: list[dict] = []
        override_attempts: list[dict] = []
        full_url = urljoin(origin, baseline_path)
        for header in TENANT_HEADERS:
            r = client.request("GET", full_url,
                               headers={header: FORGED_TENANT_IDS[0]})
            sig = _body_signature(r.text or "")
            row = {"channel": "header", "name": header,
                   "value": FORGED_TENANT_IDS[0],
                   "status": r.status, "size": r.size,
                   "signature": sig,
                   "differs_from_baseline": (sig != baseline_sig)}
            override_attempts.append(row)
            if r.status == 200 and sig != baseline_sig \
                    and _looks_like_tenant_data(r.text or ""):
                confirmed.append({**row,
                                   "snippet": (r.text or "")[:300]})
                break

        if not confirmed:
            for qp in TENANT_QUERY_PARAMS:
                qurl = (full_url + ("&" if "?" in full_url else "?")
                        + urlencode({qp: FORGED_TENANT_IDS[0]}))
                r = client.request("GET", qurl)
                sig = _body_signature(r.text or "")
                row = {"channel": "query", "name": qp,
                       "value": FORGED_TENANT_IDS[0],
                       "status": r.status, "size": r.size,
                       "signature": sig,
                       "differs_from_baseline": (sig != baseline_sig)}
                override_attempts.append(row)
                if r.status == 200 and sig != baseline_sig \
                        and _looks_like_tenant_data(r.text or ""):
                    confirmed.append({**row,
                                       "snippet": (r.text or "")[:300]})
                    break

        evidence = {"origin": origin, "baseline_path": baseline_path,
                    "baseline_signature": baseline_sig,
                    "baseline_attempts": baseline_attempts,
                    "override_attempts": override_attempts}

        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: tenant isolation bypass on "
                         f"{origin}{baseline_path} — overriding "
                         f"{top['channel']} `{top['name']}` to "
                         f"{top['value']!r} returned a body with a "
                         "different shape than the baseline (signature "
                         f"{top['signature']} vs {baseline_sig}). Server "
                         "trusts the caller-supplied tenant id."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Derive the tenant id from the authenticated "
                    "session / JWT, never from a header or query "
                    "parameter the client controls. If the gateway "
                    "must accept an X-Tenant-ID for routing reasons, "
                    "the application layer must verify it matches the "
                    "tenant claim in the access token and reject any "
                    "mismatch with 403. Add a per-request audit log "
                    "entry of (jwt.tenant_id, request.tenant_id) so "
                    "any future drift is visible."),
            )
        return Verdict(
            validated=False, confidence=0.8,
            summary=(f"Refuted: tested {len(override_attempts)} tenant "
                     f"override channels on {baseline_path}; none "
                     "produced a body shape that differed from "
                     "baseline."),
            evidence=evidence,
        )


if __name__ == "__main__":
    TenantIdHeaderSwapProbe().main()
