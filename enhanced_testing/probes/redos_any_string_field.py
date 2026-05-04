#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
ReDoS (Regular-Expression Denial of Service) on any string field
that the server validates with a vulnerable regex.

Generalises `redos_b2b_orderlines` (Juice Shop's `/b2b/v2/orders`
orderLinesData). Catastrophic-backtracking patterns
(`(a+)+`, `(a*)*`, `(.*)+`) blow up on inputs of the form `a` * N
+ `!`. The bug is in the regex; the field name is irrelevant.

High-fidelity signal:
  Compare response time on a benign payload vs a catastrophic
  payload of the same shape and field. >= 2 s delta + the
  catastrophic response either timed out (status 0 / 5xx) or
  took dramatically longer is the signal. Below the threshold
  the bug isn't real (or isn't reachable from this field).
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, method, ctype, fields)
TARGETS = (
    ("/api/users",           "POST",   "json",
        ("name", "email", "username")),
    ("/api/feedback",        "POST",   "json",
        ("comment", "message")),
    ("/api/Feedbacks",       "POST",   "json",
        ("comment",)),
    ("/api/contact",         "POST",   "json",
        ("name", "message")),
    ("/api/comments",        "POST",   "json",
        ("comment", "message", "body")),
    ("/api/posts",            "POST",   "json",
        ("title", "body", "content")),
    ("/b2b/v2/orders",       "POST",   "json",
        ("orderLinesData", "orderLines")),
    ("/api/profile",         "PATCH",  "json",
        ("name", "displayName", "bio", "signature")),
)

BENIGN = "a" * 5 + "!"
CATASTROPHIC = "a" * 32 + "!"


class RedosAnyStringFieldProbe(Probe):
    name = "redos_any_string_field"
    summary = ("Detects ReDoS by comparing response time on a "
               "catastrophic-backtracking payload vs a benign one "
               "in the same field.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--threshold-ms", type=int, default=2000,
            help="Minimum delta (ms) between benign and catastrophic "
                 "responses for a confirmed ReDoS (default 2000).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        threshold = max(500, int(args.threshold_ms or 2000))

        # Need a session for some endpoints, but a cookie/token isn't
        # strictly required for the ReDoS itself -- the server hits
        # the regex before the auth check on most frameworks. We
        # don't bother registering.
        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, method, ctype, fields in TARGETS:
            for field in fields:
                # Send benign first so we have a baseline; bound the
                # comparison loop so the probe doesn't run forever
                # if the server is just slow.
                token = secrets.token_hex(4)
                benign_body = json.dumps({field: BENIGN,
                                            "_dast": token}).encode()
                cat_body = json.dumps({field: CATASTROPHIC,
                                         "_dast": token}).encode()
                url = urljoin(origin, path)
                rb = client.request(method, url, headers={
                    "Content-Type": "application/json"},
                    body=benign_body)
                # Skip endpoints where benign already errors -- the
                # comparison would be meaningless.
                if rb.status not in (200, 201, 400, 401, 403, 404, 422):
                    continue
                rc = client.request(method, url, headers={
                    "Content-Type": "application/json"},
                    body=cat_body)
                row = {"path": path, "method": method,
                        "field": field,
                        "benign_status": rb.status,
                        "benign_ms": rb.elapsed_ms,
                        "cat_status": rc.status,
                        "cat_ms": rc.elapsed_ms,
                        "delta_ms": rc.elapsed_ms - rb.elapsed_ms}
                # Confirm when the catastrophic response is
                # dramatically slower OR timed out.
                if (rc.elapsed_ms - rb.elapsed_ms) >= threshold:
                    row["redos"] = True
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "threshold_ms": threshold,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: ReDoS at {origin}{confirmed['path']} "
                    f"({confirmed['method']}, field "
                    f"`{confirmed['field']}`). Catastrophic payload "
                    f"took {confirmed['cat_ms']} ms vs benign "
                    f"{confirmed['benign_ms']} ms (delta "
                    f"{confirmed['delta_ms']} ms >= {threshold}). "
                    "The validation regex is vulnerable to "
                    "catastrophic backtracking."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Replace the vulnerable regex with a non-"
                    "backtracking equivalent OR cap the input length "
                    "before regex evaluation.\n"
                    "  - Most frameworks ship a regex-safety lint "
                    "(safe-regex, eslint-plugin-redos, "
                    "regexp-tree-cli) -- run it on the codebase to "
                    "find the offending pattern.\n"
                    "  - Common offenders: `(a+)+`, `(a*)*`, "
                    "`(.*)*`, `(.+)+`, ambiguous alternation like "
                    "`(a|aa)*`. Rewrite to use possessive quantifiers "
                    "or atomic groups (Java `(?>a+)+`, .NET "
                    "`(?>...)`).\n"
                    "  - Defence in depth: cap the field length at "
                    "the validation layer (e.g., 256 chars) before "
                    "the regex even runs.\n"
                    "  - Move regex evaluation to RE2 (Go default, "
                    "Python `re2` package) -- RE2 is provably linear "
                    "and immune to backtracking blow-up."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(attempts)} field/endpoint "
                     f"combinations on {origin}; no catastrophic "
                     f"response delta >= {threshold} ms observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    RedosAnyStringFieldProbe().main()
