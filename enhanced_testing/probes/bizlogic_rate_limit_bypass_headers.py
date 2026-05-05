#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: rate limiter keyed on a forwarded-IP header that the
caller controls.

Many WAFs and middleware stacks key their rate limits on
`X-Forwarded-For` (or `X-Real-IP` / `X-Originating-IP` /
`X-Client-IP`) under the assumption that an upstream proxy populated
those headers truthfully. When the application server is reachable
directly (or the upstream proxy doesn't strip / overwrite the
incoming header), the attacker simply rotates the header value per
request and continues unfettered.

This probe targets a known rate-limited endpoint — login or password
reset are the cleanest candidates because their limiter is usually
visible (429 Retry-After). The detection sequence is:

  1. Hit the endpoint N times with no rotation, expecting to TRIP
     the limiter (HTTP 429 / Retry-After / observable degradation).
  2. Once tripped, switch to per-request rotation of forwarded-IP
     headers and continue. If the limiter resets and we get a long
     run of 200s, the bypass is confirmed.

Detection signal:
  Validated=True only when ALL of:
    1. The single-source phase produced at least one 429 (or other
       lockout signal) — i.e. the endpoint IS rate-limited, AND
    2. The rotated-source phase produced more than 5 successful (or
       at least non-429) responses without a single 429.

Two corroborating signals so we don't false-positive on an endpoint
that simply doesn't rate-limit at all (that's a separate finding —
auth_no_brute_force_lockout already covers it).
"""
from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that MOST commonly carry a rate limiter the operator
# expects to hold; we try them in order until one returns a 429
# during the no-rotation burst.
LIMITED_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/login",
    "/api/auth/login",
    "/rest/user/reset-password",
    "/api/users/forgot-password",
    "/auth/forgot-password",
)

# Rotation set — every header a careless reverse proxy / WAF chain
# might key its rate limit on.
ROTATING_HEADERS = ("X-Forwarded-For", "X-Real-IP",
                    "X-Originating-IP", "X-Client-IP", "Forwarded")

DEFAULT_PHASE_REQS = 12   # per phase; budget-capped at runtime
# Hard ceiling for phase-1 path discovery so we don't blow the budget
# on apps that have no rate-limiter on any path. Phase 2 needs ≥ 12
# slots to be statistically meaningful, so reserve them.
PHASE1_TOTAL_CAP = 30


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _spoofed_ip() -> str:
    """Return a syntactically-valid private IPv4 string. We stay in
    RFC1918 so a misconfigured downstream that DOES log the value
    can't mistake the test for spoofing of a public address."""
    return f"10.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"


def _login_body(target_email: str, attempt_id: int) -> bytes:
    return json.dumps({
        "email": target_email,
        "password": f"dast-rl-bypass-{attempt_id}",
    }).encode()


class BizLogicRateLimitBypassHeadersProbe(Probe):
    name = "bizlogic_rate_limit_bypass_headers"
    summary = ("Detects rate limiters keyed on a client-controlled "
               "forwarded-IP header — rotating the header per request "
               "circumvents the lockout.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--target-email", default="admin@juice-sh.op",
            help=("Email used in the login attempts (must be a "
                  "documented seed account)."))
        parser.add_argument(
            "--phase-requests", type=int, default=DEFAULT_PHASE_REQS,
            help=("Requests per phase. Total volume = 2 * this value. "
                  "Default 12 (24 total)."))

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        per_phase = max(6, min(int(args.phase_requests), 20))
        target_email = args.target_email

        # ---- Phase 1: discover a path that DOES rate-limit ----
        # We can't bypass a limiter that doesn't exist, so we walk
        # candidates until one trips; if none trip at all the probe
        # is conclusively refuted (the OTHER probe — no-brute-force-
        # lockout — covers that case).
        target_path = ""
        phase1_results: list[dict] = []
        phase1_429_seen = False
        # Spread PHASE1_TOTAL_CAP across the candidate paths so we
        # short-circuit cleanly if no limiter fires anywhere — without
        # this, each path consumed `per_phase` and a target with zero
        # rate-limiting would burn all 60 budget slots before phase 2.
        per_path_cap = max(3, PHASE1_TOTAL_CAP // len(LIMITED_PATHS))
        phase1_used = 0
        for path in LIMITED_PATHS:
            if phase1_used >= PHASE1_TOTAL_CAP:
                break
            url = urljoin(origin, path)
            statuses: list[int] = []
            saw_429 = False
            for i in range(min(per_path_cap, per_phase)):
                r = client.request("POST", url, headers={
                    "Content-Type": "application/json",
                }, body=_login_body(target_email, i))
                phase1_used += 1
                statuses.append(r.status)
                if r.status == 429 or _hdr(r.headers, "Retry-After"):
                    saw_429 = True
                    break
            phase1_results.append({"path": path, "statuses": statuses,
                                   "tripped": saw_429})
            if saw_429:
                target_path = path
                phase1_429_seen = True
                # Brief pause so the limiter window settles before
                # we measure rotation behavior. Short — we are NOT
                # waiting out the limit, we are just settling the
                # bucket so phase-2 can be compared cleanly.
                time.sleep(1)
                break

        if not phase1_429_seen:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no rate-limiter detected on any "
                         f"candidate endpoint of {origin}; bypass "
                         "test is not meaningful (see "
                         "auth_no_brute_force_lockout for the "
                         "no-limit-at-all finding)."),
                evidence={"origin": origin, "phase1": phase1_results},
            )

        # ---- Phase 2: same endpoint, rotated forwarded-IP headers ----
        # Each request gets a fresh fake IP across all five header
        # names. We expect a correctly-configured upstream to
        # IGNORE these (and continue to 429 us). A vulnerable
        # upstream will reset its bucket per fake IP and respond 200.
        url = urljoin(origin, target_path)
        rotated_results: list[dict] = []
        rotated_non_429 = 0
        rotated_429_seen = False
        for i in range(per_phase):
            spoof = _spoofed_ip()
            headers = {"Content-Type": "application/json"}
            for h in ROTATING_HEADERS:
                # `Forwarded:` uses RFC7239 syntax; the rest are simple.
                headers[h] = (f'for="{spoof}"' if h == "Forwarded" else spoof)
            r = client.request("POST", url, headers=headers,
                               body=_login_body(target_email, 1000 + i))
            entry = {"i": i, "status": r.status, "spoof_ip": spoof,
                     "retry_after": _hdr(r.headers, "Retry-After")}
            rotated_results.append(entry)
            if r.status == 429 or entry["retry_after"]:
                rotated_429_seen = True
                break
            rotated_non_429 += 1

        evidence = {"origin": origin, "endpoint": target_path,
                    "phase1_results": phase1_results,
                    "rotated_results": rotated_results,
                    "rotated_non_429": rotated_non_429,
                    "rotated_429_seen": rotated_429_seen,
                    "headers_rotated": list(ROTATING_HEADERS)}

        # Confirmation: phase 1 tripped 429 AND phase 2 with rotation
        # gave us > 5 non-429 responses AND no 429 at all in phase 2.
        if phase1_429_seen and rotated_non_429 > 5 and not rotated_429_seen:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: rate limiter on "
                         f"{origin}{target_path} is keyed on a "
                         "client-controlled forwarded-IP header. After "
                         "single-source 429, rotation across "
                         f"{', '.join(ROTATING_HEADERS)} produced "
                         f"{rotated_non_429} consecutive successful "
                         "requests without re-triggering the limit."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Key rate-limit buckets on the trusted edge IP, "
                    "NOT on a request header that can be set by the "
                    "client:\n"
                    "  - Strip / overwrite incoming "
                    "X-Forwarded-For / X-Real-IP / X-Originating-IP "
                    "/ X-Client-IP / Forwarded at the edge proxy.\n"
                    "  - Configure the application's `trust proxy` "
                    "list explicitly (e.g. Express's "
                    "`app.set('trust proxy', '127.0.0.1')`).\n"
                    "  - Pair IP-based limiting with per-account "
                    "limiting so a header rotation can't unlock the "
                    "user."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: rate limiter on {origin}{target_path} "
                     f"appears resilient to forwarded-IP rotation "
                     f"(rotated_non_429={rotated_non_429}, "
                     f"rotated_429_seen={rotated_429_seen})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicRateLimitBypassHeadersProbe().main()
