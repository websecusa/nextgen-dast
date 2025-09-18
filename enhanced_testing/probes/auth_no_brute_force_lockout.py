#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: login endpoint has no brute-force lockout.

A correctly-protected login endpoint should respond to a flurry of
failed attempts with one of: HTTP 429 with `Retry-After`, an account
lockout (subsequent attempts return a different error), or a captcha
challenge. None of those = unlimited online password guessing.

This probe fires N sequential failed logins for a known email. We
declare the endpoint unprotected when ALL N requests return the
same generic 401 (or whatever the wrong-password code is) within a
short window AND no `Retry-After` / `X-RateLimit-*` / lockout-shaped
response body appears.

This is intentionally NOT destructive — we use a known-bad password
that has no chance of succeeding. The account being targeted (a
documented seed account) will accumulate failed-login telemetry; the
operator should be aware before running this against an account they
care about.

Detection signal:
  N=20 failed POST /rest/user/login → all 20 return 401, mean
  response time stays steady, no rate-limit headers appear.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGIN_PATH = "/rest/user/login"
DEFAULT_TRIALS = 20


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class AuthNoBruteForceLockoutProbe(Probe):
    name = "auth_no_brute_force_lockout"
    summary = ("Detects login endpoint with no brute-force lockout — "
               "20 failed logins all return 401 within seconds.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target-email", default="admin@juice-sh.op",
            help="Email to attempt against (default: admin@juice-sh.op). "
                 "Must be a known seed account.")
        parser.add_argument(
            "--trials", type=int, default=DEFAULT_TRIALS,
            help="Number of failed-login attempts (default 20).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(origin, LOGIN_PATH)
        n = max(2, int(args.trials))
        statuses: list[int] = []
        retry_after_seen = False
        x_ratelimit_seen = False
        elapsed_total_ms = 0
        first_status = None
        last_body_excerpt = ""
        t_start = time.monotonic()
        for i in range(n):
            body = json.dumps({"email": args.target_email,
                               "password": f"wrong-{i}"}).encode()
            r = client.request("POST", url, headers={
                "Content-Type": "application/json"}, body=body)
            statuses.append(r.status)
            if first_status is None:
                first_status = r.status
            if _hdr(r.headers, "Retry-After"):
                retry_after_seen = True
            if any(_hdr(r.headers, h) for h in
                   ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                    "RateLimit-Limit", "RateLimit-Remaining")):
                x_ratelimit_seen = True
            if r.status == 429:
                last_body_excerpt = (r.text or "")[:200]
                # 429 means lockout IS in place; we can stop early.
                break
            last_body_excerpt = (r.text or "")[:200]
        elapsed_total_ms = int((time.monotonic() - t_start) * 1000)

        all_same = (len(set(statuses)) == 1 and statuses[0] in (401, 403))
        attempt = {"trials_attempted": len(statuses),
                   "statuses": statuses,
                   "all_same_status": all_same,
                   "first_status": first_status,
                   "retry_after_seen": retry_after_seen,
                   "x_ratelimit_seen": x_ratelimit_seen,
                   "elapsed_total_ms": elapsed_total_ms,
                   "last_body_excerpt": last_body_excerpt}
        evidence = {"origin": origin, "target_email": args.target_email,
                    "attempt": attempt}

        if all_same and not retry_after_seen and not x_ratelimit_seen \
                and 429 not in statuses:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: {len(statuses)} sequential failed "
                         f"logins on {origin}{LOGIN_PATH} all returned "
                         f"{statuses[0]} within {elapsed_total_ms} ms — "
                         "no 429, no Retry-After, no lockout. Endpoint "
                         "is open to unlimited online password guessing."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Add per-account and per-IP rate limits to the "
                    "login endpoint. A typical policy: 5 failed "
                    "attempts in 5 minutes triggers a 30-minute "
                    "lockout, or a captcha challenge. Attach a "
                    "`Retry-After` header to make the limiter "
                    "discoverable to honest clients. Pair with email "
                    "alerting on suspicious patterns."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: login endpoint on {origin} appears "
                     f"rate-limited (429={429 in statuses}, "
                     f"Retry-After={retry_after_seen}, "
                     f"X-RateLimit={x_ratelimit_seen})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthNoBruteForceLockoutProbe().main()
