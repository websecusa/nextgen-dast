#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: username enumeration via login response-time
differential.

Apps that branch their login flow on whether the email is on file
(skipping the password hash check entirely for unknown emails)
respond noticeably faster to unknown emails. The differential lets
an attacker enumerate which addresses have an account.

This is statistical — single requests are noisy. We sample multiple
trials per branch and require the slow/fast ratio to be large AND
the unknown-side mean to be small in absolute terms. Conservative
thresholds (3× mean ratio AND unknown < 30 ms) avoid false-positives
on apps with naturally varying response times.

Detection signal:
  mean(known_email_login_attempts) / mean(unknown_email_login_attempts)
  >= 3.0 AND mean(unknown) < 30 ms.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

LOGIN_PATH = "/rest/user/login"
TRIALS_PER_BRANCH = 5
RATIO_THRESHOLD   = 3.0
UNKNOWN_MEAN_MAX_MS = 30


def _time_login(client: SafeClient, url: str,
                email: str, password: str) -> int:
    body = json.dumps({"email": email, "password": password}).encode()
    t0 = time.monotonic()
    client.request("POST", url, headers={
        "Content-Type": "application/json"}, body=body)
    return int((time.monotonic() - t0) * 1000)


class AuthUsernameEnumTimingProbe(Probe):
    name = "auth_username_enum_timing"
    summary = ("Detects login response-time differential that lets an "
               "attacker enumerate registered emails.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--known-email", default="admin@juice-sh.op",
            help="Email known to exist on the target (default: "
                 "admin@juice-sh.op).")
        parser.add_argument(
            "--unknown-email-prefix", default="dast-unknown-",
            help="Prefix for the random unknown emails the probe "
                 "fabricates each trial.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(origin, LOGIN_PATH)

        # Interleave trials so unrelated jitter affects both branches
        # roughly equally.
        known_times: list[int] = []
        unknown_times: list[int] = []
        for i in range(TRIALS_PER_BRANCH):
            known_times.append(_time_login(client, url, args.known_email,
                                           "wrong-password-on-purpose"))
            ue = (f"{args.unknown_email_prefix}{i}-"
                  f"{int(time.time()*1000)}@dast.test")
            unknown_times.append(_time_login(client, url, ue,
                                             "wrong-password-on-purpose"))

        mean_known   = statistics.mean(known_times)
        mean_unknown = statistics.mean(unknown_times)
        ratio = (mean_known / mean_unknown) if mean_unknown > 0 else 0
        attempt = {"trials": TRIALS_PER_BRANCH,
                   "known_times_ms":   known_times,
                   "unknown_times_ms": unknown_times,
                   "mean_known_ms":    mean_known,
                   "mean_unknown_ms":  mean_unknown,
                   "ratio_known_over_unknown": round(ratio, 2),
                   "ratio_threshold": RATIO_THRESHOLD,
                   "unknown_max_ms":  UNKNOWN_MEAN_MAX_MS}
        evidence = {"origin": origin, "known_email": args.known_email,
                    "attempt": attempt}

        if ratio >= RATIO_THRESHOLD and mean_unknown <= UNKNOWN_MEAN_MAX_MS:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(f"Confirmed: login response-time differential "
                         f"on {origin}{LOGIN_PATH} — known emails take "
                         f"{int(mean_known)} ms vs {int(mean_unknown)} ms "
                         f"for unknown ({ratio:.1f}× ratio). The fast "
                         "path proves the address is unknown."),
                evidence=evidence,
                severity_uplift="medium",
                remediation=(
                    "Run a no-op bcrypt compare on every login attempt, "
                    "even for unknown addresses, so the response time "
                    "depends on the password-hash work, not on whether "
                    "the email exists. Better still: refactor the "
                    "endpoint to return a generic '401' on any failure "
                    "regardless of cause."),
            )
        return Verdict(
            validated=False, confidence=0.8,
            summary=(f"Refuted: login timing differential on {origin} "
                     f"insufficient (ratio {ratio:.1f}, unknown mean "
                     f"{int(mean_unknown)} ms)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AuthUsernameEnumTimingProbe().main()
