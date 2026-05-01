#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Boolean-based SQL injection confirmation.

Sends two crafted values for the target parameter — one that should always
be TRUE, one that should always be FALSE — and looks for a meaningful
difference in response. If the responses are identical, the parameter is
not boolean-injectable and the original finding is downgraded to false
positive.

Examples (CLI):
    python sqli_boolean.py --url 'https://x.com/p?id=1' --param id
    python sqli_boolean.py --url 'https://x.com/p?id=1' --param id \\
        --time-based --threshold 100

Examples (orchestrator):
    cat finding.json | python sqli_boolean.py --stdin
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict
from lib.http import SafeClient


# Standard boolean payload pairs. Tried in order until one shows a delta.
DEFAULT_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),       # string close, MySQL/PG
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),                # numeric close
    (") AND (1=1", ") AND (1=2"),            # subquery close
    (") AND ('a'='a", ") AND ('a'='b"),
]

# Time-based fallback (when the app suppresses both responses identically).
TIME_PAYLOAD = " AND SLEEP(5)-- "


def _swap_param(url: str, param: str, payload_suffix: str) -> str:
    """Inject `payload_suffix` after the existing value of `param` in the
    query string. If the param isn't present, append it."""
    u = urlparse(url)
    q = list(parse_qsl(u.query, keep_blank_values=True))
    found = False
    for i, (k, v) in enumerate(q):
        if k == param:
            q[i] = (k, v + payload_suffix)
            found = True
            break
    if not found:
        q.append((param, payload_suffix))
    return urlunparse(u._replace(query=urlencode(q, doseq=True)))


class SqliBooleanProbe(Probe):
    name = "sqli_boolean"
    summary = "Boolean-based SQL injection confirmation via response-difference analysis."
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument("--threshold", type=int, default=50,
                            help="Minimum response-size delta (bytes) to "
                                 "treat as a real difference (default 50)")
        parser.add_argument("--time-based", action="store_true",
                            help="Fall back to time-based detection if "
                                 "boolean diff is inconclusive")
        parser.add_argument("--time-threshold", type=float, default=4.0,
                            help="Seconds delta required for time-based "
                                 "detection (default 4.0)")

    def run(self, args, client: SafeClient) -> Verdict:
        param = args.param
        if not param:
            return Verdict(ok=False, validated=None,
                           summary="--param is required for sqli_boolean")

        # Step 1: baseline
        baseline = client.request(args.method, args.url)
        if baseline.status == 0:
            return Verdict(ok=False, validated=None,
                           summary="target unreachable; cannot test")

        # Step 2: try each true/false payload pair
        for true_p, false_p in DEFAULT_PAIRS:
            true_url = _swap_param(args.url, param, true_p)
            false_url = _swap_param(args.url, param, false_p)
            t = client.request(args.method, true_url)
            f = client.request(args.method, false_url)
            if t.status == 0 or f.status == 0:
                continue
            delta = abs(t.size - f.size)
            if delta >= args.threshold and t.size != baseline.size:
                return Verdict(
                    validated=True, confidence=0.85,
                    summary=(f"Boolean-based SQLi confirmed in `{param}` — "
                             f"true/false payloads produced different "
                             f"responses ({delta} byte delta)."),
                    evidence={
                        "true_payload": true_p, "false_payload": false_p,
                        "true_status": t.status, "false_status": f.status,
                        "true_size": t.size,    "false_size": f.size,
                        "delta_bytes": delta,
                        "baseline_size": baseline.size,
                    },
                    remediation=(
                        "Use parameterised queries / prepared statements "
                        "instead of string concatenation. Validate input "
                        "type at the application layer."),
                    severity_uplift="high",
                )

        # Step 3: optional time-based fallback
        if args.time_based:
            time_url = _swap_param(args.url, param, TIME_PAYLOAD)
            t0 = time.monotonic()
            r = client.request(args.method, time_url)
            elapsed = time.monotonic() - t0
            if r.status != 0 and elapsed >= args.time_threshold:
                return Verdict(
                    validated=True, confidence=0.7,
                    summary=(f"Time-based SQLi confirmed in `{param}` — "
                             f"SLEEP(5) payload caused {elapsed:.1f}s delay."),
                    evidence={"elapsed_sec": round(elapsed, 2),
                              "payload": TIME_PAYLOAD},
                    remediation=("Use parameterised queries; never "
                                 "concatenate user input into SQL."),
                    severity_uplift="high",
                )

        return Verdict(
            validated=False, confidence=0.7,
            summary=(f"No boolean-difference signal in `{param}`. "
                     "Likely false positive."),
            evidence={"baseline_size": baseline.size,
                      "pairs_tried": len(DEFAULT_PAIRS)},
        )


if __name__ == "__main__":
    SqliBooleanProbe().main()
