#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: Prometheus / OpenMetrics exposition reachable
without authentication.

Metrics endpoints are useful for ops and dangerous for attackers in
the same breath. They reliably expose:
  - the application's stack and version (e.g. nodejs_version_info,
    python_info, jvm_info)
  - process internals (memory pressure, file descriptor counts,
    queue depth) — handy for timing attacks and DoS calibration
  - request counters labelled by path/status — a free crawl hint for
    every endpoint the app actually serves
  - business labels in counters (`file_uploads_count{type=...}`,
    `juiceshop_startup_duration_seconds{task=...}`) — turn-by-turn
    fingerprint of the application

The signature of a Prometheus exposition is unmistakable: lines
starting with `# HELP <name>`, `# TYPE <name>`, and at least one
sample line. That's what this probe asserts.

Tested against:
  + OWASP Juice Shop  /metrics  →  validated=True
                                   (juiceshop_startup_duration_seconds,
                                    file_uploads_count, etc.)
  + nginx default site                       →  validated=False
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

DEFAULT_PATHS = (
    "/metrics",                 # canonical Prometheus path
    "/api/metrics",
    "/actuator/prometheus",     # Spring Boot actuator
    "/_metrics",
    "/admin/metrics",
)

# A real exposition has all three:
#   1. at least one `# HELP <metric_name> <description>` line
#   2. at least one `# TYPE <metric_name> <type>` line
#   3. at least one sample line (metric_name{labels} value)
_HELP_RE   = re.compile(r"^#\s*HELP\s+\w+\s+", re.MULTILINE)
_TYPE_RE   = re.compile(r"^#\s*TYPE\s+\w+\s+(counter|gauge|histogram|summary|untyped)\b",
                        re.MULTILINE | re.IGNORECASE)
_SAMPLE_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?\s+[\d.eE+\-]+",
                        re.MULTILINE)

# Stack-fingerprint metrics worth highlighting in the summary.
_FINGERPRINT_METRICS = (
    "nodejs_version_info", "python_info", "jvm_info",
    "go_info", "process_runtime_",
)


class MetricsExposedProbe(Probe):
    name = "info_metrics_exposed"
    summary = ("Detects Prometheus/OpenMetrics endpoints reachable "
               "without authentication.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional metrics path to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(DEFAULT_PATHS) + list(args.path or [])

        tested: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("GET", url)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                text = r.text
                # Three independent markers must all be present to call
                # this an exposition. That keeps the probe quiet on
                # arbitrary text/plain endpoints that happen to start
                # with `#`.
                help_count   = len(_HELP_RE.findall(text))
                type_count   = len(_TYPE_RE.findall(text))
                sample_count = len(_SAMPLE_RE.findall(text))
                if help_count >= 1 and type_count >= 1 and sample_count >= 1:
                    fingerprints = [m for m in _FINGERPRINT_METRICS
                                    if m in text]
                    row.update({
                        "is_metrics_exposition": True,
                        "metric_help_lines": help_count,
                        "metric_type_lines": type_count,
                        "sample_lines": sample_count,
                        "stack_fingerprints": fingerprints,
                    })
                    confirmed.append(row)
            tested.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "paths_tested": tested}
        if confirmed:
            top = confirmed[0]
            fp_note = (f" Stack fingerprint(s): "
                       + ", ".join(top["stack_fingerprints"])
                       if top["stack_fingerprints"] else "")
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: Prometheus/OpenMetrics exposition "
                         f"reachable at {origin}{top['path']} "
                         f"({top['sample_lines']} samples across "
                         f"{top['metric_type_lines']} metric types).{fp_note}"),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Move the metrics endpoint behind authentication or "
                    "bind it to a metrics-only network interface that "
                    "your scrapers can reach but the public can't.\n"
                    "  - Spring Boot: `management.server.port` to a "
                    "separate port + firewall it.\n"
                    "  - Express / FastAPI / Flask: gate the route with "
                    "session-based or basic-auth middleware.\n"
                    "  - Behind a reverse proxy: deny `/metrics` from "
                    "the public listener and only allow it from the "
                    "internal scraper VLAN."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(tested)} canonical metrics "
                     f"paths on {origin}; none returned a "
                     "Prometheus/OpenMetrics exposition."),
            evidence=evidence,
        )


if __name__ == "__main__":
    MetricsExposedProbe().main()
