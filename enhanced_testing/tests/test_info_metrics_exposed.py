# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Positive + negative + smoke tests for info_metrics_exposed."""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


def test_metrics_exposed_validates_juice_shop(juice_shop_url):
    v = run_probe("info_metrics_exposed", juice_shop_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop exposes /metrics in Prometheus format; probe "
        f"should have detected it. summary={v.get('summary')!r}")
    confirmed = ((v.get("evidence") or {}).get("confirmed") or [{}])[0]
    assert confirmed.get("path") == "/metrics"
    assert confirmed.get("metric_help_lines", 0) >= 1
    assert confirmed.get("sample_lines", 0) >= 1


def test_metrics_exposed_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("info_metrics_exposed", clean_ref_url)
    assert v["ok"] is True
    assert v["validated"] is False


def test_metrics_exposed_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "info_metrics_exposed.py"),
         "--stdin"],
        input=json.dumps({
            "url": "http://127.0.0.1:1",
            "scope": [], "max_requests": 30, "max_rps": 20.0,
        }).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True
    assert out["validated"] is False
