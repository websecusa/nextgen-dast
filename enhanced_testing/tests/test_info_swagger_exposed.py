# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Positive + negative + smoke tests for info_swagger_exposed."""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


def test_swagger_exposed_quiet_on_juice_shop(juice_shop_url):
    """Juice Shop's catch-all serves the SPA shell on every /swagger.json
    / /openapi.json variant — it does NOT expose a real OpenAPI document.
    The probe should correctly report validated=False (parse the body
    and notice it's HTML, not JSON with a `swagger` / `openapi` root key).

    This test guards against a regression where the probe might flag
    'HTTP 200 + non-empty body' as the marker rather than parsing for
    the actual top-level OpenAPI keys.
    """
    v = run_probe("info_swagger_exposed", juice_shop_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is False, (
        f"Juice Shop returns the SPA shell on /swagger.json — probe "
        f"must NOT report a finding. summary={v.get('summary')!r}")


def test_swagger_exposed_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("info_swagger_exposed", clean_ref_url)
    assert v["ok"] is True
    assert v["validated"] is False, (
        f"clean reference must not expose swagger; "
        f"summary={v.get('summary')!r}")


def test_swagger_exposed_smoke_no_stack():
    """Probe handles unreachable target without crashing."""
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "info_swagger_exposed.py"),
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
