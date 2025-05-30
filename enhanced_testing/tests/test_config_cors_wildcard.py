# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Positive + negative + smoke tests for config_cors_wildcard."""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


def test_cors_wildcard_validates_juice_shop(juice_shop_url):
    """Juice Shop's /rest/user/whoami preflight returns ACAO=* AND
    advertises Authorization in Access-Control-Allow-Headers — a real
    misconfig on an auth-bearing endpoint."""
    v = run_probe("config_cors_wildcard", juice_shop_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop returns ACAO=* + ACAH:authorization on whoami; "
        f"probe should have lit up. summary={v.get('summary')!r}")
    confirmed = ((v.get("evidence") or {}).get("confirmed") or [{}])[0]
    assert confirmed.get("ACAO") == "*"


def test_cors_wildcard_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("config_cors_wildcard", clean_ref_url)
    assert v["ok"] is True
    assert v["validated"] is False


def test_cors_wildcard_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "config_cors_wildcard.py"),
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
