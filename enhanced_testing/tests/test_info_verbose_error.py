# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Positive + negative + smoke tests for info_verbose_error."""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


def test_verbose_error_validates_juice_shop(juice_shop_url):
    """Juice Shop's /rest/products/search?q=') trips a SQLite syntax
    error and the express-default error page leaks the engine name."""
    v = run_probe("info_verbose_error", juice_shop_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop returns SQLITE_ERROR via verbose 5xx; probe should "
        f"have detected it. summary={v.get('summary')!r}")
    confirmed = ((v.get("evidence") or {}).get("confirmed") or [{}])[0]
    assert "SQLite" in (confirmed.get("error_family") or ""), (
        f"expected SQLite engine error family; got: "
        f"{confirmed.get('error_family')!r}")


def test_verbose_error_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("info_verbose_error", clean_ref_url)
    assert v["ok"] is True
    assert v["validated"] is False


def test_verbose_error_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "info_verbose_error.py"),
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
