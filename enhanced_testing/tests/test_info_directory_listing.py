# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Reference test for info_directory_listing probe.

Pattern every new probe should follow:
  - one positive-control test against Juice Shop (asserts validated=True)
  - one negative-control test against the clean-ref nginx (asserts
    validated=False)
  - one structural test that doesn't need the stack up (asserts the
    probe's --stdin entry point produces a parseable Verdict shape)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from conftest import run_probe, PROBES_DIR


def test_info_directory_listing_validates_juice_shop(juice_shop_url):
    """Juice Shop's /ftp/ exposes a directory listing — multiple
    challenges in the scoreboard depend on it. The probe MUST detect
    this; if it doesn't, the probe is broken."""
    v = run_probe("info_directory_listing", juice_shop_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"expected validated=True for Juice Shop's /ftp/, got "
        f"{v['validated']!r}. summary={v.get('summary')!r}")
    # The verdict's evidence should name the path it lit up on.
    confirmed = (v.get("evidence") or {}).get("confirmed") or []
    assert any(c.get("path") == "/ftp/" for c in confirmed), (
        f"expected /ftp/ in confirmed paths, got: "
        f"{[c.get('path') for c in confirmed]}")


def test_info_directory_listing_quiet_on_clean_ref(clean_ref_url):
    """Hardened nginx with autoindex off must produce no findings.
    A failure here means the probe has a false-positive somewhere."""
    v = run_probe("info_directory_listing", clean_ref_url)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is False, (
        f"clean reference site triggered the probe — false positive. "
        f"summary={v.get('summary')!r}, "
        f"evidence={v.get('evidence')!r}")


def test_info_directory_listing_smoke_no_stack():
    """Structural sanity check that runs WITHOUT the docker stack —
    confirms the probe handles a refused-connection target with a
    sane error verdict instead of crashing.

    Lets `pytest enhanced_testing/tests/` give a useful pass/fail
    signal even on a developer machine that never brought the stack up.
    """
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "info_directory_listing.py"),
         "--stdin"],
        input=json.dumps({
            "url": "http://127.0.0.1:1",     # nothing listens here
            "scope": [], "max_requests": 30, "max_rps": 20.0,
        }).encode(),
        capture_output=True, timeout=30, check=False,
    )
    # The probe should exit 0 with a sane Verdict even when every path
    # got connection-refused. (rc=1 is reserved for safety-budget
    # violations, which this test should not trigger because we raised
    # the budget high enough to cover the whole DEFAULT_PATHS list.)
    assert proc.returncode == 0, (
        f"probe should exit 0 when the target is unreachable; "
        f"got rc={proc.returncode} stderr={proc.stderr[:500]!r}")
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True
    assert out["validated"] is False
