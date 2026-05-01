# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Tests for auth_vendor_default_credentials.

Juice Shop is an Express/Angular app and intentionally doesn't ship with
any of the vendor login surfaces this probe targets (no Tomcat Manager,
no WordPress, no phpMyAdmin, etc.). That makes Juice Shop the *negative*
control here: the probe must report `validated=False` AND record
`vendors_matched: []` because no vendor was fingerprinted.

Same shape applies to the clean-ref nginx — even more obvious negative.

The smoke test confirms the probe runs cleanly against an unreachable
target without crashing. Positive control for this probe (a real
vendor stack with default creds) lives in a follow-up probe-stack
container; for now, the negative tests are sufficient to catch
fingerprint-logic regressions.
"""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


# All login attempts in this probe are POST or basic-auth, both of
# which trip the safety framework's destructive gate. The orchestrator
# allows it via _PROBES_NEEDING_POST in production; tests pass it
# explicitly.
_VENDOR_PROBE_CONFIG = {"allow_destructive": True,
                        "max_requests": 80, "max_rps": 20.0}


def test_vendor_creds_quiet_on_juice_shop(juice_shop_url):
    """Juice Shop is none of the vendors in our catalog. The probe
    should fingerprint, find no match, and stop without firing any
    login attempts. validated=False with vendors_matched=[] is the
    correct outcome — anything else means the fingerprinting is
    over-eager and would false-positive in production."""
    v = run_probe("auth_vendor_default_credentials", juice_shop_url,
                  **_VENDOR_PROBE_CONFIG)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is False, (
        f"Juice Shop is not a Tomcat/WordPress/phpMyAdmin/Jenkins/"
        f"Grafana/JBoss/Adminer/Kibana host; probe should report no "
        f"finding. summary={v.get('summary')!r}")
    matched = (v.get("evidence") or {}).get("vendors_matched", [])
    assert matched == [], (
        f"fingerprinting incorrectly matched: {matched!r}. The vendor "
        f"signatures are too loose — tighten the regexes.")


def test_vendor_creds_quiet_on_clean_ref(clean_ref_url):
    """Hardened nginx has no vendor login surfaces. Probe must be
    silent. A failure here means the probe is firing on the wrong
    signal."""
    v = run_probe("auth_vendor_default_credentials", clean_ref_url,
                  **_VENDOR_PROBE_CONFIG)
    assert v["ok"] is True
    assert v["validated"] is False, (
        f"clean reference triggered a vendor match — false positive. "
        f"evidence={v.get('evidence')!r}")
    matched = (v.get("evidence") or {}).get("vendors_matched", [])
    assert matched == []


def test_vendor_creds_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable,
         str(PROBES_DIR / "auth_vendor_default_credentials.py"),
         "--stdin"],
        input=json.dumps({
            "url": "http://127.0.0.1:1",
            "scope": [], "max_requests": 80, "max_rps": 20.0,
            "allow_destructive": True,
        }).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True
    assert out["validated"] is False
