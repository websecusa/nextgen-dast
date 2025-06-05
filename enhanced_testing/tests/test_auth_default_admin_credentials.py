# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Positive + negative + smoke tests for auth_default_admin_credentials."""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


# `allow_destructive: True` is set in every config below because login
# *requires* POST. The probe is semantically read-only (no state-
# changing payload) but the safety framework gates POST/PUT/PATCH/DELETE
# unless this flag is on. The orchestrator allows it via
# _PROBES_NEEDING_POST in production.
#
# max_requests has to fit (#cred-pairs × #login-paths) in the worst case
# — with the expanded generic credential list (~27 pairs) and ~5 login
# paths the worst case is ~135 attempts before the probe gives up. Set
# 200 to leave headroom and to keep the smoke test green when every
# request fails (connection refused on 127.0.0.1:1).
_AUTH_PROBE_CONFIG = {"allow_destructive": True,
                      "max_requests": 200, "max_rps": 20.0}


def test_default_admin_credentials_validates_juice_shop(juice_shop_url):
    """Juice Shop seeds admin@juice-sh.op / admin123 with role='admin'.
    The probe must log in, decode the issued JWT, and verify the role
    claim before declaring validated=True."""
    v = run_probe("auth_default_admin_credentials", juice_shop_url,
                  **_AUTH_PROBE_CONFIG)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop seeds admin@juice-sh.op / admin123 — probe should "
        f"have lit up. summary={v.get('summary')!r}")
    confirmed = (v.get("evidence") or {}).get("confirmed") or {}
    assert confirmed.get("email") == "admin@juice-sh.op", (
        f"expected admin@juice-sh.op, got: {confirmed.get('email')!r}")
    assert "role=" in (confirmed.get("jwt_admin_claim") or "")


def test_default_admin_credentials_quiet_on_clean_ref(clean_ref_url):
    """Static nginx with no /rest/user/login endpoint must produce no
    finding — every login path returns 404."""
    v = run_probe("auth_default_admin_credentials", clean_ref_url,
                  **_AUTH_PROBE_CONFIG)
    assert v["ok"] is True
    assert v["validated"] is False, (
        f"clean reference has no login endpoint; probe should be quiet. "
        f"summary={v.get('summary')!r}")


def test_default_admin_credentials_smoke_no_stack():
    """Probe handles unreachable target gracefully — even against a
    refused-connection target every cred×path combination fires a
    request, so the budget here matches _AUTH_PROBE_CONFIG."""
    proc = subprocess.run(
        [sys.executable,
         str(PROBES_DIR / "auth_default_admin_credentials.py"),
         "--stdin"],
        input=json.dumps({
            "url": "http://127.0.0.1:1",
            "scope": [], "max_requests": 200, "max_rps": 20.0,
            "allow_destructive": True,
        }).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True
    assert out["validated"] is False
