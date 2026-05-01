# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Round-2 probe tests — five new probes, one test class each.

Three of these have positive controls on Juice Shop (the bug actually
exists on this build); two are catalog-only (the bug is patched on
this Juice Shop build, but the probe is correct and ships for use
against other targets — those tests assert validated=False on Juice
Shop, which guards against false positives).
"""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import run_probe, PROBES_DIR


# Probes with login attempts need allow_destructive: True (POST is
# gated by the safety framework). Higher max_requests because the
# expanded payload lists multiply.
_AUTH_CONFIG = {"allow_destructive": True,
                "max_requests": 200, "max_rps": 20.0}
_GET_CONFIG  = {"max_requests": 60, "max_rps": 20.0}


# ---- auth_sql_login_bypass — Juice Shop POSITIVE -------------------------
# Juice Shop's seeded Login Admin challenge: ' OR 1=1-- on the email
# field returns a JWT decoding to admin@juice-sh.op / role:admin.

def test_sql_login_bypass_validates_juice_shop(juice_shop_url):
    v = run_probe("auth_sql_login_bypass", juice_shop_url, **_AUTH_CONFIG)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop's login is famously SQL-injectable; probe must "
        f"detect it. summary={v.get('summary')!r}")
    confirmed = (v.get("evidence") or {}).get("confirmed") or {}
    assert "role=" in (confirmed.get("jwt_admin_claim") or "")


def test_sql_login_bypass_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("auth_sql_login_bypass", clean_ref_url, **_AUTH_CONFIG)
    assert v["validated"] is False


def test_sql_login_bypass_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "auth_sql_login_bypass.py"),
         "--stdin"],
        input=json.dumps({"url": "http://127.0.0.1:1", "scope": [],
                          "max_requests": 200, "max_rps": 20.0,
                          "allow_destructive": True}).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["validated"] is False


# ---- info_key_material_exposed — Juice Shop POSITIVE ---------------------
# /encryptionkeys/premium.key is a 50-byte AES blob; /encryptionkeys/jwt.pub
# is a PEM RSA public key. Either firing is sufficient.

def test_key_material_exposed_validates_juice_shop(juice_shop_url):
    v = run_probe("info_key_material_exposed", juice_shop_url, **_GET_CONFIG)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop ships /encryptionkeys/jwt.pub publicly; probe "
        f"must detect it. summary={v.get('summary')!r}")
    confirmed = (v.get("evidence") or {}).get("confirmed") or []
    assert any("/encryptionkeys/" in c.get("path", "") for c in confirmed)


def test_key_material_exposed_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("info_key_material_exposed", clean_ref_url, **_GET_CONFIG)
    assert v["validated"] is False


def test_key_material_exposed_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "info_key_material_exposed.py"),
         "--stdin"],
        input=json.dumps({"url": "http://127.0.0.1:1", "scope": [],
                          "max_requests": 60, "max_rps": 20.0}).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["validated"] is False


# ---- path_traversal_extension_bypass — Juice Shop POSITIVE ---------------
# /ftp/package.json.bak%2500.md returns the package backup body —
# the .md whitelist is bypassed via the URL-encoded NUL.

def test_extension_bypass_validates_juice_shop(juice_shop_url):
    v = run_probe("path_traversal_extension_bypass", juice_shop_url,
                  **_GET_CONFIG)
    assert v["ok"] is True, f"probe errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"Juice Shop is famously bypassable via /ftp/file.bak%2500.md; "
        f"probe must detect it. summary={v.get('summary')!r}")
    confirmed = (v.get("evidence") or {}).get("confirmed") or []
    assert any(c.get("filename", "").startswith("package.json.bak")
               for c in confirmed)


def test_extension_bypass_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("path_traversal_extension_bypass", clean_ref_url,
                  **_GET_CONFIG)
    assert v["validated"] is False


def test_extension_bypass_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable,
         str(PROBES_DIR / "path_traversal_extension_bypass.py"),
         "--stdin"],
        input=json.dumps({"url": "http://127.0.0.1:1", "scope": [],
                          "max_requests": 60, "max_rps": 20.0}).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["validated"] is False


# ---- auth_jwt_alg_none — Juice Shop NEGATIVE (catalog only) --------------
# This Juice Shop build patched alg=none acceptance. The probe should
# correctly NOT fire — anything else means we're about to start
# false-positiving on every signed-JWT app in production.

def test_jwt_alg_none_quiet_on_juice_shop(juice_shop_url):
    v = run_probe("auth_jwt_alg_none", juice_shop_url, **_GET_CONFIG)
    assert v["ok"] is True
    assert v["validated"] is False, (
        f"Juice Shop's whoami doesn't echo the forged email — probe "
        f"must NOT report a finding. summary={v.get('summary')!r}")


def test_jwt_alg_none_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("auth_jwt_alg_none", clean_ref_url, **_GET_CONFIG)
    assert v["validated"] is False


def test_jwt_alg_none_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "auth_jwt_alg_none.py"),
         "--stdin"],
        input=json.dumps({"url": "http://127.0.0.1:1", "scope": [],
                          "max_requests": 60, "max_rps": 20.0}).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["validated"] is False


# ---- auth_nosql_login_bypass — Juice Shop NEGATIVE (catalog only) --------
# This Juice Shop build returns 500 on object-typed login; probe
# must correctly NOT fire.

def test_nosql_login_bypass_quiet_on_juice_shop(juice_shop_url):
    v = run_probe("auth_nosql_login_bypass", juice_shop_url, **_AUTH_CONFIG)
    assert v["ok"] is True
    assert v["validated"] is False


def test_nosql_login_bypass_quiet_on_clean_ref(clean_ref_url):
    v = run_probe("auth_nosql_login_bypass", clean_ref_url, **_AUTH_CONFIG)
    assert v["validated"] is False


def test_nosql_login_bypass_smoke_no_stack():
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / "auth_nosql_login_bypass.py"),
         "--stdin"],
        input=json.dumps({"url": "http://127.0.0.1:1", "scope": [],
                          "max_requests": 200, "max_rps": 20.0,
                          "allow_destructive": True}).encode(),
        capture_output=True, timeout=30, check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["validated"] is False
