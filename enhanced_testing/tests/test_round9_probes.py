# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Round-9 probe tests — covers the 20 new TTPs added under
`action_plan_enhanced_testing.md`.

Test triple per probe (mirrors `test_round3_probes.py`):
  - validates_juice_shop / quiet_on_juice_shop — whether THIS build
    of Juice Shop exhibits the issue. The action-plan §3 specs each
    probe's expected verdict against Juice Shop 19.x; we hard-code
    that here.
  - quiet_on_clean_ref — every probe must stay quiet on the clean-
    nginx negative control. A `validated=True` from clean-ref is a
    false-positive bug.
  - smoke_no_stack — every probe must run cleanly against an
    unreachable target (exit 0, valid JSON, no validated=True).

Probes that need POST/PUT/PATCH get `allow_destructive: True` in
the stdin config.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import run_probe, PROBES_DIR


# Single source of truth for the 20 round-9 probes.
# `juice_expects`: "validated" / "refuted"
#                  - "validated" means the probe MUST return validated=True
#                    against Juice Shop on this build (positive control).
#                  - "refuted" means the probe MUST return validated=False
#                    or validated=None against Juice Shop (Juice Shop has
#                    fixed / never had this class of bug). The probe still
#                    fires on real targets that don't have the fix.
_PROBES = [
    # ----- Critical / high — direct compromise -----------------------
    {"name": "info_excessive_data_users_password",     "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "info_excessive_data_cards",              "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "info_graphql_introspection_schema",      "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "api_pagination_unbounded",               "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "auth_host_header_password_reset",        "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "xss_reflected_search_query",             "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "path_traversal_static_serve",            "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "authz_pii_idor_user_enum",               "needs_post": True,
     "juice_expects": "validated", "max_requests": 80},
    {"name": "authz_api_legacy_v1_auth_bypass",        "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 80},
    # ----- Cache / network / framing ---------------------------------
    {"name": "config_cache_deception_path_extension",  "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "config_cache_poison_xforwarded_host",    "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "config_clickjacking_frame_ancestors",    "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "config_csp_missing_or_unsafe",           "needs_post": False,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "config_websocket_origin_validation",     "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    # ----- Information disclosure ------------------------------------
    {"name": "info_backup_files_root",                 "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "info_diagnostic_endpoints_exposed",      "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "path_traversal_nginx_alias_off_by_slash", "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "config_basic_auth_over_http",            "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "config_xcontent_type_options_missing",   "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "auth_session_fixation_no_rotation",      "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
]


def _config_for(p: dict) -> dict:
    cfg: dict = {"max_requests": p.get("max_requests", 60),
                 "max_rps": 20.0}
    if p.get("needs_post"):
        cfg["allow_destructive"] = True
    return cfg


_VALIDATED_ON_JUICE = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "validated"]
_REFUTED_ON_JUICE   = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "refuted"]


# --- Positive (Juice Shop should fire) -----------------------------------

@pytest.mark.parametrize("name", _VALIDATED_ON_JUICE)
def test_probe_validates_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"{name} should validate against Juice Shop. "
        f"summary={v.get('summary')!r}")
    # Round-9 contract: validated=True must come with confidence >= 0.85.
    # The verdict_to_status floor is 0.7; we hold round-9 probes to a
    # tighter bar so they survive the bulk-Challenge runner without
    # producing soft-validate noise.
    assert (v.get("confidence") or 0) >= 0.85, (
        f"{name} validated at confidence {v.get('confidence')} -- "
        "round-9 probes must validate at >= 0.85.")


# --- Catalog-only (probe stays quiet on this Juice Shop build) -----------

@pytest.mark.parametrize("name", _REFUTED_ON_JUICE)
def test_probe_quiet_on_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    # Refuted (False) or inconclusive (None) are both acceptable on a
    # catalog-only probe -- what we don't want is a false-positive True.
    assert v["validated"] is not True, (
        f"{name} false-positived on Juice Shop. "
        f"summary={v.get('summary')!r}")


# --- Negative (clean nginx must stay quiet on EVERY probe) ---------------

@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_quiet_on_clean_ref(clean_ref_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, clean_ref_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is not True, (
        f"{name} false-positived on the clean-ref site. "
        f"summary={v.get('summary')!r}")


# --- Smoke (no stack required) -------------------------------------------

@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_smoke_no_stack(name):
    """Probe must run cleanly against an unreachable target -- exit 0,
    valid JSON output, no exception leak."""
    p = next(p for p in _PROBES if p["name"] == name)
    cfg = {"url": "http://127.0.0.1:1", "scope": [],
           **_config_for(p), "max_requests": 60, "max_rps": 20.0}
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / f"{name}.py"), "--stdin"],
        input=json.dumps(cfg).encode(),
        capture_output=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, (
        f"{name} did not exit 0 against unreachable target. "
        f"stderr={proc.stderr.decode('utf-8','replace')[:500]!r}")
    out = json.loads(proc.stdout)
    assert out["validated"] is not True, (
        f"{name} false-positived on unreachable target. "
        f"summary={out.get('summary')!r}")
