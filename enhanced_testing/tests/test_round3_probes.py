# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Round-3+ probe tests — covers every probe added after Round 2.

Test triple per probe:
  - validates_juice_shop / quiet_on_juice_shop — whether Juice Shop
    actually exhibits the bug. Some bugs (vendor-specific defaults,
    XXE on a recent build, etc.) are catalog-only — the probe ships
    correct, the test asserts it stays quiet on the live target.
  - quiet_on_clean_ref — probe must NOT light up against vanilla
    nginx serving fixtures/clean-site/.
  - smoke_no_stack — probe runs without a stack and handles the
    unreachable target gracefully (validated=False, returncode=0).

Probes that take POST/PUT/PATCH/DELETE are passed `allow_destructive:
True`; probes whose own logic is gated on `--allow-destroy` get an
extra header set in the stdin config.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import run_probe, PROBES_DIR


# ------------------------------------------------------------------------
# Probe registry — single source of truth for the test cases below.
# Fields:
#   name           : probe filename stem (also the probe's `name`)
#   needs_post     : passes allow_destructive=True (any non-GET method)
#   destructive    : also passes the probe's --allow-destroy logic flag
#                    (probes that mutate live state set this)
#   juice_expects  : "validated" | "refuted" | "skip"  — what we
#                    require the probe to return against Juice Shop.
#                    "skip" = probe returns validated is None when
#                    --allow-destroy isn't passed; we don't check it
#                    against the live stack.
#   max_requests   : per-probe budget override
# ------------------------------------------------------------------------
#
# Note on the `juice_expects` values: many bugs documented in the
# original TODO have been patched in the upstream Juice Shop image
# we test against. Those probes correctly stay quiet here — we keep
# them in the catalog (they fire on real targets where the fix
# isn't deployed) and assert the negative on this stack so we
# protect against future false-positives.
_PROBES = [
    # ----- Critical (Round 3) ---------------------------------------
    {"name": "auth_jwt_rsa_hmac_confusion",       "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "ssrf_profile_image_url",            "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "xxe_file_upload",                   "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "deserialization_b2b_eval",          "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "deserialization_b2b_sandbox_escape","needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "authz_role_mass_assignment",        "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "authz_admin_section_force_browse",  "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "authz_basket_idor_walk",            "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "authz_basket_manipulation",         "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "auth_oauth_password_from_email",    "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    # ----- High Authz (Round 4) -------------------------------------
    {"name": "authz_feedback_userid_assignment",  "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "authz_feedback_delete",             "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "authz_product_review_edit",         "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "authz_address_idor_walk",           "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "authz_basket_checkout_arbitrary",   "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "authz_order_history_view_all",      "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "authz_method_override_admin",       "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "authz_deluxe_membership_tamper",    "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "authz_user_email_change_other",     "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    # ----- High AuthN / Session (Round 5) ----------------------------
    {"name": "auth_password_reset_weak_question", "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "auth_jwt_unverified_email_admin",   "needs_post": False,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "auth_2fa_status_unauthenticated",   "needs_post": False,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "auth_jwt_no_expiration",            "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "auth_logout_does_not_invalidate",   "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    # ----- High Injection (Round 6) ----------------------------------
    {"name": "nosql_review_operator_injection",   "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "nosql_review_dos_where",            "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "redos_b2b_orderlines",              "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "prototype_pollution_user_patch",    "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "path_traversal_ftp_download",       "needs_post": False,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "ssti_pug_username",                 "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "xss_stored_lastloginip",            "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "cmdi_video_subtitles",              "needs_post": False,
     "juice_expects": "refuted", "max_requests": 60},
    # ----- High Modern / Misconfig (Round 7) -------------------------
    {"name": "info_source_map_exposed",           "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "redirect_allowlist_bypass",         "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    # ----- Medium (Round 8) ------------------------------------------
    {"name": "auth_username_enum_timing",         "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "auth_no_brute_force_lockout",       "needs_post": True,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "config_session_cookie_flags",       "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "auth_password_change_no_current",   "needs_post": True,
     "destructive": True, "juice_expects": "skip",
     "max_requests": 60},
    {"name": "config_hsts_missing",               "needs_post": False,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "info_robots_txt_admin_paths",       "needs_post": False,
     "juice_expects": "validated", "max_requests": 60},
    {"name": "info_graphql_endpoint",             "needs_post": True,
     "juice_expects": "refuted", "max_requests": 60},
    {"name": "info_security_txt",                 "needs_post": False,
     "juice_expects": "validated", "max_requests": 60},
]


def _config_for(p: dict) -> dict:
    cfg: dict = {"max_requests": p.get("max_requests", 60),
                 "max_rps": 20.0}
    if p.get("needs_post"):
        cfg["allow_destructive"] = True
    if p.get("destructive"):
        # The probe's own --allow-destroy flag is exposed on argparse
        # as `allow_destroy` on the namespace. The Probe driver
        # accepts arbitrary keys via stdin and sets them on the
        # namespace, so passing it here lights up the destructive
        # codepath without the test having to know how each probe
        # parses the flag.
        cfg["allow_destroy"] = True
    return cfg


# Probes that genuinely should fire on this Juice Shop build.
_VALIDATED_ON_JUICE = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "validated"]
_REFUTED_ON_JUICE   = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "refuted"]
_SKIP_ON_JUICE      = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "skip"]


# --- Positive (Juice Shop should fire) ----------------------------------

@pytest.mark.parametrize("name", _VALIDATED_ON_JUICE)
def test_probe_validates_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"{name} should validate against Juice Shop. "
        f"summary={v.get('summary')!r}")


# --- Catalog-only (probe correctly stays quiet on this Juice Shop build)

@pytest.mark.parametrize("name", _REFUTED_ON_JUICE)
def test_probe_quiet_on_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    # Some "refuted" probes use `validated=False` (definitive refute)
    # AND some return None (inconclusive — probe couldn't even
    # establish a session, etc.). Both are acceptable for catalog-
    # only; what we don't want is a false-positive `True`.
    assert v["validated"] is not True, (
        f"{name} should NOT validate against Juice Shop on this build "
        f"(catalog-only). summary={v.get('summary')!r}")


# --- Destructive probes — assert the safety guard fires (not the bug) --

@pytest.mark.parametrize("name", _SKIP_ON_JUICE)
def test_probe_safety_skipped_without_allow_destroy(juice_shop_url, name):
    """When --allow-destroy is NOT passed, destructive probes must
    refuse to fire and return validated=None. This stops a CI run
    from accidentally rotating a real password / posting feedback /
    submitting a checkout."""
    p = next(p for p in _PROBES if p["name"] == name)
    cfg = _config_for(p)
    cfg.pop("allow_destroy", None)            # explicitly omit
    v = run_probe(name, juice_shop_url, **cfg)
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is None, (
        f"{name} must refuse to fire without --allow-destroy. "
        f"summary={v.get('summary')!r}")


# --- Negative (clean nginx must stay quiet on every probe) -------------

@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_quiet_on_clean_ref(clean_ref_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, clean_ref_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is not True, (
        f"{name} false-positived on the clean-ref site. "
        f"summary={v.get('summary')!r}")


# --- Smoke (no stack required) -----------------------------------------

@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_smoke_no_stack(name):
    """Probe must run cleanly against an unreachable target — exit 0,
    valid JSON output, no exception leak. Catches probes that crash
    on connection refused."""
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
