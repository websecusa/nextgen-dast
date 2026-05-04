# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Round-10 + Round-11 probe tests.

Round 11 (extract & generalize): 15 probes that supersede the JS-
coupled patterns in rounds 1-8. Each fires on a generic class
detector, not a Juice-Shop-literal route.

Round 10 (platform-targeted): 18 probes covering Angular / Java /
PHP / Python / IIS / AEM and three cross-stack generics.

Test triple per probe:
  - validates_juice_shop / quiet_on_juice_shop -- whether Juice
    Shop on this build exhibits the bug. Most R10 probes refute
    (Juice Shop isn't AEM / PHP / Java); a few R11 probes fire
    because the underlying class is in JS too.
  - quiet_on_clean_ref -- never fire on the negative control.
  - smoke_no_stack -- exit cleanly with valid JSON against an
    unreachable target.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import run_probe, PROBES_DIR


_PROBES = [
    # ------ Round 11 -------------------------------------------------
    {"name": "ssrf_url_field_persisted",            "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 200},
    {"name": "authz_resource_idor_walk",            "needs_post": True,
     "juice_expects": "validated", "max_requests": 200},
    {"name": "xss_stored_via_request_headers",      "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 200},
    {"name": "xxe_any_xml_upload",                  "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "cmdi_filename_param_in_query",        "needs_post": False,
     "juice_expects": "validated", "max_requests": 250},
    {"name": "path_traversal_filename_param",       "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 250},
    {"name": "prototype_pollution_any_patch",       "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "nosql_operator_injection_any_filter", "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 60},
    {"name": "redos_any_string_field",              "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "ssti_any_template_engine",            "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 200},
    {"name": "authz_mass_assignment_widened",       "needs_post": True,
     "juice_expects": "validated", "max_requests": 30},
    {"name": "auth_jwt_kid_injection",              "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 80},
    {"name": "cors_reflected_origin_with_creds",    "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 30},
    {"name": "info_admin_login_at_common_paths",    "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 40},
    {"name": "auth_password_reset_token_in_referer","needs_post": False,
     "juice_expects": "validated", "max_requests": 30},
    # ------ Round 10 -------------------------------------------------
    {"name": "angular_dev_mode_in_prod",             "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 30},
    {"name": "angular_secrets_in_bundle",            "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 30},
    {"name": "java_jenkins_script_console",          "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "java_jboss_jmx_invoker",               "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "java_tomcat_examples_left_in",         "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "php_phpinfo_exposed",                  "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "php_composer_installed_json",          "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "php_wp_user_enumeration",              "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "python_django_debug_page",             "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 12},
    {"name": "python_werkzeug_debugger",             "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "iis_short_filename_disclosure",        "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "iis_webdav_methods_enabled",           "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 12},
    {"name": "aem_querybuilder_full_dump",           "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 12},
    {"name": "aem_crx_de_lite",                      "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "aem_felix_console",                    "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 20},
    {"name": "aem_sling_dotjson_selectors",          "needs_post": False,
     "juice_expects": "refuted",   "max_requests": 30},
    {"name": "http_trace_method_enabled",            "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 12},
    {"name": "http_dangerous_methods_allowed",       "needs_post": True,
     "juice_expects": "refuted",   "max_requests": 20},
]


def _config_for(p: dict) -> dict:
    cfg: dict = {"max_requests": p.get("max_requests", 60),
                 "max_rps": 30.0}
    if p.get("needs_post"):
        cfg["allow_destructive"] = True
    return cfg


_VALIDATED_ON_JUICE = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "validated"]
_REFUTED_ON_JUICE   = [p["name"] for p in _PROBES
                       if p["juice_expects"] == "refuted"]


@pytest.mark.parametrize("name", _VALIDATED_ON_JUICE)
def test_probe_validates_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is True, (
        f"{name} should validate against Juice Shop. "
        f"summary={v.get('summary')!r}")
    assert (v.get("confidence") or 0) >= 0.85, (
        f"{name} validated at confidence {v.get('confidence')} -- "
        "round-10/11 probes must validate at >= 0.85.")


@pytest.mark.parametrize("name", _REFUTED_ON_JUICE)
def test_probe_quiet_on_juice_shop(juice_shop_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, juice_shop_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is not True, (
        f"{name} false-positived on Juice Shop. "
        f"summary={v.get('summary')!r}")


@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_quiet_on_clean_ref(clean_ref_url, name):
    p = next(p for p in _PROBES if p["name"] == name)
    v = run_probe(name, clean_ref_url, **_config_for(p))
    assert v["ok"] is True, f"probe {name} errored: {v.get('error')}"
    assert v["validated"] is not True, (
        f"{name} false-positived on the clean-ref site. "
        f"summary={v.get('summary')!r}")


@pytest.mark.parametrize("name", [p["name"] for p in _PROBES])
def test_probe_smoke_no_stack(name):
    """Probe must run cleanly against an unreachable target."""
    p = next(p for p in _PROBES if p["name"] == name)
    cfg = {"url": "http://127.0.0.1:1", "scope": [],
           **_config_for(p), "max_rps": 30.0}
    proc = subprocess.run(
        [sys.executable, str(PROBES_DIR / f"{name}.py"), "--stdin"],
        input=json.dumps(cfg).encode(),
        capture_output=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, (
        f"{name} did not exit 0 against unreachable target. "
        f"stderr={proc.stderr.decode('utf-8','replace')[:500]!r}")
    out = json.loads(proc.stdout)
    assert out["validated"] is not True, (
        f"{name} false-positived on unreachable target. "
        f"summary={out.get('summary')!r}")
