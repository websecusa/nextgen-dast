# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""SAML 2.0 SP wrapper around python3-saml (OneLogin's toolkit).

Why python3-saml: it does spec-correct signature verification via libxmlsec1
and handles the messy edge cases (response signing vs assertion signing,
relay-state preservation, NotOnOrAfter / NotBefore checks). Rolling our
own would be a footgun.

Public surface (callers in app/server.py):

  load_config()              → dict from the saml_config row
  save_config(fields)        → upsert the row
  is_enabled()               → quick "should /saml routes work?" check
  is_force_active()          → True iff enabled=1, force_saml=1, AND the
                                 bypass file is NOT present
  bypass_active()            → True iff /data/.saml_bypass exists
  build_settings(host_url)   → python3-saml settings dict, derived from
                                 the saml_config row + caller's request
                                 host (so SP entity / ACS / SLS URLs
                                 always reflect the deployment)
  prepare_request_dict(req)  → adapt FastAPI Request to OneLogin's
                                 expected dict shape
  sso_redirect_url(req)      → URL to send the browser to for IdP login
  process_acs(req)           → returns (username, error). On success the
                                 caller looks up / JIT-creates the user
                                 row and issues a session.
  slo_redirect_url(req,user) → URL to send the browser to for IdP logout
  process_sls(req)           → returns (success, error). Caller clears
                                 the session cookie either way.
  build_metadata_xml(host_url) → SP metadata document Okta can ingest

The bypass file (/data/.saml_bypass) is the operator's escape hatch when
SSO breaks: a single `touch /data/.saml_bypass` (or any equivalent — the
file's contents are not inspected) re-enables /login regardless of the
force_saml DB flag. This lives in /data so it survives across container
recreates while still being trivially toggleable from the host.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Optional, Tuple

import db


# Single file flag. Existence (not contents) is what matters. The path
# is inside the /data volume so the operator can `touch` it from the
# host without entering the container, and so it survives container
# recreate (which is the most common scenario in which an operator is
# debugging a broken SSO config).
BYPASS_FILE = "/data/.saml_bypass"


# Endpoint paths the SP exposes. Hardcoded so the SP entity ID / ACS /
# SLS URLs are deterministic from a host name; admins copy these into
# Okta's app config rather than discovering them. /saml/metadata returns
# an XML document Okta can also ingest from a URL to populate the same
# values automatically.
PATH_ACS = "/saml/acs"
PATH_SLS = "/saml/sls"
PATH_METADATA = "/saml/metadata"
PATH_SSO = "/saml/login"


# --------------------------------------------------------------------- #
# Persistence: single-row table, mirrors branding's pattern.
# --------------------------------------------------------------------- #

def load_config() -> dict:
    """Return the single saml_config row. The row is seeded by schema.sql
    (INSERT IGNORE id=1) but we self-heal a missing row defensively so a
    DB that somehow lost the seed still serves /admin/sso instead of 500."""
    row = db.query_one("SELECT * FROM saml_config WHERE id = 1")
    if not row:
        db.execute("INSERT IGNORE INTO saml_config (id) VALUES (1)")
        row = db.query_one("SELECT * FROM saml_config WHERE id = 1")
    return row or {}


def save_config(fields: dict) -> None:
    """Upsert recognised fields onto the single saml_config row.

    Booleans (`enabled`, `force_saml`) are coerced to 0/1. The IdP cert
    is stored verbatim — python3-saml accepts the PEM body with or
    without the BEGIN/END lines, so we don't normalise. Empty strings
    become NULL so the form's "clear this field" gesture works."""
    allowed_text = {
        "idp_label",
        "idp_entity_id", "idp_sso_url", "idp_slo_url", "idp_x509_cert",
        "sp_entity_id", "sp_acs_url", "sp_slo_url",
    }
    bool_cols = {"enabled", "force_saml"}
    sets, params = [], []
    for k, v in fields.items():
        if k in bool_cols:
            s = str(v if v is not None else "").strip().lower()
            sets.append(f"{k} = %s")
            params.append(1 if s in ("1", "true", "yes", "on") else 0)
            continue
        if k not in allowed_text:
            continue
        if k == "idp_label":
            v = (v or "generic").strip().lower()
            if v not in ("generic", "okta"):
                v = "generic"
            sets.append("idp_label = %s")
            params.append(v)
            continue
        sets.append(f"{k} = %s")
        params.append((v or "").strip() or None)
    if not sets:
        return
    params.append(1)
    db.execute(f"UPDATE saml_config SET {', '.join(sets)} WHERE id = %s", params)


# --------------------------------------------------------------------- #
# Bypass file + force-SAML gate.
# --------------------------------------------------------------------- #

def bypass_active() -> bool:
    """True iff the bypass file exists. Cheap stat() call; no caching so
    a freshly-touched file takes effect on the next request without a
    container restart."""
    try:
        return os.path.exists(BYPASS_FILE)
    except OSError:
        return False


def is_enabled() -> bool:
    """True iff a config row says SAML is enabled. Used by templates to
    decide whether to render the 'Sign in with SSO' button on /login and
    by the /saml/* routes to refuse traffic when SSO isn't configured."""
    cfg = load_config()
    return bool(int(cfg.get("enabled") or 0))


def is_force_active() -> bool:
    """True iff force_saml is on AND the bypass file is absent. Used by
    /login to decide whether to refuse local login and redirect users
    into the SSO flow. The bypass file overrides this so an operator
    locked out of a broken Okta config can still sign in by editing
    nothing more than /data/.saml_bypass on the host."""
    cfg = load_config()
    if not int(cfg.get("enabled") or 0):
        return False
    if not int(cfg.get("force_saml") or 0):
        return False
    return not bypass_active()


# --------------------------------------------------------------------- #
# python3-saml integration. Lazy import so app boot doesn't depend on
# the library when SSO isn't configured (some deployments may build the
# image without libxmlsec1 — rare, but we shouldn't crash on import).
# --------------------------------------------------------------------- #

def _import_onelogin():
    """Import python3-saml lazily and surface a helpful error if the
    library or its native dependencies are missing."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        return OneLogin_Saml2_Auth, OneLogin_Saml2_Settings
    except ImportError as e:
        raise RuntimeError(
            "python3-saml is not installed (or libxmlsec1 is missing). "
            f"Original error: {e!r}"
        )


def _host_url(request) -> str:
    """Reconstruct the public base URL for SP-side metadata + ACS / SLS
    endpoints. Honors X-Forwarded-Proto / X-Forwarded-Host when the
    nginx proxy sets them so the SP URLs match what Okta sees, not the
    upstream uvicorn 0.0.0.0:8888."""
    headers = getattr(request, "headers", {}) or {}
    proto = headers.get("x-forwarded-proto") or request.url.scheme or "https"
    host = headers.get("x-forwarded-host") or headers.get("host") or ""
    if not host:
        host = request.url.netloc
    return f"{proto}://{host}"


def build_settings(request) -> dict:
    """Compose the python3-saml settings dict from the saml_config row
    plus the request's host. SP URLs are derived (not stored) so a
    deployment that moves between hostnames stays correct without
    manual reconfiguration."""
    cfg = load_config()
    base = _host_url(request)
    # Stored SP fields override the derived ones, so an operator can
    # pin specific values when the install sits behind an unusual
    # proxy that mangles Host. Leave the form fields blank to use
    # the auto-derived defaults.
    sp_entity = cfg.get("sp_entity_id") or f"{base}{PATH_METADATA}"
    sp_acs = cfg.get("sp_acs_url") or f"{base}{PATH_ACS}"
    sp_sls = cfg.get("sp_slo_url") or f"{base}{PATH_SLS}"
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity,
            "assertionConsumerService": {
                "url": sp_acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sp_sls,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat":
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": cfg.get("idp_entity_id") or "",
            "singleSignOnService": {
                "url": cfg.get("idp_sso_url") or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": cfg.get("idp_slo_url") or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.get("idp_x509_cert") or "",
        },
        "security": {
            # Require the IdP to sign assertions; we don't yet support
            # encrypted assertions (deliberately deferred — see CHANGELOG).
            "wantAssertionsSigned": True,
            # We don't sign AuthnRequests by default. Adding SP signing
            # would require generating + storing an SP key pair, which
            # is the same key-management surface we're deferring with
            # encrypted assertions. Okta accepts unsigned requests.
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
        },
    }


def prepare_request_dict(request, post_form: Optional[dict] = None) -> dict:
    """Adapt a FastAPI Request to the dict shape OneLogin expects.

    The library was written before ASGI; it wants a Flask-/Django-shaped
    dict. The fields it actually consults are documented in OneLogin's
    sample code. `post_data` must be the parsed form body for the ACS /
    SLS POST; `get_data` carries the redirect-binding query string for
    SLS responses."""
    base = _host_url(request)
    parsed = urllib.parse.urlparse(base)
    return {
        "https": "on" if parsed.scheme == "https" else "off",
        "http_host": parsed.netloc,
        "server_port": "443" if parsed.scheme == "https" else "80",
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_form or {},
    }


def sso_redirect_url(request, return_to: str = "/") -> str:
    """Compute the IdP login URL for SP-initiated SSO. The caller is
    expected to issue an HTTP 302 to this URL. `return_to` rides along
    as RelayState so the IdP echoes it back on the ACS POST."""
    OneLogin_Saml2_Auth, _ = _import_onelogin()
    auth = OneLogin_Saml2_Auth(prepare_request_dict(request),
                               build_settings(request))
    return auth.login(return_to=return_to)


def process_acs(request, post_form: dict) -> Tuple[Optional[str],
                                                   Optional[str], str]:
    """Validate the SAML response POSTed to /saml/acs.

    Returns (username, relay_state, error). On success `username` is the
    authenticated NameID (typically an email) and `error` is empty. On
    failure `username` is None and `error` carries a short diagnostic
    string suitable for the login page banner."""
    OneLogin_Saml2_Auth, _ = _import_onelogin()
    auth = OneLogin_Saml2_Auth(prepare_request_dict(request, post_form),
                               build_settings(request))
    try:
        auth.process_response()
    except Exception as e:
        return None, "", f"SAML response parse error: {type(e).__name__}"
    errors = auth.get_errors()
    if errors:
        # auth.get_last_error_reason() carries the human-readable
        # explanation when the toolkit recognised the failure mode.
        reason = auth.get_last_error_reason() or ""
        return None, "", f"SAML validation failed: {','.join(errors)}: {reason}"
    if not auth.is_authenticated():
        return None, "", "SAML response did not authenticate the user"
    name_id = auth.get_nameid() or ""
    relay = post_form.get("RelayState") or "/"
    return (name_id.strip() or None), relay, ""


def slo_redirect_url(request, name_id: Optional[str],
                     session_index: Optional[str] = None) -> Optional[str]:
    """Compute the IdP logout URL for SP-initiated SLO. Returns None when
    the IdP has no SLO endpoint configured (operator left the field
    blank); callers fall back to a local-only logout in that case."""
    cfg = load_config()
    if not (cfg.get("idp_slo_url") or "").strip():
        return None
    OneLogin_Saml2_Auth, _ = _import_onelogin()
    auth = OneLogin_Saml2_Auth(prepare_request_dict(request),
                               build_settings(request))
    return auth.logout(name_id=name_id, session_index=session_index)


def process_sls(request, post_form: Optional[dict] = None
                ) -> Tuple[bool, str]:
    """Validate an IdP-initiated SLO request landing on /saml/sls.
    Returns (success, error)."""
    OneLogin_Saml2_Auth, _ = _import_onelogin()
    auth = OneLogin_Saml2_Auth(prepare_request_dict(request, post_form or {}),
                               build_settings(request))
    try:
        # delete_session_cb is a no-op here; the route layer handles the
        # actual session cookie clear via response.delete_cookie.
        auth.process_slo(delete_session_cb=lambda: None)
    except Exception as e:
        return False, f"SAML SLO parse error: {type(e).__name__}"
    errors = auth.get_errors()
    if errors:
        return False, f"SAML SLO validation failed: {','.join(errors)}"
    return True, ""


def build_metadata_xml(request) -> Tuple[str, str]:
    """Return (xml, error) for the SP metadata document. Okta's app
    wizard accepts either a metadata URL or a pasted XML blob; we serve
    the doc at /saml/metadata so the URL form works without extra
    operator effort."""
    _, OneLogin_Saml2_Settings = _import_onelogin()
    settings = OneLogin_Saml2_Settings(build_settings(request),
                                       sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        return "", "; ".join(errors)
    return (metadata.decode("utf-8") if isinstance(metadata, bytes)
            else metadata), ""
