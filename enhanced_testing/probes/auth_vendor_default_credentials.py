#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Authentication: vendor-specific default credentials reachable on this
target.

Default-credential bugs for COTS software (WordPress, Tomcat Manager,
Jenkins, Grafana, JBoss, Cisco appliances, etc.) account for an
outsized share of large-scale breaches — the credentials are documented
in the vendor's own install guide, attackers grep them out of CIRT.net's
DB, and stale staging deployments forget to rotate them. Generic
"admin/admin" probes catch some; the rest hide behind vendor-specific
login URLs and authentication mechanisms (HTTP basic on /manager/html,
form-multipart on /wp-login.php, JSON on /api/auth, etc.).

Two-stage probe:
  1. **Fingerprint** — fetch a small set of marker URLs and inspect the
     responses for vendor signatures (page title, generator meta,
     Server/X-Powered-By headers, framework-specific files). Each match
     adds a vendor to the "try" list.
  2. **Targeted credential test** — for each fingerprinted vendor, run
     the vendor's documented default cred pairs against the vendor's
     own login URL using the right authentication method (basic, form,
     JSON). Stop on first success per vendor; never try a vendor whose
     fingerprint didn't match.

Why fingerprint first instead of "fire all 80 pairs at every host":
  - A blind 80-pair sweep is loud, often triggers WAF/IDS, and risks
    legitimate-account lockouts on shared endpoints.
  - The detection signal is the SAME pair that blew up [vendor] for
    other people in the news. We don't need volume — we need precision.
  - Fingerprint failure for a vendor means "this isn't [vendor]" —
    skip its cred set. Total request budget per scan stays bounded.

Safety:
  - Read-only by spirit (login attempts don't mutate app state) but
    requires `allow_destructive: True` to issue POSTs. The orchestrator
    grants this via _PROBES_NEEDING_POST.
  - Per-vendor cap of 5 cred pairs (vendor's most-documented defaults).
  - Aborts a vendor on 429 or Retry-After.
  - Total request budget: bounded by the safety framework.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402


# ---- vendor catalogue ------------------------------------------------------
#
# Each entry has:
#   fingerprint_paths:    URLs to GET while fingerprinting. The catch is
#                         that we DON'T require all of them to succeed —
#                         any single one matching counts.
#   fingerprint_markers:  list of (path_glob, regex_or_str). Match if
#                         glob applies AND substring/regex appears in
#                         the response body or status line.
#   login:                {url, method:'form-urlencoded'|'basic'|'json',
#                         user_field, pass_field, success_regex}
#   credentials:          (user, password) pairs to try, capped per
#                         documented-default lists. ORDERED most-likely first.
#
# `success_regex` is the verdict gate: a response on the login attempt
# whose body matches the regex (or whose status is 200/302 with the
# right Set-Cookie name) counts as a successful login. Each vendor
# defines what success looks like — it's almost never just "HTTP 200".

VENDORS: list[dict] = [

    # ---- Apache Tomcat Manager (HTTP Basic auth) --------------------------
    # The vendor that historically loses the most production servers to
    # default creds. Tomcat Manager exposes deployable WAR upload —
    # default-cred + Manager = arbitrary code execution.
    {
        "name": "tomcat_manager",
        "fingerprint_paths": ["/manager/html", "/manager/status",
                              "/host-manager/html"],
        "fingerprint_markers": [
            (".+", r"Tomcat (?:Web )?Application Manager"),
            (".+", r"WWW-Authenticate:.*Tomcat"),
        ],
        "login": {"url": "/manager/html",
                  "method": "basic",
                  "success_status": (200,),
                  "success_regex": r"Tomcat (?:Web )?Application Manager"},
        "credentials": [
            ("tomcat",  "tomcat"),
            ("admin",   "admin"),
            ("manager", "manager"),
            ("admin",   ""),
            ("tomcat",  "s3cret"),
        ],
        "severity_uplift": "critical",
    },

    # ---- WordPress wp-login --------------------------------------------------
    {
        "name": "wordpress",
        "fingerprint_paths": ["/wp-login.php", "/wp-admin/", "/"],
        "fingerprint_markers": [
            ("/wp-login.php",   r"<title>[^<]*Log In[^<]*WordPress"),
            ("/wp-admin/",      r"<title>[^<]*WordPress"),
            (".+",              r'<meta\s+name="generator"\s+content="WordPress'),
        ],
        "login": {"url": "/wp-login.php",
                  "method": "form-urlencoded",
                  "user_field": "log",
                  "pass_field": "pwd",
                  "extra_fields": {"wp-submit": "Log In",
                                   "redirect_to": "/wp-admin/",
                                   "testcookie": "1"},
                  # WP's success path: 302 to /wp-admin/ AND a
                  # wordpress_logged_in_* cookie set. We match either
                  # signal.
                  "success_status": (302,),
                  "success_set_cookie": r"wordpress_logged_in_"},
        "credentials": [
            ("admin",     "admin"),
            ("admin",     "password"),
            ("admin",     "admin123"),
            ("wordpress", "wordpress"),
            ("admin",     "wordpress"),
        ],
        "severity_uplift": "critical",
    },

    # ---- phpMyAdmin --------------------------------------------------------
    # Default-cred phpMyAdmin = full DB read/write. Reachable from web.
    {
        "name": "phpmyadmin",
        "fingerprint_paths": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/",
                              "/admin/phpmyadmin/"],
        "fingerprint_markers": [
            (".+", r"phpMyAdmin"),
            (".+", r"<title>[^<]*phpMyAdmin"),
        ],
        # phpMyAdmin's own login posts to itself with pma_username +
        # pma_password. Success = 302 with a phpMyAdmin Set-Cookie.
        "login": {"url": "/phpmyadmin/index.php",
                  "method": "form-urlencoded",
                  "user_field": "pma_username",
                  "pass_field": "pma_password",
                  "extra_fields": {"server": "1"},
                  "success_status": (200, 302),
                  "success_set_cookie": r"phpMyAdmin"},
        "credentials": [
            ("root",  ""),
            ("root",  "root"),
            ("root",  "password"),
            ("admin", "admin"),
            ("pma",   "pma"),
        ],
        "severity_uplift": "critical",
    },

    # ---- Grafana ----------------------------------------------------------
    # Universally-known: admin/admin is the OOB password, and it's
    # supposed to force-rotate on first login but operators routinely
    # skip the rotation step.
    {
        "name": "grafana",
        "fingerprint_paths": ["/login", "/"],
        "fingerprint_markers": [
            (".+", r"<title>Grafana</title>"),
            (".+", r"grafana_session"),
            (".+", r"<meta\s+name=.application-name.\s+content=.Grafana."),
        ],
        # /login POST with JSON body { user, password }. Success: 200
        # with `{"message":"Logged in"}` or a Set-Cookie of grafana_session.
        "login": {"url": "/login",
                  "method": "json",
                  "user_field": "user",
                  "pass_field": "password",
                  "success_status": (200,),
                  "success_regex": r'"message"\s*:\s*"Logged in"'},
        "credentials": [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "grafana"),
        ],
        "severity_uplift": "critical",
    },

    # ---- Jenkins ----------------------------------------------------------
    # Jenkins doesn't ship with a default password (setup wizard
    # forces a custom one), but a depressing number of staging/dev
    # boxes finish setup with admin/admin or admin/changeme. Login
    # uses a CSRF-protected form with j_username/j_password.
    {
        "name": "jenkins",
        "fingerprint_paths": ["/login", "/", "/api/json"],
        "fingerprint_markers": [
            (".+", r"<title>[^<]*Jenkins[^<]*</title>"),
            (".+", r"X-Jenkins"),
        ],
        "login": {"url": "/j_acegi_security_check",
                  "method": "form-urlencoded",
                  "user_field": "j_username",
                  "pass_field": "j_password",
                  "extra_fields": {"from": "/", "remember_me": "false"},
                  "success_status": (302,),
                  "success_set_cookie": r"JSESSIONID"},
        "credentials": [
            ("admin",   "admin"),
            ("admin",   "password"),
            ("admin",   "changeme"),
            ("admin",   "jenkins"),
            ("jenkins", "jenkins"),
        ],
        "severity_uplift": "critical",
    },

    # ---- JBoss / WildFly admin console -------------------------------------
    {
        "name": "jboss_wildfly",
        "fingerprint_paths": ["/console", "/admin-console",
                              "/management", "/jmx-console/"],
        "fingerprint_markers": [
            (".+", r"WildFly"),
            (".+", r"JBoss"),
            (".+", r"<title>[^<]*Administration Console[^<]*</title>"),
        ],
        "login": {"url": "/management",
                  "method": "basic",
                  "success_status": (200,),
                  "success_regex": r'"name"\s*:\s*"core-service"'},
        "credentials": [
            ("admin",   "admin"),
            ("admin",   "jboss"),
            ("admin",   "wildfly"),
            ("jboss",   "jboss"),
            ("admin",   "Admin#70365"),    # WildFly silver-default
        ],
        "severity_uplift": "critical",
    },

    # ---- Adminer (PHP DB admin tool) --------------------------------------
    {
        "name": "adminer",
        "fingerprint_paths": ["/adminer.php", "/adminer/", "/admin/adminer.php"],
        "fingerprint_markers": [
            (".+", r"Adminer\s+(?:- )?\d"),
            (".+", r"<title>Login - Adminer</title>"),
        ],
        "login": {"url": "/adminer.php",
                  "method": "form-urlencoded",
                  "user_field": "auth[username]",
                  "pass_field": "auth[password]",
                  "extra_fields": {"auth[driver]": "server",
                                   "auth[server]": "localhost",
                                   "auth[db]": ""},
                  "success_status": (200, 302),
                  "success_regex": r"<title>(?!Login)"},
        "credentials": [
            ("root",  ""),
            ("root",  "root"),
            ("root",  "password"),
            ("admin", "admin"),
        ],
        "severity_uplift": "critical",
    },

    # ---- Kibana ------------------------------------------------------------
    {
        "name": "kibana",
        "fingerprint_paths": ["/login", "/app/home", "/api/status"],
        "fingerprint_markers": [
            (".+", r"<title>Kibana</title>"),
            (".+", r"\"name\"\s*:\s*\"kibana\""),
            (".+", r"kbn-name"),
        ],
        "login": {"url": "/internal/security/login",
                  "method": "json",
                  # Kibana's body is more complex; we send the simplest
                  # form that works for the basic auth provider.
                  "request_body_template": (
                      '{{"providerType":"basic",'
                      '"providerName":"basic",'
                      '"currentURL":"/login",'
                      '"params":{{"username":"{user}","password":"{password}"}}}}'
                  ),
                  "success_status": (200,),
                  "success_set_cookie": r"sid"},
        "credentials": [
            ("elastic", "changeme"),
            ("elastic", "elastic"),
            ("kibana",  "changeme"),
            ("admin",   "admin"),
        ],
        "severity_uplift": "critical",
    },
]


# ---- helpers ---------------------------------------------------------------

def _hdr_ci(headers: dict, name: str) -> str:
    nl = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == nl:
            return v
    return ""


def _matches_marker(path: str, marker_path: str, body_text: str,
                    headers: dict, regex_or_str: str) -> bool:
    """A marker matches if the response *path* is consistent with
    `marker_path` (a regex) AND the body or one of the headers matches
    `regex_or_str`. Headers are searched as a flat blob so things like
    `WWW-Authenticate:...Tomcat` match cleanly."""
    if not re.search(marker_path, path):
        return False
    headers_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    haystack = headers_blob + "\n" + body_text[:60000]
    try:
        return bool(re.search(regex_or_str, haystack, re.IGNORECASE))
    except re.error:
        return regex_or_str.lower() in haystack.lower()


def _fingerprint_vendors(client: SafeClient, origin: str
                         ) -> tuple[list[dict], list[dict]]:
    """Walk the catalogue and return ([matched vendor entries], [audit rows]).
    Each marker GET counts against the request budget; matched vendors
    are de-duped by name."""
    audit: list[dict] = []
    matched_names: set[str] = set()
    matched: list[dict] = []
    # Cache by path so multiple vendors that share a path don't re-fetch
    # it. fingerprint_paths overlap between vendors (e.g. "/" / "/login").
    fetched: dict[str, tuple[int, dict, str]] = {}
    for vendor in VENDORS:
        for fp in vendor["fingerprint_paths"]:
            url = urljoin(origin, fp)
            if fp not in fetched:
                r = client.request("GET", url)
                fetched[fp] = (r.status, dict(r.headers), r.text)
                audit.append({"path": fp, "status": r.status,
                              "size": r.size})
            status, headers, text = fetched[fp]
            if status == 0:
                continue
            for marker_path, marker_regex in vendor["fingerprint_markers"]:
                if _matches_marker(fp, marker_path, text, headers,
                                   marker_regex):
                    if vendor["name"] not in matched_names:
                        matched_names.add(vendor["name"])
                        matched.append(vendor)
                    break
            if vendor["name"] in matched_names:
                break
    return matched, audit


def _try_login(client: SafeClient, origin: str, vendor: dict,
               user: str, pw: str) -> dict:
    """Issue one login attempt for a vendor. Returns a dict suitable
    for the audit log; sets `success: True` on a verified positive."""
    login = vendor["login"]
    url = urljoin(origin, login["url"])
    method = login["method"]
    headers: dict = {}
    body: bytes | None = None

    if method == "basic":
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
        http_method = "GET"
    elif method == "form-urlencoded":
        params = dict(login.get("extra_fields") or {})
        params[login["user_field"]] = user
        params[login["pass_field"]] = pw
        body = urlencode(params).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        http_method = "POST"
    elif method == "json":
        if "request_body_template" in login:
            body = login["request_body_template"].format(
                user=user, password=pw).encode()
        else:
            body = json.dumps({
                login["user_field"]: user,
                login["pass_field"]: pw,
            }).encode()
        headers["Content-Type"] = "application/json"
        # Kibana, Grafana, etc. require this header to allow the POST
        headers["kbn-xsrf"] = "true"
        headers["X-Requested-With"] = "XMLHttpRequest"
        http_method = "POST"
    else:
        return {"vendor": vendor["name"], "user": user,
                "error": f"unknown method {method!r}"}

    r = client.request(http_method, url, headers=headers, body=body)
    row: dict = {"vendor": vendor["name"], "user": user,
                 "status": r.status, "size": r.size, "method": method}

    # Success heuristics — checked in order of strongest-evidence first.
    set_cookie_blob = (_hdr_ci(r.headers, "set-cookie")
                       + "\n" + _hdr_ci(r.headers, "Set-Cookie"))
    success = False
    why = ""
    if "success_set_cookie" in login and re.search(
            login["success_set_cookie"], set_cookie_blob, re.IGNORECASE):
        success = True
        why = f"Set-Cookie matched {login['success_set_cookie']!r}"
    elif "success_regex" in login and r.body and \
            r.status in login.get("success_status", (200, 302)) and \
            re.search(login["success_regex"], r.text, re.IGNORECASE):
        success = True
        why = f"body matched {login['success_regex']!r}"
    elif login.get("method") == "basic" and \
            r.status in login.get("success_status", (200,)):
        # Basic-auth path: 200 = creds accepted (401 = rejected). Pair
        # this with a body-content sanity check via success_regex above
        # — if that didn't fire but status is 200, we still call it a
        # weak hit. Most basic-auth-protected admin consoles return a
        # 401 challenge until the right pair lands.
        # For the catalog above, every basic-auth vendor also has a
        # success_regex, so this branch only fires when the regex is
        # missing (defensive default).
        success = True
        why = f"HTTP {r.status} after basic auth"

    if success:
        row.update({"success": True, "why": why})
    return row


# ---- the probe -------------------------------------------------------------

class VendorDefaultCredentialsProbe(Probe):
    name = "auth_vendor_default_credentials"
    summary = ("Detects vendor-specific default credentials (Tomcat, "
               "WordPress, phpMyAdmin, Jenkins, Grafana, JBoss, Adminer, "
               "Kibana) reachable on this target.")
    safety_class = "read-only"

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        matched, fp_audit = _fingerprint_vendors(client, origin)
        if not matched:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: fingerprinted {len(fp_audit)} paths "
                         f"on {origin}; no known vendor stack matched, "
                         "so no vendor-specific default-credential "
                         "tests were attempted."),
                evidence={"origin": origin,
                          "fingerprint_audit": fp_audit,
                          "vendors_matched": []},
            )

        # For each matched vendor, try its credential set.
        confirmed: list[dict] = []
        attempts: list[dict] = []
        for vendor in matched:
            aborted = False
            for user, pw in vendor["credentials"]:
                if aborted:
                    break
                row = _try_login(client, origin, vendor, user, pw)
                attempts.append(row)
                # Lockout-awareness: 429 / Retry-After means stop hitting
                # this vendor's login URL.
                if row.get("status") == 429:
                    aborted = True
                    row["aborted_reason"] = "rate-limited (429)"
                    break
                if row.get("success"):
                    confirmed.append(row)
                    break    # don't keep firing once we have a hit

        evidence = {
            "origin": origin,
            "fingerprint_audit": fp_audit,
            "vendors_matched": [v["name"] for v in matched],
            "attempts": attempts,
        }

        if confirmed:
            top = confirmed[0]
            vendor_name = top["vendor"]
            vendor_entry = next(v for v in matched if v["name"] == vendor_name)
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: vendor default credentials accepted "
                         f"on {origin} — {vendor_name} login succeeded for "
                         f"user {top['user']!r} ({top['why']})."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift=vendor_entry.get("severity_uplift", "critical"),
                remediation=(
                    "Rotate the password for this account immediately. "
                    "If the account is the documented vendor default "
                    "(e.g. tomcat/tomcat, admin/admin), rotate AND "
                    "consider whether the management interface should "
                    "be exposed at all — most production deployments "
                    "should bind the admin interface to localhost only "
                    "and reach it via SSH tunnel.\n"
                    "Add a deploy-time check that fails the build / "
                    "rollout if any user record matches the vendor's "
                    "documented default password hash."),
            )

        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: fingerprinted "
                     f"{len(matched)} vendor stack(s) on {origin} — "
                     + ", ".join(v["name"] for v in matched) +
                     f" — and tried {len(attempts)} default-credential "
                     "pairs across them; none authenticated."),
            evidence=evidence,
        )


if __name__ == "__main__":
    VendorDefaultCredentialsProbe().main()
