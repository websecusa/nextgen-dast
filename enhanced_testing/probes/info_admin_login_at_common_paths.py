#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: admin / management login surface reachable
at a well-known path.

Many apps ship an admin / management UI on a public path (`/admin`,
`/manage`, `/wp-admin/`, `/console`, `/dashboard/admin`,
`/control-panel`) that's "secured" only by the login form on it.
That's not security -- it's an attack surface. Any credential
weakness, brute-force gap, default-creds setting, or session-
related flaw on that login form is fully reachable from the public
internet.

Different from `authz_admin_section_force_browse` (which looks for
a *user list* leaking through the admin route). This one looks for
a *login form* itself appearing on a known admin path -- the
pre-condition for the attacks rather than the data leak.

High-fidelity signal: GET candidate paths; validate when the body
contains an HTML `<form>` element with both an `<input type="password">`
AND an `<input>` whose name suggests username/email.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

ADMIN_PATHS = (
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/wp-admin/", "/wp-login.php",
    "/console", "/manage", "/manager/html",
    "/dashboard", "/dashboard/login",
    "/management", "/cms",
    "/backoffice", "/backend",
    "/sysadmin", "/system",
    "/control-panel", "/cpanel",
    "/admin.php", "/login.php",
    "/portal/admin",
)

_FORM_RE     = re.compile(r"<form\b[^>]*>", re.I)
_PWD_INPUT   = re.compile(r'<input[^>]+type\s*=\s*"password"',
                            re.I)
_USER_INPUT  = re.compile(
    r'<input[^>]+name\s*=\s*"(?:username|user|email|login|userid|'
    r'uid|account|j_username)"', re.I)


class InfoAdminLoginAtCommonPathsProbe(Probe):
    name = "info_admin_login_at_common_paths"
    summary = ("Detects admin / management login forms reachable at "
               "well-known paths -- attack-surface exposure that "
               "downgrades the auth design to whatever the form "
               "provides.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional admin path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(ADMIN_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            r = client.request("GET", urljoin(origin, p),
                                follow_redirects=True)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size,
                         "final_url": r.final_url}
            if r.status == 200 and r.body:
                text = r.text or ""
                if (_FORM_RE.search(text)
                        and _PWD_INPUT.search(text)
                        and _USER_INPUT.search(text)):
                    row["login_form_present"] = True
                    confirmed.append(row)
                    attempts.append(row)
                    if len(confirmed) >= 3:
                        break
                    continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.85,
                summary=(
                    f"Confirmed: admin login form reachable at "
                    f"{origin}{top['path']} (final URL "
                    f"{top['final_url']}). "
                    f"{len(confirmed)} admin path(s) returned a "
                    "login form on the public origin -- the auth "
                    "design now sits behind whatever this form "
                    "implements (creds strength, lockout, MFA, "
                    "session flags)."),
                evidence={**evidence, "confirmed": confirmed},
                # Surface-inventory only: the probe confirms an admin
                # login form is reachable on the public origin, which
                # is informational. The actual defects (default creds,
                # missing lockout, weak session flags, MFA gaps) are
                # scored independently by the paired auth_* probes.
                severity_uplift="info",
                remediation=(
                    "Move admin / management UIs off the public "
                    "internet -- VPN-only ingress, SSO with hardware "
                    "MFA, or at minimum IP-restricted at the edge.\n"
                    "If the UI must remain public, harden the login: "
                    "rate-limit, account-lockout, MFA, audit-log "
                    "every successful authentication, and rotate any "
                    "default credentials.\n"
                    "Pair with the existing "
                    "`auth_default_admin_credentials`, "
                    "`auth_no_brute_force_lockout`, and "
                    "`auth_username_enum_timing` probes -- they "
                    "validate exactly the failure modes this surface "
                    "exposes."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} admin / "
                     f"management paths on {origin}; none returned "
                     "an HTML login form on the public origin."),
            evidence=evidence,
        )


if __name__ == "__main__":
    InfoAdminLoginAtCommonPathsProbe().main()
