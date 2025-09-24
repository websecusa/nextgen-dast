# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Hand-written remediation catalog for the most common findings the scanners
in this project emit. Keys are matched by `enrichment.match_static()` against
a normalized finding signature; the value supplies the long-form fields the
LLM would otherwise have to generate.

A catalog hit is free (no token cost), deterministic, and reviewer-blessed.
A miss falls through to LLM enrichment, which is then cached forever in
`finding_enrichment` so you also pay at most once per finding type.

Match rules (in order):
  1. exact (source_tool, title_norm)
  2. (source_tool, owasp_category)
  3. (None, owasp_category)             — generic fallback per OWASP class
"""
from __future__ import annotations

# ---- helpers ---------------------------------------------------------------

def _steps(*items: str) -> list[str]:
    return list(items)


# Each entry must supply enough material to be ticket-ready: a real
# description, real impact, concrete numbered steps, code/config example,
# references, a user story, and a Jira-ready markdown body.

# ---- per-tool, per-title overrides -----------------------------------------

BY_TITLE = {
    # nuclei: HTTP missing-security-headers family
    ("nuclei", "http-missing-security-headers"): {
        "owasp_category": "A05:2021-Security_Misconfiguration",
        "cwe": "693",
        "suggested_priority": "p3",
        "description_long": (
            "The web server is responding without one or more security headers "
            "that browsers use as belt-and-braces defenses against XSS, "
            "clickjacking, MIME sniffing, mixed-content downgrades, and "
            "third-party data leakage. Each missing header on its own is a "
            "low-severity hardening gap, but the absence of several at once "
            "indicates the platform was deployed without a web-security "
            "baseline and any future application vulnerability will land "
            "with no browser-side mitigation."
        ),
        "impact": (
            "Successful XSS, clickjacking, or content-injection attacks "
            "that would otherwise be partially blocked by the browser will "
            "execute fully. Sensitive URLs may leak via Referer to third "
            "parties. HTTPS sessions can be downgraded over insecure links."
        ),
        "remediation_long": (
            "Set the missing headers at the edge (reverse proxy / CDN) so "
            "they apply uniformly to every response, rather than depending "
            "on each application stack to set them. Match the values to the "
            "policy actually in place — overly strict CSPs that get rolled "
            "back are worse than a thoughtful one."
        ),
        "remediation_steps": _steps(
            "Decide on a baseline policy: HSTS (12 months + preload), CSP "
            "(start with `default-src 'self'`), X-Content-Type-Options "
            "nosniff, X-Frame-Options DENY (or CSP frame-ancestors), "
            "Referrer-Policy strict-origin-when-cross-origin, "
            "Permissions-Policy locking down unused features.",
            "Add the headers in nginx / Apache / CDN config so every vhost "
            "inherits them — do not leave it to per-app middleware.",
            "Roll out CSP in `Content-Security-Policy-Report-Only` first, "
            "collect violation reports for at least one full traffic cycle, "
            "then switch to enforcing.",
            "Verify with `curl -I` and an external scanner "
            "(securityheaders.com, Mozilla Observatory).",
            "Add a regression test that fails the build if any of the "
            "headers disappears.",
        ),
        "code_example": (
            "# nginx\n"
            "add_header Strict-Transport-Security \"max-age=31536000; "
            "includeSubDomains; preload\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header X-Frame-Options \"DENY\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "add_header Permissions-Policy "
            "\"geolocation=(), microphone=(), camera=()\" always;\n"
            "add_header Content-Security-Policy "
            "\"default-src 'self'; object-src 'none'; frame-ancestors 'none'\" always;"
        ),
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://content-security-policy.com/",
        ],
        "user_story": (
            "As a security engineer, I want every HTTP response from our "
            "application edge to carry the OWASP secure-headers baseline "
            "so that browser-side defenses mitigate the impact of any "
            "future XSS, clickjacking, or content-injection bug."
        ),
    },

    # nuclei: weak access control / missing-auth patterns
    ("nuclei", "bypassable weak restriction"): {
        "owasp_category": "A01:2021-Broken_Access_Control",
        "cwe": "284",
        "suggested_priority": "p1",
        "description_long": (
            "An access restriction on this endpoint can be bypassed by "
            "trivial means — most commonly a header tweak (X-Original-URL, "
            "X-Rewrite-URL, X-Forwarded-For), a path-normalization trick "
            "(`%2e%2e/`, trailing dot/slash, mixed case), or by hitting an "
            "alternative method (HEAD, OPTIONS) that the deny rule didn't "
            "cover. The control is in place but not load-bearing."
        ),
        "impact": (
            "An unauthenticated or low-privilege attacker reaches "
            "functionality intended only for authenticated/admin users. "
            "Depending on the endpoint this can mean data exfiltration, "
            "privilege escalation, or full account takeover. This is the "
            "#1 risk in the OWASP Top 10."
        ),
        "remediation_long": (
            "Move the access decision out of the front-end / proxy / "
            "WAF layer (which is what the bypass is exploiting) and into "
            "the application — where every code path that handles the "
            "resource passes through one allow/deny check. Front-end rules "
            "are defense in depth, not the access control itself."
        ),
        "remediation_steps": _steps(
            "Identify the resource being protected and enumerate every "
            "code path that can reach it. Add a centralized authorization "
            "check at the controller or middleware layer.",
            "Deny by default. Treat any request that doesn't carry a valid "
            "session/role as unauthenticated regardless of its headers, "
            "method, or path encoding.",
            "Reject ambiguous request forms at the edge: drop "
            "X-Original-URL / X-Rewrite-URL / X-Forwarded-For unless they "
            "come from a trusted proxy, normalize paths before routing, "
            "and ensure the deny rule covers every HTTP method the app "
            "responds to (not just GET/POST).",
            "Add a regression test that calls the bypass payload exactly "
            "as the scanner did and asserts a 401/403.",
            "Audit similar endpoints for the same pattern — the original "
            "bypass is rarely the only one.",
        ),
        "code_example": (
            "# Express middleware example — server-side, not WAF\n"
            "function requireAdmin(req, res, next) {\n"
            "  if (!req.session?.user || req.session.user.role !== 'admin')\n"
            "    return res.status(403).json({error: 'forbidden'});\n"
            "  next();\n"
            "}\n"
            "app.all('/admin/*', requireAdmin);  // .all = every method"
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://portswigger.net/web-security/access-control",
        ],
        "user_story": (
            "As an application owner, I want every restricted endpoint to "
            "enforce its access decision in application code (not in a "
            "front-end rewrite or WAF rule) so that header tricks, path "
            "normalization, or alternative HTTP methods cannot bypass the "
            "control."
        ),
    },

    # nuclei: directory listing
    ("nuclei", "directory listing"): {
        "owasp_category": "A05:2021-Security_Misconfiguration",
        "cwe": "548",
        "suggested_priority": "p2",
        "description_long": (
            "The web server is returning the contents of one or more "
            "directories to anyone who requests them, exposing filenames "
            "that the application doesn't normally link to. Backups, "
            "configuration files, half-deployed branches, and internal "
            "tooling routinely surface this way."
        ),
        "impact": (
            "Sensitive files (.env, .git, backup tarballs, source maps) "
            "become trivially discoverable. Directory listings are also a "
            "reconnaissance signal that the deployment is sloppy, which "
            "tends to correlate with other issues."
        ),
        "remediation_long": (
            "Disable autoindex on every vhost — it should never be on for "
            "an internet-facing application. Then audit what was being "
            "exposed and remove anything that isn't meant to be public."
        ),
        "remediation_steps": _steps(
            "In nginx, set `autoindex off;` (the default) and remove any "
            "explicit `autoindex on;` lines. In Apache, remove `Options "
            "+Indexes` or add `Options -Indexes`.",
            "Walk the listing the scanner found and remove sensitive "
            "files: .git/, .env, *.bak, *.swp, npm/composer/pip caches.",
            "Add a deploy-time check that fails CI if any of those "
            "patterns end up in the document root.",
        ),
        "code_example": (
            "# nginx\n"
            "location / {\n"
            "    autoindex off;\n"
            "    try_files $uri $uri/ =404;\n"
            "}"
        ),
        "references": [
            "https://owasp.org/www-community/Improper_Error_Handling",
            "https://cwe.mitre.org/data/definitions/548.html",
        ],
        "user_story": (
            "As a security engineer, I want directory listings disabled on "
            "every public vhost so that filenames the application doesn't "
            "explicitly serve are not enumerable."
        ),
    },

    # nuclei: CVEs are deferred to LLM by default; we only catalog generics
}

# ---- per-OWASP-category fallback (any tool) --------------------------------

BY_OWASP = {
    "A01:2021-Broken_Access_Control": {
        "suggested_priority": "p1",
        "description_long": (
            "An access-control gap was identified — a user without the "
            "expected role, session, or ownership relationship to the "
            "resource was able to interact with it. Broken access control "
            "is the most prevalent risk in the OWASP Top 10 because each "
            "deployment has thousands of access decisions and only one of "
            "them needs to be wrong."
        ),
        "impact": (
            "Unauthorized data access, privilege escalation, or "
            "destructive actions taken by users who should not have been "
            "able to reach the resource at all."
        ),
        "remediation_long": (
            "Deny by default. Centralize authorization in the application "
            "layer rather than relying on UI hides, client-side checks, "
            "or proxy/WAF rules. Every request that touches a resource "
            "must pass through one well-tested check that says 'is this "
            "actor allowed to do this verb to this resource?'"
        ),
        "remediation_steps": _steps(
            "Map the resource and every code path that mutates or reads "
            "it. Add a single authorization function used by all paths.",
            "Validate ownership/role on the *server* using session "
            "identity — never trust an ID, role, or tenant claim that "
            "came from the request body, query, or a custom header.",
            "Default to 403. Only allow when the check returns true.",
            "Add a regression test that replays the original bypass and "
            "asserts denial.",
            "Log denied attempts and alert on bursts — repeated 403s are "
            "a strong attack signal.",
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        ],
        "user_story": (
            "As an application owner, I want every authorization decision "
            "made server-side using the authenticated session identity so "
            "that no client-supplied value can grant access the user "
            "should not have."
        ),
    },

    "A02:2021-Cryptographic_Failures": {
        "suggested_priority": "p2",
        "description_long": (
            "A cryptographic weakness was detected: deprecated TLS "
            "version, weak cipher, expired/self-signed certificate, or "
            "use of a legacy primitive (MD5, SHA-1, RC4, DES, 1024-bit "
            "RSA). Modern attackers and compliance frameworks both treat "
            "these as failed."
        ),
        "impact": (
            "Confidentiality and integrity guarantees of TLS are reduced "
            "or eliminated. Depending on the weakness, an active attacker "
            "may downgrade the connection, recover plaintext, or "
            "impersonate the service."
        ),
        "remediation_long": (
            "Match the Mozilla Server-Side TLS 'intermediate' profile "
            "(or 'modern' if you can drop legacy clients), rotate any "
            "expired certificates, and remove every cipher / protocol "
            "version not on the allowed list."
        ),
        "remediation_steps": _steps(
            "Disable TLS 1.0, TLS 1.1, and SSLv3 at the load balancer / "
            "web server. Allow only TLS 1.2 and TLS 1.3.",
            "Restrict ciphers to the Mozilla intermediate suite (or "
            "modern). Remove RC4, 3DES, NULL, EXPORT, anonymous, and any "
            "static-RSA key exchange.",
            "Enable HSTS with at least 12 months and includeSubDomains.",
            "Confirm certificate chain validity, hostname match, and "
            "renewal automation (Let's Encrypt / ACM / etc.).",
            "Re-test with testssl.sh and aim for an A or A+ rating.",
        ),
        "code_example": (
            "# nginx — Mozilla intermediate\n"
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n"
            "ssl_prefer_server_ciphers off;\n"
            "ssl_session_timeout 1d;\n"
            "ssl_session_cache shared:MozSSL:10m;"
        ),
        "references": [
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://ssl-config.mozilla.org/",
        ],
        "user_story": (
            "As a platform owner, I want our TLS configuration to match "
            "the Mozilla intermediate profile so that confidentiality and "
            "integrity guarantees match current industry baseline."
        ),
    },

    "A03:2021-Injection": {
        "suggested_priority": "p0",
        "description_long": (
            "User-controlled input is reaching an interpreter (SQL, "
            "shell, NoSQL, LDAP, OS command, template engine, HTML "
            "rendering) without being safely separated from the code "
            "context. The scanner observed a payload changing the "
            "interpreter's behavior."
        ),
        "impact": (
            "Depending on the sink, this can mean data exfiltration "
            "(SQLi), arbitrary code execution (template / OS command), "
            "stored XSS that runs on every other user's session, or "
            "authentication bypass."
        ),
        "remediation_long": (
            "Replace string concatenation with parameterised APIs at the "
            "sink. Output-encode at the rendering layer based on context "
            "(HTML body / attribute / JS / URL). Validate inputs on "
            "structure, but never rely on filtering as the only defense."
        ),
        "remediation_steps": _steps(
            "Find the sink and switch to a safe API: prepared statements "
            "for SQL, parameterised queries for NoSQL, "
            "subprocess.run(..., shell=False) with a list arg for OS "
            "commands, an autoescaping template engine for HTML.",
            "For HTML output, use the framework's built-in escaping "
            "(Jinja2 autoescape, React's default JSX, Django's |escape). "
            "Treat any |safe / dangerouslySetInnerHTML as a security "
            "review checkpoint.",
            "Add structural input validation (allowlist of expected "
            "shapes) at the boundary — but never trust it to substitute "
            "for safe APIs at the sink.",
            "Add a regression test using the exact scanner payload.",
            "Sweep the codebase for the same anti-pattern: `f\"... {x} ...\"` "
            "into SQL, `os.system(...)`, raw `innerHTML =`, etc.",
        ),
        "code_example": (
            "# WRONG\n"
            "cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# RIGHT\n"
            "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "user_story": (
            "As an application developer, I want every interpreter sink "
            "(SQL, OS command, template, HTML render) to receive user "
            "input via a parameterised or auto-escaping API so that no "
            "input can change the interpreter's intent."
        ),
    },

    "A05:2021-Security_Misconfiguration": {
        "suggested_priority": "p3",
        "description_long": (
            "A configuration setting weakens the security posture: "
            "default credentials, verbose error messages, debug endpoints "
            "exposed, missing security headers, unnecessary features "
            "enabled, or out-of-date components. None of these is a "
            "vulnerability on its own — together they form the surface "
            "that real exploits land on."
        ),
        "impact": (
            "Increased reconnaissance surface, leaked stack traces / "
            "version strings that fingerprint exploitable components, "
            "and removal of browser-side mitigations that would otherwise "
            "blunt the impact of an application bug."
        ),
        "remediation_long": (
            "Establish a hardened baseline configuration as code "
            "(Terraform / Ansible / nginx config in the repo) and apply "
            "it everywhere. Treat configuration drift as a build failure."
        ),
        "remediation_steps": _steps(
            "Address the specific finding: change the default password, "
            "remove the debug endpoint, set `display_errors=Off`, etc.",
            "Move the configuration into version control so the next "
            "deploy can't reintroduce the issue.",
            "Add a CI check (or scheduled scan) that fails when the "
            "regression returns.",
            "Audit similar surfaces — misconfigurations cluster.",
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
        "user_story": (
            "As a platform engineer, I want hardened configuration baked "
            "into infrastructure-as-code so that misconfigurations cannot "
            "drift back in unnoticed."
        ),
    },

    "A07:2021-Identification_and_Authentication_Failures": {
        "suggested_priority": "p1",
        "description_long": (
            "An authentication weakness was detected — default or weak "
            "credentials, missing MFA on a privileged path, session "
            "cookies missing Secure / HttpOnly / SameSite, predictable "
            "session identifiers, or login that doesn't rate-limit / "
            "lock out."
        ),
        "impact": (
            "An attacker can guess, replay, fix, or bypass authentication "
            "for the affected accounts. For privileged accounts this is "
            "full takeover."
        ),
        "remediation_long": (
            "Enforce strong credentials, secure session cookies, rate-"
            "limited login, and MFA (or equivalent) on every privileged "
            "or sensitive path."
        ),
        "remediation_steps": _steps(
            "Rotate any default / weak credentials uncovered by the scan.",
            "Set session cookies with Secure; HttpOnly; SameSite=Lax (or "
            "Strict where compatible).",
            "Add login rate limiting and progressive lockout after "
            "failed attempts.",
            "Require MFA on admin paths and on credential change.",
            "Use a vetted authentication framework — do not roll a "
            "custom session/password scheme.",
        ),
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
        "user_story": (
            "As a security engineer, I want every authentication "
            "boundary to enforce secure cookies, rate limiting, lockout, "
            "and MFA for privileged paths so that credential guessing "
            "and session theft cannot succeed."
        ),
    },

    "A10:2021-SSRF": {
        "suggested_priority": "p1",
        "description_long": (
            "The application accepts a URL or hostname from user input "
            "and fetches it server-side, without restricting the "
            "destination. SSRF lets an attacker pivot into internal "
            "networks, cloud metadata services, or other backend "
            "endpoints not exposed to the internet."
        ),
        "impact": (
            "Cloud metadata theft (instance credentials), internal "
            "service discovery, port scanning, exfiltration via DNS, and "
            "in some cases remote code execution via vulnerable internal "
            "services."
        ),
        "remediation_long": (
            "Treat every URL fetched on behalf of a user as untrusted. "
            "Allowlist destinations, resolve DNS once and validate the "
            "resulting IP, and block link-local / private / loopback "
            "ranges. Never let user input pick the protocol."
        ),
        "remediation_steps": _steps(
            "Define an allowlist of host patterns the app may legitimately "
            "fetch. Reject anything else.",
            "Resolve DNS in the app, check the IP against an explicit "
            "deny list (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7, fe80::/10), "
            "then connect to that exact IP — defeating DNS rebinding.",
            "Force protocol to https:// (or http: for known cases).",
            "Block redirects, or re-validate the redirect target.",
            "Run the fetcher in an egress-restricted network segment.",
        ),
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        "user_story": (
            "As an application developer, I want every server-side fetch "
            "of a user-supplied URL to validate the destination against "
            "an allowlist and block private / metadata IP ranges so that "
            "SSRF cannot reach internal infrastructure."
        ),
    },

    "A06:2021-Vulnerable_and_Outdated_Components": {
        "suggested_priority": "p2",
        "description_long": (
            "A third-party library, framework, or runtime component in "
            "use is at a version with publicly known vulnerabilities. "
            "These findings come from the SCA stage, which fingerprints "
            "JavaScript libraries against retire.js, audits any exposed "
            "lockfile via OSV-Scanner, and consults a local cache "
            "(populated from OSV / retire / nuclei templates / LLM "
            "lookups) for any package without a direct hit."
        ),
        "impact": (
            "Vulnerable components import the bug into your application "
            "verbatim. The blast radius depends on the specific CVE, but "
            "the common cases are: client-side XSS via DOM-manipulation "
            "library bugs, RCE via deserialization in server-side "
            "frameworks, and information disclosure via debug or "
            "diagnostic endpoints exposed by an old admin module."
        ),
        "remediation_long": (
            "Upgrade to the patched version. Where an upgrade is not "
            "immediately possible, mitigate the specific exploit path "
            "(e.g. restrict which sinks consume untrusted input, add a "
            "Subresource Integrity hash, or pin a CSP that blocks the "
            "vulnerable behaviour). Add the package to a recurring SCA "
            "report so the next disclosure is caught quickly."
        ),
        "remediation_steps": _steps(
            "Identify the consuming code paths. Most upgrades are safe; "
            "a small number require code changes for breaking API moves.",
            "Upgrade to the first non-vulnerable version per the advisory.",
            "Re-run the SCA stage to confirm the finding clears.",
            "Add the package to a tracked dependency manifest checked "
            "into source control so the upgrade is repeatable across "
            "environments.",
            "If you cannot upgrade, document the compensating control "
            "(CSP, SRI, code-level input filter) and add a regression "
            "test that asserts the control still applies.",
        ),
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1104.html",
            "https://osv.dev/",
            "https://retirejs.github.io/retire.js/",
        ],
        "user_story": (
            "As an application owner, I want every third-party "
            "component in our stack to be inventoried, watched for new "
            "advisories, and upgraded on a defined cadence so that a "
            "newly disclosed CVE never sits in production unnoticed."
        ),
    },
}


# ---- API used by enrichment.py ---------------------------------------------

def lookup(source_tool: str, title_norm: str,
           owasp: str | None) -> dict | None:
    """Return the catalog entry for this (tool, title, owasp), or None.
    Order: exact title match → tool+owasp → owasp-only."""
    if title_norm:
        hit = BY_TITLE.get((source_tool, title_norm))
        if hit:
            return hit
    if owasp:
        hit = BY_OWASP.get(owasp)
        if hit:
            return hit
    return None
