# enhanced_testing — Action Plan: Rounds 10 & 11 + Fixture Rework

_Author: Tim Rice <tim.j.rice@hackrange.com>_
_Status: planning_
_Target product: nextgen-dast 2.1.1 (NO version bump — reuse 2.1.1 tag/branch)_
_Predecessor: `action_plan_enhanced_testing.md` (Round 9, shipped)_

---

## 1. Goal

Lift the platform from "high-fidelity probes that mostly fire on
Juice Shop" to "high-fidelity probes that find weaknesses on real
customer web apps regardless of stack." Three coordinated efforts:

1. **Round 11 — extract & generalize.** 15 new probes that replace
   the Juice-Shop-coupled detection patterns in rounds 1-8 with
   generic class detectors (sweep small catalogues of common-shape
   paths + structural / regex / numeric signals that are stack-
   agnostic).
2. **Round 10 — platform-targeted coverage.** 15 new probes that
   cover the highest-impact issues on the platforms the org builds
   on (Angular, J2EE, PHP, Python/Django/Flask, IIS/ASP.NET, AEM)
   plus three cross-stack generic probes.
3. **Fixture rework.** Replace the "Juice Shop = positive control"
   contract with per-class minimal fixtures — small Dockerfiles
   that exhibit *one* bug each. Juice Shop becomes one fixture
   among many, used only for the genuinely-business-logic probes
   from rounds 3-8 (basket / B2B / feedback) where it remains the
   right test target.

Success criteria for the combined effort:
- ≥ 90 high-fidelity generic probes total (60 existing + 15 R10 +
  15 R11; old JS-coupled probes stay as catalog-only entries).
- Every R10 / R11 probe ships with a positive control (per-class
  fixture or a compiled list of known-vulnerable real-world apps
  the security team can spin up locally).
- Zero false positives on the negative control (clean nginx).
- Bulk-Challenge runner re-routes every R10 / R11 finding via the
  same `matches_titles` mechanism rounds 1-9 use.
- The 0.7 confidence floor on `validated=True` (shipped in Round 9)
  still holds; new probes self-impose ≥ 0.85 on validate, ≥ 0.80
  on refute, `validated=None` anywhere in between.

---

## 2. Context: what the existing 80 probes cover

After Round 9 the probe inventory is:

| Family | Generic on real apps | JS-coupled (Juice-Shop-shaped) |
|---|---|---|
| JWT / auth | alg=none, RSA→HMAC, no-exp, unverified-email, default creds, vendor creds, no-lockout, username-enum-timing, password-change-no-current, logout-no-invalidate | OAuth-password-from-email |
| AuthZ | role-mass-assignment, admin-force-browse, PII-IDOR-user-enum, API-v1-bypass, method-override | basket walk/manip/checkout, feedback userid/delete, address walk, deluxe membership, user-email-change-other, product-review-edit, order-history view-all |
| Injection | SQL-login, NoSQL-login, XSS-reflected-search, host-header-reset, path-traversal-static, path-traversal-nginx-alias | NoSQL-review-operator, NoSQL-review-DoS, ReDoS-b2b, prototype-pollution-user-patch, SSTI-pug, XSS-stored-lastloginip, cmdi-video-subtitles, XXE-file-upload, deserialization-b2b-eval, deserialization-b2b-sandbox |
| Misconfig | CORS-wildcard, HSTS, session-cookie-flags, CSP-missing, clickjacking-frame-ancestors, cache-deception, cache-poison-XFH, websocket-origin, basic-auth-over-HTTP, nosniff-missing, session-fixation | — |
| Info disclosure | dirlisting, swagger, metrics, robots, security.txt, source-map, key-material, verbose-error, GraphQL-endpoint, GraphQL-schema-introspection, backup-files-root, diagnostic-endpoints | — |
| Excessive data | users-password-hash, cards-PAN, pagination-unbounded | — |
| SSRF / SCA | profile-image-URL (Juice-Shop literal), SCA-runtime | — |

Rough split: ~45 probes already-generic, ~35 JS-coupled. Round 11
turns the 35 into 15 strong generics by extracting the *class* and
widening the catalogue (one R11 probe replaces 1-3 JS-coupled ones).

---

## 3. Round 11 — extract & generalize (15 probes)

Each probe sweeps a small catalogue of common-shape paths and
fields. JS-literal paths can stay in the catalogue as one entry
among many — the new probe reaches them too.

### 3.1 SSRF / URL-field persistence

#### R11-1 — `ssrf_url_field_persisted`
Replaces / supersedes: `ssrf_profile_image_url`.
**Detection:** Register a throwaway user. Sweep POST/PATCH endpoints
with a payload that sets a URL-shaped field
(`{imageUrl|webhookUrl|callback|redirectUrl|avatarUrl|profilePic|
homepage|website|notificationUrl}`: `http://dast-ssrf-marker-XXXX.example/`).
Sweep verification endpoints (`/api/me`, `/api/users/me`,
`/api/profile`, `/rest/user/whoami`, `/api/account`) for the marker
URL. Validate when the marker round-trips into the persisted record.
**Why generic:** the bug is "trust an attacker URL enough to store
it"; the literal route is irrelevant. AWS metadata exfil,
SSRF-to-Redis, file:// reads all chain off this same primitive
regardless of platform.
**Fidelity:** 0.95 on round-trip (marker is unique random).
**OWASP:** A10 SSRF / API7 / **CWE-918, CWE-441**.

### 3.2 Authorization / IDOR

#### R11-2 — `authz_resource_idor_walk`
Replaces: `authz_basket_idor_walk`, `authz_address_idor_walk`,
parts of `authz_order_history_view_all`.
**Detection:** Register two throwaway users (A and B). Determine
A's id and at least one resource id A owns (basket / address / order /
invoice / favorite / project / etc — sweep candidate listing paths).
As B, GET resource paths that include A's resource id
(`/api/<resource>/<a_id>`). Validate when B's response includes A's
data (different owner id / different email / non-empty content B
doesn't own).
**Why generic:** No literal resource hardcoded; sweep covers
`/api/baskets/<id>`, `/api/orders/<id>`, `/api/invoices/<id>`,
`/api/projects/<id>`, `/api/files/<id>`, `/api/documents/<id>`,
`/api/messages/<id>`, `/api/posts/<id>`, etc.
**Fidelity:** 0.92 on confirmed cross-account read.
**OWASP:** API1 BOLA / A01 / **CWE-639, CWE-284**.

### 3.3 Stored XSS via request headers

#### R11-3 — `xss_stored_via_request_headers`
Replaces: `xss_stored_lastloginip`.
**Detection:** Register a throwaway. Trigger a state-recording
action (login, comment post, support ticket) while sending one of
`{True-Client-IP, X-Forwarded-For, Referer, User-Agent, X-Real-IP,
X-Original-URL}: <DAST-XSS-MARKER-XXXX>` where the marker contains
literal `<dast-xss-marker-XXXX>`. Then GET reflective surfaces
(`/api/me`, `/profile`, `/dashboard`, `/admin/audit`, `/api/account`).
Validate when the marker appears un-HTML-escaped in any response.
**Fidelity:** 0.95 on un-escaped reflection.
**OWASP:** A03 / **CWE-79**.

### 3.4 XXE on any XML-accepting endpoint

#### R11-4 — `xxe_any_xml_upload`
Replaces: `xxe_file_upload`.
**Detection:** Sweep XML-accepting endpoints — multipart `/upload`,
`/import`, `/api/files`, `/api/v*/upload`, `/api/v*/parse`, `/api/import-xml`,
`/svg`, plus a Content-Type-XML POST to `/api/parse`, `/api/data`,
`/api/v*/import` — with an XXE payload that retrieves
`file:///etc/hostname`. Validate when the response body contains
the host's `/etc/hostname` shape (single-line lowercase
alphanumeric, length 1-63).
**Fidelity:** 0.97 on file:// retrieval.
**OWASP:** A05 / **CWE-611, CWE-776**.

### 3.5 Command injection via filename / path query parameter

#### R11-5 — `cmdi_filename_param_in_query`
Replaces / supersedes: `cmdi_video_subtitles`.
**Detection:** Sweep query-string parameters whose names suggest a
file path (`file`, `path`, `download`, `export`, `subtitles`,
`filename`, `template`, `view`, `attachment`) at common endpoints
(`/`, `/download`, `/export`, `/view`, `/api/files`, `/cgi-bin/*`,
`/php-cgi/*`). Payload combines path traversal + shell metachars
plus a marker file read: `";cat /etc/hostname;#`,
`$(cat /etc/hostname)`, `\` + cat. Validate when the response body
matches the host's hostname-shape AND the request status was 200.
**Fidelity:** 0.92 on hostname-shape return + 200.
**OWASP:** A03 / **CWE-78, CWE-77**.

### 3.6 Path traversal via filename / path query parameter

#### R11-6 — `path_traversal_filename_param`
Replaces / supersedes: `path_traversal_extension_bypass`,
`path_traversal_ftp_download`.
**Detection:** Different from `path_traversal_static_serve`
(R9-7 — focuses on static-mount routes). This one sweeps
*query parameters* whose values get joined with a base path:
`?file=../../../etc/passwd`, `?path=...`, `?download=...`,
`?template=...`, `?view=...`. Sweep candidate endpoints
(`/`, `/download`, `/export`, `/preview`, `/template`,
`/api/files`, `/api/v*/files`). Validate on `^root:x:0:0:` body
match.
**Fidelity:** 0.97 on /etc/passwd return.
**OWASP:** A01 / **CWE-22, CWE-23**.

### 3.7 Prototype pollution via PATCH / PUT body

#### R11-7 — `prototype_pollution_any_patch`
Replaces: `prototype_pollution_user_patch`.
**Detection:** Register throwaway. Sweep PATCH/PUT endpoints
(`/api/users/me`, `/api/profile`, `/api/settings`, `/api/preferences`,
`/api/me`) with body `{"__proto__": {"dast_pp_marker_XXXX": "1"}}`
and `{"constructor": {"prototype": {"dast_pp_marker_XXXX": "1"}}}`.
After the PATCH, GET an UNRELATED endpoint (`/api/products`,
`/api/categories`, `/api/about`, `/api/health`) and look for the
marker key appearing in the response (proves prototype pollution
crossed object boundaries — same global Object.prototype now
carries the marker).
**Fidelity:** 0.97 on cross-endpoint marker leak.
**OWASP:** A04 / A08 / **CWE-1321**.

### 3.8 NoSQL operator injection

#### R11-8 — `nosql_operator_injection_any_filter`
Replaces: `nosql_review_operator_injection`.
**Detection:** Sweep query-string filter parameters with the
operator-injection shape: `?id[$ne]=-1`, `?status[$gt]=`,
`?email[$regex]=.*` against listing endpoints
(`/api/users`, `/api/products`, `/api/reviews`, `/api/orders`,
`/api/posts`, `/api/items`). Compare the row count for
`?id=1` vs `?id[$ne]=-1` — if the operator form returns markedly
more rows than the literal form, validate.
**Fidelity:** 0.92 on row-count blow-up.
**OWASP:** A03 / API8 / **CWE-943, CWE-89**.

### 3.9 ReDoS on any string field

#### R11-9 — `redos_any_string_field`
Replaces: `redos_b2b_orderlines`.
**Detection:** Sweep POST/PATCH endpoints with a body containing a
catastrophic-backtracking payload in a string field
(`{name|description|comment|title|notes|message}`:
`a` × 30 + `!`). Compare response time vs a benign payload of the
same field. Validate when the catastrophic payload takes ≥ 2 s
longer than the benign one AND the catastrophic response timed out
or returned 5xx.
**Fidelity:** 0.85 on time delta (timing-based — at the edge of the
fidelity floor).
**OWASP:** A04 / **CWE-1333, CWE-407**.

### 3.10 SSTI across template engines

#### R11-10 — `ssti_any_template_engine`
Replaces: `ssti_pug_username`.
**Detection:** Sweep POST/PATCH user-display-name-shape fields
(`username`, `displayName`, `name`, `nickname`, `bio`, `signature`)
with a battery of template-engine markers:
`{{7*191}}` (Jinja/Handlebars/Vue), `${7*191}` (Velocity/Freemarker),
`#{7*191}` (Pug), `<%= 7*191 %>` (ERB), `[[${7*191}]]` (Thymeleaf),
`{{=7*191}}` (Ractive). Then GET the rendering endpoint and look
for `1337` in the response body.
**Fidelity:** 0.97 on `1337` in the body.
**OWASP:** A03 / **CWE-94, CWE-1336**.

### 3.11 Mass assignment beyond `role`

#### R11-11 — `authz_mass_assignment_widened`
Replaces: `authz_role_mass_assignment` (which already covers `role`
field; this one widens to the additional privileged fields modern
apps actually use).
**Detection:** POST registration with body containing every
privileged field shape:
`{role: "admin", isAdmin: true, is_admin: true, isSuperUser: true,
permissions: ["*"], groups: ["administrators"], plan: "enterprise",
tier: "premium", verified: true, emailVerified: true, suspended:
false, balance: 999999, credit: 999999}`. Validate on any one
returning in the response with the supplied value.
**Fidelity:** 0.95 per field.
**OWASP:** API6 / A04 / **CWE-915, CWE-1320**.

### 3.12 JWT `kid` header injection

#### R11-12 — `auth_jwt_kid_injection`
**Detection:** Forge a JWT with `kid` header set to one of:
`/dev/null` + signature with empty key; `../../../../dev/null`
(traversal — same trick); SQL injection shape
(`x' UNION SELECT 'AAA' --` + signature with key `AAA`); URL shape
(`http://dast-jwt-jku.example/key.json` — server may fetch).
Replay the forged token at common whoami endpoints. Validate when
the server responds with a 200 carrying the marker email from the
forged payload.
**Fidelity:** 0.97 on marker echo.
**OWASP:** A07 / **CWE-345, CWE-287, CWE-94**.

### 3.13 CORS reflected origin with credentials

#### R11-13 — `cors_reflected_origin_with_creds`
Different from existing `config_cors_wildcard` (looks for `*` +
credentials). This one sends `Origin: http://dast-marker-XXXX.example`
and validates when the response reflects that exact origin AND
sets `Access-Control-Allow-Credentials: true`. Reflected-origin-
with-creds is strictly worse than wildcard-no-creds.
**Detection:** Sweep `/`, `/api/`, `/api/me`, `/api/users`,
`/api/v1/`, `/oauth/token`. Validate on `Access-Control-Allow-Origin:
http://dast-marker-XXXX.example` AND `Access-Control-Allow-Credentials:
true`.
**Fidelity:** 0.95 on header pair.
**OWASP:** A05 / **CWE-942, CWE-346**.

### 3.14 Admin login pages at common paths

#### R11-14 — `info_admin_login_at_common_paths`
**Detection:** Sweep candidate admin paths: `/admin`,
`/admin/login`, `/administrator`, `/wp-admin/`, `/wp-login.php`,
`/console`, `/manage`, `/manager/html`, `/dashboard`, `/management`,
`/cms`, `/backoffice`, `/backend`, `/sysadmin`, `/control-panel`.
Validate when any returns 200 with a login-form signature
(an `<input type="password">` AND an `<input name="username|email|user|
login">` AND a `<form>` element). Different from
`authz_admin_section_force_browse` which looks for a *user list*;
this looks for a login surface that admins forgot to gate behind a
VPN.
**Fidelity:** 0.85 on login-form structural match.
**OWASP:** A05 / **CWE-1059, CWE-200**.

### 3.15 Reset-password token leaked in Referer

#### R11-15 — `auth_password_reset_token_in_referer`
**Detection:** Trigger a password reset for a throwaway account.
Server emails or surfaces a URL like
`https://app.example/reset?token=<TOKEN>`. The client opens that
URL — and *every* `<a>` with an `href` to a third-party domain on
the resulting page leaks the token via Referer. (We can't simulate
the browser side, so we approximate: GET the reset-confirmation
URL with a deliberately set `Referer:` and look for any third-party
external link in the response that would receive the token.) Also
detects the simpler bug shape: token present in URL fragment-less
`?reset_token=` query string AND no
`Referrer-Policy: no-referrer` / `same-origin` header on that page.
**Fidelity:** 0.85 on token-in-query-string + missing-or-permissive
referrer-policy combination.
**OWASP:** A07 / **CWE-598, CWE-200**.

---

## 4. Round 10 — platform-targeted (15 probes)

### 4.1 Angular (2)

#### R10-1 — `angular_dev_mode_in_prod`
**Detection:** Fetch the homepage. Parse `<script src="...main*.js">`
candidates. GET each. Validate when the bundle body contains any of:
`ngDevMode = true`, `ng.probe`, unminified `@angular/core` source
markers (function names like `bootstrapModule`, `defineComponent`
in plain text), or the Angular dev-mode console-warning string
`"Angular is running in development mode"`. Production builds
strip all of these.
**Fidelity:** 0.92 on dev-mode marker presence.
**OWASP:** A05 / **CWE-489, CWE-200**.

#### R10-2 — `angular_secrets_in_bundle`
**Detection:** Fetch the homepage. GET each `<script>` bundle.
Match each bundle body against high-entropy cloud-key patterns:
- AWS access key: `AKIA[0-9A-Z]{16}`
- AWS secret access key: `(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])`
  (with surrounding context — `aws_secret_access_key`,
  `secretAccessKey`)
- Google API: `AIza[0-9A-Za-z_\-]{35}`
- Stripe live: `sk_live_[0-9a-zA-Z]{24}`
- Firebase: `apiKey:.+authDomain:.+firebaseapp\.com`
- GitHub PAT: `gh[opusr]_[A-Za-z0-9]{36}`
- Slack webhook: `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`
Validate on any match.
**Fidelity:** 0.95 (regex-validated, not heuristic).
**OWASP:** A02 / API3 / **CWE-798, CWE-200, CWE-540**.

### 4.2 Java / J2EE (3)

#### R10-3 — `java_jenkins_script_console`
**Detection:** GET `/script`, `/jenkins/script`, `/manage/script`.
Validate on body containing `<title>Script Console` OR
`Type in an arbitrary Groovy script`. Reachable script console =
RCE-on-click (Groovy runs as the Jenkins server).
**Fidelity:** 0.97.
**OWASP:** A05 / **CWE-489, CWE-78**.

#### R10-4 — `java_jboss_jmx_invoker`
**Detection:** GET `/jmx-console`, `/jmx-console/HtmlAdaptor`,
`/web-console/`, `/invoker/JMXInvokerServlet`,
`/invoker/EJBInvokerServlet`. Validate on response body containing
`JBoss JMX Management Console`, `JBoss Web Console`, or the binary
Java-serialization stream signature `\xac\xed\x00\x05` on the
invoker path.
**Fidelity:** 0.95.
**OWASP:** A05 / **CWE-489, CWE-502**.

#### R10-5 — `java_tomcat_examples_left_in`
**Detection:** GET `/docs/`, `/examples/`, `/examples/jsp/`,
`/examples/servlets/`, `/manager/status`. Validate on title
matches: `Apache Tomcat Examples`, `Apache Tomcat/x.y.z Status`.
Tomcat ships these in `webapps/` by default — leaving them in
production both fingerprints the version and exposes documented
attack surface.
**Fidelity:** 0.95.
**OWASP:** A05 / **CWE-200, CWE-489**.

### 4.3 PHP (3)

#### R10-6 — `php_phpinfo_exposed`
**Detection:** GET `/phpinfo.php`, `/info.php`, `/test.php`,
`/i.php`, `/_phpinfo.php`, `/phpinfo`. Validate on
`<title>phpinfo()</title>` AND `<h1 class="p">PHP Version`.
Leaks every server config, every env var, every loaded module.
**Fidelity:** 0.97.
**OWASP:** A05 / **CWE-200, CWE-540**.

#### R10-7 — `php_composer_installed_json`
**Detection:** GET `/vendor/composer/installed.json`,
`/vendor/composer/installed.php`, `/vendor/autoload.php`.
Validate on JSON body with `packages` (or `installed`) array
containing entries with `name` AND `version` keys.
**Fidelity:** 0.97.
**OWASP:** A05 / API9 / **CWE-200, CWE-1059**.

#### R10-8 — `php_wp_user_enumeration`
**Detection:**
1. GET `/?author=1`, `/?author=2`, `/?author=3` (anonymous).
   Validate when any redirects (301/302) to `/author/<slug>/` —
   the slug is the username.
2. GET `/wp-json/wp/v2/users` — validate on JSON array of
   `{id, name, slug, ...}`.
**Fidelity:** 0.95 on either signal.
**OWASP:** A07 / API3 / **CWE-200, CWE-203**.

### 4.4 Python (2)

#### R10-9 — `python_django_debug_page`
**Detection:** GET `/<random-non-existent-path-XXXX>` and
`/admin/<random>/`. Validate when the body contains
`You're seeing this error because you have DEBUG = True` AND
`Request Method:`. Captures the Django DEBUG=True 404/500 page,
which leaks the SECRET_KEY (sometimes), every middleware, every
view, full traceback, and request data.
**Fidelity:** 0.97.
**OWASP:** A05 / **CWE-489, CWE-200, CWE-209**.

#### R10-10 — `python_werkzeug_debugger`
**Detection:** GET `/console`, `/debug`, `/__debug__/`,
`/_werkzeug/`. Validate on `<title>Console // Werkzeug Debugger</title>`
or the inline `Werkzeug Debugger</a>` link. Reachable Werkzeug
debugger = RCE on PIN guess (PIN is generated from semi-public
machine details).
**Fidelity:** 0.97.
**OWASP:** A05 / **CWE-489, CWE-78**.

### 4.5 ASP.NET / IIS (2)

#### R10-11 — `iis_short_filename_disclosure`
**Detection:** Differential between `/<random-non-existent-prefix>~1*~1.aspx`
(returns 404 Not Found) and `/aspnet_clien~1*~1.aspx` (returns
404 Bad Request when the 8.3-truncated prefix matches an actual
file/dir). The differential is the IIS-specific filesystem-prefix
leak. Probe a small fixed list of common prefixes
(`aspnet_client`, `inetpub`, `App_Data`, `bin`, `web`, `images`).
**Fidelity:** 0.85 on response-code differential (single-shot
fidelity is medium; we use 4 probes per prefix to confirm).
**OWASP:** A05 / **CWE-200**.

#### R10-12 — `iis_webdav_methods_enabled`
**Detection:** OPTIONS `/`. Validate when `Allow` header lists any
of `PROPFIND`, `MKCOL`, `MOVE`, `COPY`, `LOCK`, `PUT`, OR a
`DAV:` header is returned. Also follow up with a
`PROPFIND /` and validate on a `<D:multistatus>` XML response.
**Fidelity:** 0.95.
**OWASP:** A05 / A01 / **CWE-552, CWE-285**.

### 4.6 AEM — Adobe Experience Manager (4)

These are derived from Adobe's published security checklist
and known exploit patterns reported in CVEs (e.g., the
Querybuilder AEM-2018-002 family and the Felix-console RCE
chain). No internal AEM access required — each detection
signal is a structurally-unique response body or status code
shape that real AEM instances produce by default.

#### R10-13 — `aem_querybuilder_full_dump`
**Detection:** GET `/bin/querybuilder.json?path=/&p.limit=10&p.hits=full`,
`/bin/querybuilder.feed?path=/`,
`/bin/querybuilder.json?type=cq:Page&p.limit=10`. Validate on JSON
body with shape `{"success":true, "results":<n>, "total":<m>,
"hits":[{"jcr:path":"/...", ...}]}` AND `hits` length ≥ 1.
**Why high-fidelity:** No app other than Sling/AEM produces this
exact JSON shape with this exact field set.
**OWASP:** A01 / A05 / **CWE-200, CWE-285, CWE-668**.

#### R10-14 — `aem_crx_de_lite`
**Detection:** GET `/crx/de/index.jsp`, `/crx/de/`,
`/crx/explorer/index.jsp`, `/crx/explorer/diff.jsp`,
`/crx/explorer/browser/index.jsp`. Validate on title
`<title>CRXDE Lite</title>`, `<title>CRX Explorer</title>`, or
title containing `Adobe Experience Manager`.
**OWASP:** A05 / **CWE-200, CWE-489**.

#### R10-15 — `aem_felix_console`
**Detection:** GET `/system/console`, `/system/console/bundles.json`,
`/system/console/configMgr`, `/system/console/status-Configurations`,
`/system/console/status-config.txt`. Validate per-path:
- `/system/console` etc. — title `Apache Felix Web Console`.
- `/system/console/bundles.json` — JSON `{"bundles":[{"id":...,
  "symbolicName":"org.apache.felix...."}]}` with at least one
  entry whose `symbolicName` starts with `org.apache.` or
  `com.adobe.granite.`.
**Why critical:** The Felix console is RCE-by-design — anyone
who reaches the `Configuration` page can rewrite OSGi service
configs, including setting custom JCR access controls.
**OWASP:** A01 / A05 / **CWE-489, CWE-285**.

#### R10-16 — `aem_sling_dotjson_selectors`
**Detection:** GET `/.json`, `/.tidy.json`, `/.infinity.json`,
`/.4.json`, `/content.json`, `/etc.json`, `/var.json`,
`/libs.json`, `/.docview.json`. Validate on JSON body containing
`jcr:primaryType` field at top level OR nested. The
`jcr:primaryType` key is JCR-specific; finding it in any anonymous
response is unambiguous proof that the dispatcher (or its absence)
is letting Sling default selectors through.
**Why critical:** `/.infinity.json` returns the entire JCR subtree
under `/`. A few selectors like `/.tidy.json` against `/etc/users`
return all user records.
**OWASP:** A01 / A05 / **CWE-285, CWE-200**.

### 4.7 Generic platform (3)

#### R10-17 — `http_trace_method_enabled`
**Detection:** Send `TRACE / HTTP/1.1` with a custom marker
header. Validate when the response status is 200 AND the body
echoes the request including the marker header. Cross-Site
Tracing (XST) primitive in legacy browsers / proxies; even where
XST itself is mitigated, TRACE on production = anti-pattern with
no upside.
**Fidelity:** 0.95.
**OWASP:** A05 / **CWE-693, CWE-16**.

#### R10-18 — `http_dangerous_methods_allowed`
**Detection:** OPTIONS on `/`, `/api/`, `/api/v1/`, `/static/`,
`/assets/`, `/uploads/`. Parse `Allow` header. Validate when any
read-only-shape path returns `Allow:` containing `PUT`, `DELETE`,
`PATCH`, or `PROPFIND`. Only fire on paths where these methods
shouldn't be exposed (skip API roots that intentionally support
PATCH).
**Fidelity:** 0.85.
**OWASP:** A05 / **CWE-693, CWE-749**.

(Round 10 lands at 18 probes counting the AEM expansion. Drop
nothing — all 18 ship.)

---

## 5. Fixture rework

### Why

Today `tests/probe_stack.yml` brings up Juice Shop + clean nginx.
The "validates against Juice Shop" pattern was right for rounds
1-8 (Juice Shop ships every relevant bug), but Round 9 already
showed the strain — only 2/20 R9 probes fire green on JS. R10/R11
make this worse: most of them are *correctly refuted* on JS,
because JS doesn't run PHP, doesn't expose AEM, doesn't ship
Werkzeug.

### What

Add per-class minimal fixtures to `tests/probe_stack.yml` so each
probe has a positive control matched to its class:

| New service | Image | Purpose | Probes it controls |
|---|---|---|---|
| `php-info` | `php:8.2-apache` with a `/var/www/html/info.php` containing `<?php phpinfo(); ?>` | phpinfo positive | R10-6 |
| `composer-leak` | `nginx:alpine` serving a real `installed.json` at `/vendor/composer/installed.json` | composer-leak positive | R10-7 |
| `werkzeug-debug` | `python:3.12-slim` running a Flask app with `app.run(debug=True)` and an `/console` route | Werkzeug debugger positive | R10-10 |
| `django-debug` | `python:3.12-slim` running `django-admin startproject` with `DEBUG=True` | Django debug positive | R10-9 |
| `nginx-alias-bad` | `nginx:alpine` with the off-by-slash misconfig from R9 | Nginx alias positive | R9-17, possibly more |
| `iis-mock` | nginx with hand-rolled responses mimicking IIS WebDAV / 8.3 leak | IIS positive | R10-11, R10-12 |

Total new fixtures: 6. Each adds ~8-12 lines to `probe_stack.yml`
and a tiny Dockerfile or static `fixtures/` directory.

For AEM, J2EE-specific (Jenkins/JBoss/Tomcat), and Angular —
no fixture; we ship the probe class-detector with no positive
control and rely on the negative control + smoke + a manual
sanity-check against a real AEM/Jenkins/Tomcat instance the
security team has access to. The probe still gets the standard
quiet-on-clean-ref + smoke tests in CI.

### How probes route the new fixtures

The conftest grows new session-scoped fixtures (`php_info_url`,
`werkzeug_url`, `django_debug_url`, etc.). Tests requesting them
auto-skip when the corresponding container isn't up — same
pattern as today.

---

## 6. Step-by-step execution

### Step 0 — Pre-flight (fixtures + plan)

- [ ] Append the six new services to
      `enhanced_testing/tests/probe_stack.yml` and add the
      `enhanced_testing/tests/fixtures/` content for each.
- [ ] `docker compose -f tests/probe_stack.yml up -d` and confirm
      every fixture is healthy.
- [ ] Add the new session-scoped fixtures to `conftest.py`.

### Steps 1-15 — Round 11 probes

Per probe (same disciplined process as R9):
1. Implement `enhanced_testing/probes/<name>.py`.
2. Manifest with `matches_titles` + specific CWEs.
3. Test row in `tests/test_round10_round11_probes.py`.
4. Run pytest until green.

### Steps 16-33 — Round 10 probes

Same process.

### Step 34 — Wire orchestrator

Add POST-needing probes to `_PROBES_NEEDING_POST` in
`scripts/orchestrator.py`. Update TODO.md backlog → shipped.

### Step 35 — Mirror, image, push, git

- Mirror `/data/pentest/enhanced_testing/`,
  `/data/pentest/scripts/`, `/data/pentest/app/` into
  `/data/pentest/src/`.
- Rebuild image as `dockerregistry.fairtprm.com/nextgen-dast:2.1.1`
  (no version bump per CLAUDE.md).
- Push to registry; redeploy via `pentest.sh pull && up -d`.
- Git commit on `master` and cherry-pick to `2.1.1` branch; push
  both.

### Step 36 — Live engagement run

- Premium scan against a real customer FQDN. Expect new findings
  from R10/R11 probes. Click "Challenge all findings" and confirm
  routing works.

---

## 7. Acceptance criteria

- [ ] `python3 -m pytest enhanced_testing/tests/test_round10_round11_probes.py -v`
      passes 100 % with the expanded fixture stack up.
- [ ] Existing `test_round9_probes.py` and earlier rounds still
      green (no regressions).
- [ ] Every probe carries `validated=True` confidence ≥ 0.85,
      `validated=False` ≥ 0.80, `validated=None` everywhere in
      between.
- [ ] No "top-level OWASP" warnings from `app.toolkit.list_probes()`.
- [ ] Image republished on `2.1.1`; fresh-host pull works with no
      source files (CLAUDE.md self-sufficiency).
- [ ] `master` and `2.1.1` git branches both carry the commit;
      `.claude/` excluded.

---

## 8. Out of scope (deferred to a future round)

- **Active SSRF chains**: cloud-metadata IMDSv1 read, internal
  Redis / Memcache auth-bypass. These need a controllable internal
  network or a callback host; both are infrastructure risks bigger
  than the marker-URL persistence check.
- **WebSocket message-content tests**: hijacking-once-connected
  needs a stateful client; the round-9 origin-validation probe
  catches the upstream issue.
- **Compiled-language source disclosure** (Java decompilation,
  .NET reverse): too noisy and the SCA probes already cover the
  outdated-component class.
- **Container runtime / K8s** weaknesses (kubelet exposed, etcd
  leaks): these are infra-level, not web-app-level. Belong in a
  dedicated infra-scan family.
- **Active brute force** beyond the 20-attempt no-lockout check we
  already ship: more would creep into destructive territory.
