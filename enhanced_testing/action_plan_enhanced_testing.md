# enhanced_testing — Action Plan: 20 new high-fidelity TTPs

_Author: Tim Rice <tim.j.rice@hackrange.com>_
_Status: planning_
_Target product: nextgen-dast 2.1.1 (NO version bump — reuse 2.1.1 tag/branch)_
_Test fixture: `enhanced_testing/tests/probe_stack.yml` (Juice Shop + clean nginx)_

---

## 1. Goal

Add 20 new probes to `enhanced_testing/probes/` that:

1. Detect issues the existing 60 probes do not cover.
2. Lead directly to **web-application compromise** (RCE, ATO, full data
   exfiltration, session theft, privilege escalation, cache-layer
   poisoning that affects every visitor).
3. Are **read-only / non-destructive** (`safety_class = "read-only"`):
   no mutating writes that the analyst couldn't undo, no destructive
   methods (DELETE, password changes against existing accounts, etc.).
4. Are **high fidelity** — return `validated=True` only on an
   unambiguous, deterministic signal (regex / structural / numeric);
   confidence **≥ 0.85** on validation, **≥ 0.80** on refutation,
   `validated=None` (→ inconclusive) anywhere in between. This is
   the bar for surviving "Challenge all findings" without producing
   false positives. Step P1 adds a 0.7 platform-wide floor on the
   `validated=True` branch so the bar is enforced even if a future
   probe forgets it.
5. Carry a manifest with `matches_titles` + `validates` (specific CWE,
   never a top-level OWASP category) so the bulk-challenge runner
   re-routes the same finding to the same probe.
6. Emit findings whose **what was detected**, **impact**, **technical
   details**, **reproduce**, **verify** sections all carry concrete
   values (URL, marker, status code, response excerpt, header) — not
   generic prose.

The 20 TTPs together close the largest remaining gaps in the OWASP API
Top 10 (BOLA / Broken Authentication / Excessive Data Exposure /
Misconfiguration / Lack of Resources & Rate Limiting / Improper Assets
Management) and the OWASP Web Top 10 (A01 / A02 / A03 / A04 / A05 / A07).

---

## 2. What the existing 60 probes already cover (do NOT duplicate)

| Family | Already covered |
|---|---|
| JWT | alg=none, no-expiration, RSA→HMAC confusion, unverified-email admin, logout, brute force, 2FA |
| Auth bypass | NoSQL injection, SQL injection, default admin, vendor defaults, OAuth-password-from-email, password-reset weak Q, password-change without current |
| Authz / IDOR | basket walk/manipulation/checkout, address walk, feedback userid, feedback delete, product-review edit, role mass assignment, deluxe membership, user-email change, order-history view-all, admin force-browse, method override |
| Injection | SQLi-login, NoSQL operator + $where DoS, SSTI Pug, stored XSS via True-Client-IP, cmd-injection in /video, ReDoS, prototype pollution |
| Path traversal | /ftp extension bypass, /ftp named-file leakage |
| SSRF / XXE / Deserialization | profile-image URL SSRF, multipart XXE, B2B order eval, B2B sandbox escape |
| Misconfig | CORS wildcard+creds, HSTS missing, session-cookie flags |
| Info disclosure | dirlisting, swagger, metrics, robots, security.txt, source map, key material, verbose error, GraphQL endpoint fingerprint |
| Posture | username-enum timing, no brute-force lockout |

The TTPs below were chosen because **none of them appears in the table
above** AND each has a deterministic detection primitive.

---

## 3. The 20 new TTPs

Each entry below is the spec the probe will be written against. Filename
follows the existing `<class>_<topic>.py` convention. CWE list is what
goes in `manifest.validates`. Severity is the *uplift* the probe emits
on confirmation; the parser keys severity off this rather than off
`safety_class`.

### 3.1 Critical / High — direct compromise

#### TTP 1 — `info_excessive_data_users_password`
**OWASP / CWE:** API3:2023 BOLP / A02 / **CWE-256, CWE-359, CWE-200**
**Severity:** Critical
**Why it matters:** A `GET /api/Users` (or `/api/Users/<id>`) response
that includes a `password` field — even hashed — hands the attacker an
offline-cracking corpus for every account. With one HTTP request and
no auth, an attacker walks away with the entire hash dictionary.
**Detection signal:** Response is JSON; some user object contains a
`password` (or `passwordHash`, `pwd`) key whose value matches a
known-hash shape regex (bcrypt `$2[abxy]\$\d\d\$.{53}`, argon2
`\$argon2.*`, scrypt, sha-256 hex, MD5 hex with 32 chars). Validates
only when the regex matches — eliminates a placeholder field
populated with `null` / empty string.
**Reproduce:**
```
GET /api/Users HTTP/1.1
Host: target
```
**Verify:** Response contains `"password":"<hash-shape>"` for one or
more user objects.
**Juice Shop expectation:** Validates true (admin user has bcrypt
hash returned in `/api/Users`).

#### TTP 2 — `info_excessive_data_cards`
**OWASP / CWE:** A01 / API3:2023 / **CWE-359, CWE-200**
**Severity:** Critical
**Why it matters:** `/api/Cards` (or `/api/PaymentMethods`) returns a
full unmasked PAN. PCI scope, breach-disclosure obligation,
multi-million-dollar-fine class.
**Detection signal:** Response field whose value is 13–19 digits AND
passes the Luhn checksum AND the field name is one of `cardNum`,
`number`, `pan`, `cardNumber`. Luhn check is what eliminates the
many false positives (booking-reference IDs, order numbers).
**Reproduce:**
```
GET /api/Cards HTTP/1.1
Authorization: Bearer <session token from /rest/user/login>
```
**Verify:** At least one card object contains a Luhn-valid 13–19 digit
PAN.
**Juice Shop expectation:** Validates true (registered user can read
their own card with full number).

#### TTP 3 — `info_graphql_introspection_schema`
**OWASP / CWE:** A05 / API9:2023 / **CWE-200, CWE-668**
**Severity:** High
**Why it matters:** Different from the existing `info_graphql_endpoint`
fingerprint probe — that probe only asserts whether `/graphql` exists.
This one asserts whether `__schema { types { name } }` returns the
full schema, which lets an attacker enumerate every mutation, every
field, and every authentication boundary in one request.
**Detection signal:** POST `{"query":"{__schema{queryType{name}
mutationType{name} types{name kind}}}"}`; response JSON has
`data.__schema.types` with ≥ 5 named types.
**Reproduce:** POST the introspection query to candidate paths
(`/graphql`, `/api/graphql`, `/v1/graphql`, `/api/v1/graphql`).
**Verify:** Response JSON contains `__schema.types[*].name` for ≥ 5
types. Sample 10 type names into the evidence.
**Juice Shop expectation:** Inconclusive (no GraphQL); will fire on
any production app shipping an Apollo / Hasura / express-graphql
endpoint with introspection unguarded.

#### TTP 4 — `api_pagination_unbounded`
**OWASP / CWE:** API4:2023 / A04 / **CWE-770, CWE-200**
**Severity:** High
**Why it matters:** A list endpoint that honours `?limit=99999` lets
the attacker exfiltrate every row in one request, and is a denial-of-
service primitive against the database. Most apps pretend they cap
the limit and silently don't.
**Detection signal:** For a list endpoint discovered via Swagger or
the route catalogue, request `?limit=10000` and `?limit=10`. If the
returned row count for `limit=10000` is ≥ 1000 (well above any
plausible paging cap), validates.
**Reproduce:**
```
GET /api/Users?limit=10000
GET /api/Products?limit=10000
```
**Verify:** JSON array length ≥ 1000.
**Juice Shop expectation:** Likely validates on `/api/Products` /
`/api/Users` since Juice Shop's Sequelize `findAll` doesn't enforce
a cap.
**False-positive guard:** Compare `limit=10` and `limit=10000` row
counts — only fire when the larger limit returns more rows AND ≥ 1000.

#### TTP 5 — `auth_host_header_password_reset`
**OWASP / CWE:** A05 / **CWE-644, CWE-93**
**Severity:** Critical
**Why it matters:** If the password-reset email's link is built from
the request's `Host` header without validation, an attacker who
triggers a reset for a victim using
`Host: dast-marker.example.com` causes the victim's email to contain
`https://dast-marker.example.com/reset?token=…` — every reset token
goes to the attacker's server.
**Detection signal:** Two-step:
  1. POST `/rest/user/reset-password` (or `/api/auth/forgot-password`,
     `/api/auth/password/reset/request`) with valid email and
     `Host: dast-marker-XXXX.example`; **also** check whether the JSON
     response body or any redirect Location echoes the marker host.
  2. If the app exposes the most-recent reset token via an API
     (Juice Shop's challenge surface) or via a `Location` redirect to
     the reset URL, look for the marker host in that URL.
**Reproduce:** capture the request, swap Host, replay; inspect the
JSON for `resetUrl`/`link`/`url` keys.
**Verify:** Response body contains the marker host string verbatim.
**Juice Shop expectation:** Inconclusive (Juice Shop's reset flow
does not expose the URL). Will fire against ~30 % of real apps that
echo the reset URL in the JSON ack body.
**Read-only safety:** This probe sends a reset-request POST with a
unique throwaway email we registered seconds earlier — it never
triggers a reset on a real user.

#### TTP 6 — `xss_reflected_search_query`
**OWASP / CWE:** A03 / API8:2023 / **CWE-79**
**Severity:** High
**Why it matters:** A search endpoint that interpolates `q=` into
the rendered HTML page without escaping is the canonical reflected-XSS
primitive. Steals session tokens, performs CSRF on behalf of the
victim, exfiltrates DOM data.
**Detection signal:** GET `/search?q=<DAST-MARKER-tag-XXXX>` (and
`/?q=`, `/products?search=`, `/api/Products/search?q=`); response
body contains the marker **un-escaped** (the literal `<` and `>`
characters present in the body, not `&lt;` / `&gt;`). Marker is a
random string wrapped in `<dast-marker-XXXX>` so the angle-brackets
are the variable that confirms reflection without HTML encoding.
**Reproduce:** Request with the random marker, grep response for the
literal angle-bracket form.
**Verify:** Substring `<dast-marker-` present in the response body.
**Juice Shop expectation:** Validates true (well-known Juice Shop
challenge — `/#/search?q=<iframe src="javascript:alert(1)">`).

#### TTP 7 — `path_traversal_static_serve`
**OWASP / CWE:** A01 / **CWE-22, CWE-23**
**Severity:** Critical
**Why it matters:** Local file inclusion on a static-file route lets
an attacker pull `/etc/passwd`, `.env`, `app.js` (source disclosure),
private keys. RCE adjacent if the app then evaluates the loaded file.
**Detection signal:** GET `/static/..%2f..%2fetc%2fpasswd`,
`/uploads/../../etc/passwd`, `/api/files/../../etc/passwd`. Response
body contains `root:x:0:0:` (Linux) OR `[fonts]` near `[boot loader]`
(Windows). The marker is OS-baked content nothing else returns —
unambiguous.
**Reproduce:** Try a small bag of encoded/double-encoded traversal
patterns at common file-serving endpoints.
**Verify:** Response body matches `^root:x:0:0:` (multi-line regex)
or contains the Windows hosts-file marker.
**Juice Shop expectation:** Refuted on Juice Shop (its static serve
is hardened); fires against real apps with `app.use("/files",
express.static(uploadsDir))` patterns.

#### TTP 8 — `authz_pii_idor_user_enum`
**OWASP / CWE:** API1:2023 / A01 / **CWE-639, CWE-284**
**Severity:** High
**Why it matters:** Existing `authz_admin_section_force_browse` only
covers the unauthenticated `/api/Users` listing. This probe iterates
`/api/Users/{1..10}` while logged in **as a normal user** and flags
when the response carries PII fields the caller doesn't own
(phone, dob, address, security-question answer, role).
**Detection signal:** Register user A, walk `/api/Users/1`..
`/api/Users/10`; if any non-self user returns a JSON object whose
keys include `email` AND any of {`phone`, `dob`, `address`,
`securityAnswer`, `creditCard`}, validate.
**Reproduce:** Register, walk, dump field counts.
**Verify:** Field-set inclusion check + foreign user id in response.
**Juice Shop expectation:** Validates true (Juice Shop's
`/api/Users/<id>` does not verify ownership for normal users).

#### TTP 9 — `authz_api_legacy_v1_auth_bypass`
**OWASP / CWE:** API9:2023 / A05 / **CWE-1059, CWE-285**
**Severity:** High
**Why it matters:** A new v2 path enforces auth, but the old v1 path
that the team forgot to delete still answers anonymous requests.
Common in apps that grew through API redesigns.
**Detection signal:** For each `/api/v2/<route>` discovered (via
Swagger or hard-coded list — `/users`, `/orders`, `/admin`),
unauthenticated GET to the v2 path returns 401/403 AND
unauthenticated GET to `/api/v1/<same-route>` (or `/api/<route>`,
`/v1/<route>`, `/api/old/<route>`) returns 200 with a JSON body.
The differential is the signal.
**Reproduce:** GET v2, GET v1 alternate.
**Verify:** v2 ≠ 200 AND v1 = 200 with body.
**Juice Shop expectation:** Inconclusive (Juice Shop has only one
version namespace). Will fire on enterprise APIs.

### 3.2 Cache / network / framing — drive-by compromise

#### TTP 10 — `config_cache_deception_path_extension`
**OWASP / CWE:** A05 / **CWE-525, CWE-200**
**Severity:** High
**Why it matters:** Many apps route `/account/profile.css` to the
same controller as `/account/profile`, and CDNs often cache anything
ending in `.css` / `.js` / `.png`. Result: the next visitor to
`/account/profile.css` reads the previous user's session-rendered
HTML — full PII leak via cache deception.
**Detection signal:** Authenticate, GET `/profile`, cache the
response. GET `/profile.css` (and `.js`, `.png`, `.gif`) — if the
response status is 200 AND `Cache-Control` permits caching (`public`,
or no `private`/`no-store`) AND the body contains the same PII
markers as `/profile`, validate.
**Reproduce:** Auth, fetch, fetch with .css suffix, diff.
**Verify:** Body equality / PII marker present + cacheable headers.
**Juice Shop expectation:** Likely refuted (Juice Shop's Express
routes 404 on bad extensions). Fires on real apps with Rails /
Django catch-all routing.

#### TTP 11 — `config_cache_poison_xforwarded_host`
**OWASP / CWE:** A05 / **CWE-444, CWE-345**
**Severity:** High
**Why it matters:** If a CDN doesn't include `X-Forwarded-Host`
in its cache key but the origin reflects that header into a
`<link rel="canonical">` or a redirect, an attacker poisons the
cache with `<link rel="canonical" href="http://attacker.example">`
and every subsequent visitor's browser follows the attacker's link.
**Detection signal:** GET `/` and a couple of high-traffic-looking
paths with `X-Forwarded-Host: dast-marker-XXXX.example`. Response
body contains the marker host AND response carries a cache-friendly
header (`Cache-Control: public`, `Age:`, `X-Cache:`).
**Reproduce:** Inject header, grep response, check cache headers.
**Verify:** Marker reflected + cache headers permit caching.
**Juice Shop expectation:** Refuted (Juice Shop doesn't honour
`X-Forwarded-Host` in canonical links).

#### TTP 12 — `config_clickjacking_frame_ancestors`
**OWASP / CWE:** A05 / **CWE-1021**
**Severity:** Medium
**Why it matters:** A login or password-change page that doesn't set
`X-Frame-Options` AND lacks `frame-ancestors` in CSP is iframe-able
on an attacker page — clickjacking primitive that turns into 1-click
account takeover when paired with a CSRF or unguarded state-change.
Existing `config_hsts_missing` only checks HSTS; this is a different
header.
**Detection signal:** GET `/login`, `/register`, `/profile`,
`/profile/change-password`, `/admin`. For each 200 response, check
header set: a finding fires when **both** of:
  1. `X-Frame-Options` header absent OR not in
     {`DENY`, `SAMEORIGIN`}.
  2. CSP header absent OR doesn't include `frame-ancestors` directive.
**Reproduce:** Issue requests, dump headers.
**Verify:** Header inspection.
**Juice Shop expectation:** Refuted (Juice Shop sets
`X-Frame-Options: SAMEORIGIN`).

#### TTP 13 — `config_csp_missing_or_unsafe`
**OWASP / CWE:** A05 / **CWE-693, CWE-79**
**Severity:** Medium
**Why it matters:** No CSP at all (or one that includes
`'unsafe-inline'` / `'unsafe-eval'` on `script-src`) means a single
reflected-XSS finding becomes session-stealing instead of being
blocked by the browser.
**Detection signal:** GET `/`. Validates when:
  - No `Content-Security-Policy` header AND content type is `text/html`, OR
  - CSP present AND `script-src` directive contains `'unsafe-inline'` or `'unsafe-eval'`, AND no `'nonce-…'` or `'sha256-…'` source.
**Reproduce:** Issue request, parse CSP.
**Verify:** Header inspection.
**Juice Shop expectation:** Validates true (Juice Shop has no CSP).

#### TTP 14 — `config_websocket_origin_validation`
**OWASP / CWE:** A05 / **CWE-346, CWE-1385**
**Severity:** High
**Why it matters:** A WebSocket server that accepts any `Origin`
on the upgrade handshake lets the attacker page open a websocket
to the app and act as the victim — cross-site WebSocket hijacking.
**Detection signal:** Initiate the WS upgrade handshake at common
paths (`/socket.io/`, `/ws`, `/api/ws`) with
`Origin: http://dast-attacker.example` and a valid `Sec-WebSocket-
Key`. A response status of `101 Switching Protocols` AND a
`Sec-WebSocket-Accept` header confirms the server accepted a
foreign origin.
**Reproduce:** Send the upgrade headers; check 101.
**Verify:** Status == 101, Sec-WebSocket-Accept present.
**Juice Shop expectation:** Likely validates (socket.io defaults
to permissive Origin policy).

### 3.3 Information disclosure — pre-conditions for compromise

#### TTP 15 — `info_backup_files_root`
**OWASP / CWE:** A05 / **CWE-538, CWE-200**
**Severity:** High
**Why it matters:** A `/backup.zip`, `/.env`, `/database.sql`,
`/dump.sql`, `/.git/config` reachable at the public root hands the
attacker either credentials, source code, or the entire database.
Different from `info_directory_listing` (which requires autoindex
enabled) — this probe **fetches specific filenames** and pattern-
matches the body.
**Detection signal:** GET each of (~25 paths):
`/.env`, `/.env.production`, `/.env.local`, `/config.json`,
`/config.yaml`, `/database.sql`, `/dump.sql`, `/backup.zip`,
`/backup.tar.gz`, `/.git/config`, `/.svn/entries`,
`/composer.lock`, `/yarn.lock`, `/package.json.bak`,
`/wp-config.php.bak`, `/.htpasswd`, `/server.key`,
`/id_rsa`, `/private.key`. For each 200, body must match a
file-specific signature: `.env` → `^[A-Z_]+=`, `.git/config` →
`[core]`, SQL → `INSERT INTO`, ZIP → `PK\x03\x04` magic, RSA
key → `-----BEGIN`, `.htpasswd` → `^[a-z0-9_\-]+:\$`. Pattern
match removes the false positive of an SPA returning `index.html`
for any unknown path.
**Reproduce:** Walk the catalogue.
**Verify:** Per-file signature regex.
**Juice Shop expectation:** Refuted (Juice Shop traps file requests
into the SPA). Fires hard against real apps.

#### TTP 16 — `info_diagnostic_endpoints_exposed`
**OWASP / CWE:** A05 / **CWE-200, CWE-489**
**Severity:** High
**Why it matters:** ASP.NET `/trace.axd` and `/elmah.axd` log every
recent request including auth tokens; Spring Boot Actuator
`/actuator/env` and `/actuator/heapdump` expose secrets and the
entire JVM heap (which contains every request body in flight);
Apache `/server-status` and `/server-info` leak request URLs and
client IPs; `/cgi-bin/printenv` leaks environment variables.
**Detection signal:** GET each of
`/trace.axd`, `/elmah.axd`, `/server-status`, `/server-info`,
`/actuator`, `/actuator/env`, `/actuator/heapdump`,
`/actuator/health`, `/cgi-bin/printenv`, `/console`,
`/jolokia/list`, `/manage/health`. Validate when 200 AND body
matches the per-endpoint signature
(`<title>elmah` / `<title>Apache Status`/ `"contexts":` for
actuator / `magic` bytes for heap dumps).
**Reproduce:** Walk catalogue, check signature.
**Verify:** Signature regex per path.
**Juice Shop expectation:** Refuted (Node app, none of these
endpoints exist).

#### TTP 17 — `path_traversal_nginx_alias_off_by_slash`
**OWASP / CWE:** A03 / A01 / **CWE-22, CWE-200**
**Severity:** High
**Why it matters:** A common nginx misconfiguration —
`location /static { alias /home/app/static/; }` (note the **trailing
slash on alias**) — lets the attacker request `/static../app.py` and
read the parent directory because nginx concatenates the path
literally.
**Detection signal:** For each `/static`, `/assets`, `/img`,
`/files` location detected from the homepage's `<link>`/`<script>`
tags, request `<location>../package.json`, `<location>../app.py`,
`<location>../..//etc/passwd`, `<location>../../etc/hostname`.
Validate when one of these returns 200 AND body matches
`{` (JSON), `import` (Python), `root:x:0:0:` (passwd), or a
hostname-shape regex respectively.
**Reproduce:** Two requests per `<location>` candidate.
**Verify:** Body signature.
**Juice Shop expectation:** Refuted (Juice Shop is Express, not
nginx).

#### TTP 18 — `config_basic_auth_over_http`
**OWASP / CWE:** A02 / **CWE-319, CWE-523**
**Severity:** High
**Why it matters:** Any path that returns
`WWW-Authenticate: Basic` over plaintext `http://` ships every
authenticated request's credentials in base64 over the wire;
captured by anyone on the same Wi-Fi.
**Detection signal:** GET `/`, `/admin`, `/manager`, `/jenkins`,
`/grafana`, `/prometheus`, `/wp-admin`, `/api`. If the URL
**scheme is `http://`** AND any response carries `WWW-Authenticate:
Basic`, validate.
**Reproduce:** Walk paths over the http:// scheme.
**Verify:** Header inspection on http:// URLs only.
**Juice Shop expectation:** Refuted (no Basic realms). Fires
against ops dashboards and old Jenkins / Tomcat / phpMyAdmin
deployments.

#### TTP 19 — `config_xcontent_type_options_missing`
**OWASP / CWE:** A05 / **CWE-693, CWE-430**
**Severity:** Medium
**Why it matters:** A user-content path that returns
`Content-Type: image/svg+xml` (or anything without
`X-Content-Type-Options: nosniff`) lets the browser MIME-sniff and
treat an attacker-uploaded SVG as HTML — stored XSS via image upload.
**Detection signal:** GET candidate user-content paths
(`/profile-image/<id>`, `/uploads/<id>`, `/files/<id>`, plus the
homepage). Validate when response is HTML/SVG/JS-ish content type
AND `X-Content-Type-Options: nosniff` is missing.
**Reproduce:** Walk paths, inspect headers.
**Verify:** Header absence + content-type match.
**Juice Shop expectation:** Refuted (Juice Shop sets nosniff).

#### TTP 20 — `auth_session_fixation_no_rotation`
**OWASP / CWE:** A07 / **CWE-384, CWE-613**
**Severity:** High
**Why it matters:** If the session ID issued **before** login is
the same one carried **after** login, an attacker who pre-seeds the
victim's browser with a known cookie (via a man-in-the-middle, an
XSS on a sibling subdomain, or a `Set-Cookie` smuggle) takes over
the session the moment the victim logs in.
**Detection signal:**
  1. GET `/` with no cookie; capture every `Set-Cookie` whose name
     looks session-shaped.
  2. POST `/rest/user/login` (or `/login`) with the seeded cookie
     reflected back AND valid creds (use the throwaway account this
     probe just registered).
  3. Compare the post-login session cookie value against the
     pre-login one.
Validates when the **value is byte-identical** AND the cookie name
is in the session-shaped allow list.
**Reproduce:** Two requests with the same cookie jar; diff values.
**Verify:** Equality check on session-cookie value.
**Juice Shop expectation:** Refuted (Juice Shop uses JWT in body,
not session cookies). Fires hard against PHP/Rails/Django apps that
forget `session_regenerate_id()` / `reset_session` / SessionMiddleware
rotation.

---

## 4. Why these will survive "Challenge all findings"

The challenge runner re-runs the matched probe against the finding's
`evidence_url` and writes back the verdict. A new probe survives this
loop when:

1. The probe is **idempotent** — every run produces the same verdict
   given the same target state. All 20 above are: each marker is
   regenerated per run from `secrets.token_hex()`, every detection
   signal is a deterministic byte / numeric / structural match, and
   none depend on timing alone (the existing username-enum and
   redos-orderlines probes already prove the timing-based path; we
   intentionally avoided adding another).
2. The manifest's `matches_titles` is **specific** (no top-level
   OWASP categories in `validates` — see toolkit.py:108 warning).
3. The probe's POST/PUT requirements (if any) are listed in
   `_PROBES_NEEDING_POST` in `scripts/orchestrator.py`. The probes
   in this batch needing the destructive gate:
   - `auth_host_header_password_reset` (POSTs reset request)
   - `auth_session_fixation_no_rotation` (POST login)
   - `info_excessive_data_cards` (needs auth, so register/login)
   - `authz_pii_idor_user_enum` (needs auth)
   - `info_graphql_introspection_schema` (POST query)
   - `config_websocket_origin_validation` (handshake is a CONNECT-
     style upgrade — encoded as POST to the safety layer)
   - `xss_reflected_search_query` (GET only — no gate)
   - All other probes are GET-only.
4. The probe's verdict mapping aligns with
   `toolkit.verdict_to_status` (`app/toolkit.py:284-311`).
   *Current* behavior:
   - `validated=True` (any confidence) → `validated`  ← **no floor today**
   - `validated=False`, `confidence ≥ 0.80` → `false_positive`
   - `validated=False`, `confidence < 0.80` → `inconclusive`
   - `validated=null` → `inconclusive`
   Step P1 below fixes the missing floor on the True branch (so a
   probe returning `validated=True, confidence=0.2` falls into
   `inconclusive` rather than silently validating). Every probe in
   this batch self-imposes:
   - `validated=True` only at confidence **≥ 0.85** (typical 0.95-0.97)
   - `validated=False` only at confidence **≥ 0.80**
   - Anywhere else: `validated=None`, `confidence ≤ 0.7` → lands in
     `inconclusive` cleanly. Probes never fake a verdict at low
     confidence.

---

## 5. Step-by-step execution

This is the order we run; each step is a single PR-shaped change.
Steps P1 and P2 are **pre-Round-9 fidelity hardening** — they fix
existing low-fidelity verdicts visible in the UI today (e.g., the
0.2-confidence verdict on assessment 16 / finding 807) before any
new probes go in. They MUST run before Step 0 so the new probes
land on a corrected baseline.

### Step P1 — Add a confidence floor on `validated=True`

**Why:** `app/toolkit.py:305-306` currently maps any
`validated=True` to `validation_status='validated'` with no minimum
confidence — so a probe that returns `True` at 0.2 silently marks
the finding validated. That's the root cause of the UI showing a
0.2 next to a green "validated" badge.

**Change:** `app/toolkit.py:284-311` (`verdict_to_status`). Add a
0.7 floor on the True branch; below the floor the verdict falls
through to the same `inconclusive` bucket as a low-confidence
False or a `validated=null`:

```python
# Before
v = verdict.get("validated")
if v is True:
    return "validated"

# After
v = verdict.get("validated")
if v is True:
    if (verdict.get("confidence") or 0) >= 0.7:
        return "validated"
    # Confidence too low to claim a confirmation — do not stamp
    # 'validated' on the finding. Treat as inconclusive so the
    # analyst (or a tighter probe) can decide.
    return "inconclusive"
```

**Why 0.7 and not 0.8 / 0.85:** the 0.8 floor on the False branch
already exists; matching it on True would push the existing
no-brute-force-lockout probe's 0.75 verdicts into inconclusive
when they're meant to validate. A 0.7 floor catches the obvious
fidelity holes (anything below half-confident) without disturbing
the existing well-tuned probes. New Round-9 probes self-impose a
stricter ≥ 0.85 anyway.

**Mirror to `src/`:** also patch `src/app/toolkit.py` so the change
ships in the next image build (CLAUDE.md: "all changes go into the
docker image and git repo").

**Test:** add a unit test in `tests/test_toolkit.py` (create if
missing) covering the four boundary cases:
- `{validated: True,  confidence: 0.95}` → `validated`
- `{validated: True,  confidence: 0.70}` → `validated` (boundary inclusive)
- `{validated: True,  confidence: 0.69}` → `inconclusive`
- `{validated: True,  confidence: 0.20}` → `inconclusive` ← the bug
- `{validated: False, confidence: 0.80}` → `false_positive` (regression check)

**Acceptance:** `python3 -m pytest tests/test_toolkit.py -v` passes
before moving on.

### Step P2 — Audit existing probes for low-confidence True verdicts

**Why:** The floor in P1 prevents *future* low-confidence True
verdicts from validating, but any verdict already written to
`findings.validation_status='validated'` with `confidence < 0.7`
in `findings.validation_evidence` is stale. The analyst needs to
see those re-evaluated, not preserved by the no-downgrade guard
in `scripts/challenge_runner.py:307-315`.

**Find the affected rows:**

```sql
-- which assessments / findings have a low-confidence "validated"
-- verdict on file? Run on the live DB.
SELECT
  f.id, f.assessment_id, f.source_tool, f.severity,
  LEFT(f.title, 60)  AS title,
  f.validation_probe,
  JSON_EXTRACT(f.validation_evidence, '$.confidence') AS conf
FROM findings f
WHERE f.validation_status = 'validated'
  AND JSON_EXTRACT(f.validation_evidence, '$.confidence') IS NOT NULL
  AND CAST(JSON_EXTRACT(f.validation_evidence, '$.confidence') AS DECIMAL(4,3)) < 0.70
ORDER BY conf ASC, f.assessment_id DESC;
```

**Per-probe audit:** for every probe name that appears in the
result set above, open the probe's `run()` method and confirm
each `Verdict(validated=True, …)` constructor uses confidence
≥ 0.85. The two patterns we expect to find:

1. **Probe is fine, the verdict was a one-off low-confidence
   True** (network blip, partial body). The P1 floor catches
   future runs; clear the stale verdict by setting
   `validation_status='unvalidated'` on the affected rows and
   let the next bulk-Challenge re-run them under the new floor.
2. **Probe systematically returns True at low confidence** — e.g.,
   it falls through to a heuristic guess instead of returning
   `validated=None`. Tighten the probe (replace the heuristic
   with a deterministic signal, or return `validated=None` on
   ambiguity) and bump its manifest version so the orchestrator
   re-runs it.

**Reset the stale rows** (one statement, idempotent — re-runnable):

```sql
UPDATE findings
SET    validation_status = 'unvalidated',
       validation_evidence = NULL,
       validation_run_at   = NULL
WHERE  validation_status = 'validated'
  AND  CAST(JSON_EXTRACT(validation_evidence, '$.confidence')
            AS DECIMAL(4,3)) < 0.70;
```

After the next Challenge-all pass, those rows land in either
`validated` (with confidence ≥ 0.7), `false_positive`, or
`inconclusive` per the new mapping — none of them keep a green
badge they didn't earn.

**Acceptance:** the SELECT in this step returns zero rows. The
analyst sees only confidently-validated findings under the green
badge.

**Audit run on 2026-05-04 (current DB):**
- Validated rows below 0.7 confidence: **0** (clean).
- Validated rows with no top-level `confidence` key: 19 — all from
  two non-`verdict_to_status` paths: `enhanced_ai_testing` (LLM
  validator stores confidence inside the summary text, embedded
  values 0.80-0.95) and `fast_path` (the per-finding /challenge
  route stores the raw fast-path body whose `verdict: "reproduced"`
  is the fidelity signal). Not affected by the round-9 floor; not
  reset. **Note for a future cleanup round**: align the fast-path
  write path to store the verdict-shaped dict (with the 0.95
  confidence that `_fast_path_response_to_verdict` already sets)
  instead of the raw response body, so the JSON shape is uniform
  across all validation paths.

### Step 0 — Pre-flight (one-time, ~10 min)

- [ ] Confirm fixture stack is up:
  ```
  docker compose -f /data/pentest/enhanced_testing/tests/probe_stack.yml ps
  curl -s http://127.0.0.1:3010/rest/admin/application-version  # must return JSON
  curl -sI http://127.0.0.1:3011/                                # must return 200
  ```
  If unhealthy:
  ```
  docker compose -f /data/pentest/enhanced_testing/tests/probe_stack.yml up -d --force-recreate
  ```
- [ ] Add a "Backlog" section to `enhanced_testing/TODO.md` containing
  the 20 entries below as `[ ]` items.

### Steps 1–20 — Build one probe per step

For each TTP in §3 (in the order listed — criticals first, then
caches, then info disclosure):

1. **Implement** `enhanced_testing/probes/<name>.py` modelled on
   `info_directory_listing.py` for GET-only probes or
   `ssrf_profile_image_url.py` for register-and-login probes:
   - Module docstring covering: what the bug is, why it matters,
     detection signal, what makes the signal high-fidelity.
   - `safety_class = "read-only"`.
   - `add_args(parser)` for the TTP-specific knobs.
   - `run(args, client)` returning a `Verdict` whose `summary`
     names the URL, the marker, and the exact byte that
     proved the finding.
   - `remediation` block lists the **fix per stack** (Express /
     Rails / Django / Spring / IIS), not generic prose.
2. **Manifest** `enhanced_testing/probes/<name>.manifest.json`:
   - `name`, `summary`, `validates: [CWE-…]` (NEVER a top-level
     OWASP category), `matches_titles` (3–5 wording variants the
     scanner could emit), `matches_tools: ["enhanced_testing", …]`,
     `safety_class`, `request_budget_typical`, `request_budget_max`,
     `args`.
3. **Test** `enhanced_testing/tests/test_<name>.py`:
   - `test_<name>_validates_juice_shop` — must return `validated=True`
     when the spec above says it should fire.
   - `test_<name>_quiet_on_clean_ref` — must return `validated=False`
     against `clean-ref` (or against an internal stub when
     Juice Shop also negates).
   - `test_<name>_smoke_no_stack` — runs without docker; must not
     crash.
4. **Run** `python3 -m pytest enhanced_testing/tests/test_<name>.py -v`
   until both real tests pass.
5. **Commit** the three files into `/data/pentest/enhanced_testing/`
   AND mirror to `/data/pentest/src/enhanced_testing/` (CLAUDE.md
   pipeline rule). No image rebuild yet — we batch.

### Step 21 — Wire orchestrator + roadmap

- [ ] Edit `scripts/orchestrator.py`: add the eight POST-needing
      probes from §4 to `_PROBES_NEEDING_POST` with one-line
      reason strings.
- [ ] Edit `enhanced_testing/TODO.md`: move each `[ ]` Backlog item
      to `[x]` with the `→ probes/<file>.py` pointer, add a
      "Round 9 (drive-by + cache + new auth)" history entry.
- [ ] Mirror both files to `src/`.

### Step 22 — End-to-end: premium scan + Challenge all

- [ ] Run a premium scan against the Juice Shop fixture in the live
      web UI (the "premium" profile is what invokes
      `run_enhanced_testing`).
- [ ] Confirm the new findings appear with the expected severities
      under `source_tool='enhanced_testing'`.
- [ ] Click **Challenge all findings**. Watch
      `assessments.current_step` count down (`auto_validate: running
      probe i/N`). Confirm:
      - Every new finding goes to `validated` or `false_positive`,
        not `inconclusive` or `errored`.
      - No "no-probe" bucket entries — `find_probe_for_finding`
        successfully routes back to each probe via
        `matches_titles`.
- [ ] Spot-check one finding's evidence pane in the UI: the
      reproduce + verify sections must include real values (URL,
      marker, status, response bytes), not placeholders.

### Step 23 — Image build + registry push + git

This is the standard nextgen-dast pipeline and reuses the existing
2.1.1 tag (no version bump per CLAUDE.md).

- [ ] `cd /data/pentest && docker build -t dockerregistry.fairtprm.com/nextgen-dast:2.1.1 .`
- [ ] `docker push dockerregistry.fairtprm.com/nextgen-dast:2.1.1`
- [ ] `./pentest.sh pull && ./pentest.sh up -d` — confirm the new
      image runs against an unrelated assessment.
- [ ] `git add enhanced_testing/ src/enhanced_testing/ scripts/orchestrator.py src/scripts/orchestrator.py`
- [ ] `git commit -m "enhanced_testing: 20 new TTPs (round 9)"` —
      Author: Tim Rice <tim.j.rice@hackrange.com>; **no Claude
      trailers** (CLAUDE.md feedback rule).
- [ ] `git push origin master` and `git push origin 2.1.1` (create
      the 2.1.1 branch if it doesn't exist locally).

### Step 24 — Run against the live engagement target

The platform tools we'll point at the live assessment target (the
fairtprm.com site under authorised pentest scope) to surface real
findings:

- [ ] Trigger a **premium** profile scan in the web UI against the
      target FQDN. The orchestrator will run the existing six
      scanners *plus* enhanced_testing (now 80 probes).
- [ ] Click **Challenge all findings** to re-validate everything,
      including the 20 new probes.
- [ ] Triage:
      - Critical / High validated → write up immediately.
      - Inconclusive → click per-finding **Challenge** to re-run
        with the analyst's full session-cookie context.
      - False-positive → confirm the verdict is correct; close.
- [ ] Use the existing **report PDF** export (the orchestrator's
      report pipeline) to package the findings for the engagement
      report. Each new TTP populates the
      "What was detected / Impact / Technical details / Reproduce /
      Verify" sections directly from the probe's `summary` +
      `evidence` + `remediation` fields, so no manual rewrite is
      needed.

---

## 6. File map (what gets created / changed)

```
enhanced_testing/
├── action_plan_enhanced_testing.md           [this file]
├── TODO.md                                   [+1 "Backlog" / Round 9 history block]
├── probes/
│   ├── info_excessive_data_users_password.py + .manifest.json    [NEW]
│   ├── info_excessive_data_cards.py          + .manifest.json    [NEW]
│   ├── info_graphql_introspection_schema.py  + .manifest.json    [NEW]
│   ├── api_pagination_unbounded.py           + .manifest.json    [NEW]
│   ├── auth_host_header_password_reset.py    + .manifest.json    [NEW]
│   ├── xss_reflected_search_query.py         + .manifest.json    [NEW]
│   ├── path_traversal_static_serve.py        + .manifest.json    [NEW]
│   ├── authz_pii_idor_user_enum.py           + .manifest.json    [NEW]
│   ├── authz_api_legacy_v1_auth_bypass.py    + .manifest.json    [NEW]
│   ├── config_cache_deception_path_extension.py + .manifest.json [NEW]
│   ├── config_cache_poison_xforwarded_host.py   + .manifest.json [NEW]
│   ├── config_clickjacking_frame_ancestors.py   + .manifest.json [NEW]
│   ├── config_csp_missing_or_unsafe.py          + .manifest.json [NEW]
│   ├── config_websocket_origin_validation.py    + .manifest.json [NEW]
│   ├── info_backup_files_root.py                + .manifest.json [NEW]
│   ├── info_diagnostic_endpoints_exposed.py     + .manifest.json [NEW]
│   ├── path_traversal_nginx_alias_off_by_slash.py + .manifest.json [NEW]
│   ├── config_basic_auth_over_http.py           + .manifest.json [NEW]
│   ├── config_xcontent_type_options_missing.py  + .manifest.json [NEW]
│   └── auth_session_fixation_no_rotation.py     + .manifest.json [NEW]
└── tests/
    └── test_round9_probes.py                                     [NEW — pattern of test_round3_probes.py]

scripts/orchestrator.py                                           [+8 entries in _PROBES_NEEDING_POST]
app/toolkit.py                                                    [Step P1 — confidence floor in verdict_to_status]
tests/test_toolkit.py                                             [Step P1 — boundary-case unit tests (NEW if missing)]
src/...                                                           [mirror of all of the above]
```

---

## 7. Acceptance criteria (what "done" looks like)

- [ ] **Step P1 done:** `verdict_to_status` floors `validated=True`
      at confidence ≥ 0.7; boundary-case tests pass.
- [ ] **Step P2 done:** SQL audit query returns zero rows — no
      `findings.validation_status='validated'` carries a stored
      confidence below 0.7.
- [ ] `python3 -m pytest enhanced_testing/tests/ -v` passes 100 % with
      Juice Shop fixture up.
- [ ] All 20 manifests load via `app.toolkit.list_probes()` with no
      "top-level OWASP" warning logs.
- [ ] A premium scan against Juice Shop produces ≥ 8 validated
      findings from the new probes (the ones expected to fire on
      Juice Shop per §3).
- [ ] "Challenge all findings" on that assessment finishes with
      zero `errored` rows attributable to the new probes.
- [ ] `dockerregistry.fairtprm.com/nextgen-dast:2.1.1` is republished
      with the new probes baked in. A fresh-host pull + run works
      with no source files (CLAUDE.md self-sufficiency rule).
- [ ] `master` and `2.1.1` branches both carry the commit. `.claude/`
      is not in either branch (`.gitignore` covers it).

---

## 8. Out-of-scope on purpose

The following ideas were considered and rejected for this round —
flagged here so we don't re-litigate later:

- **Race-condition coupon redemption** (parallel POSTs to
  `/api/Coupons/redeem`). Race conditions need parallel HTTP, which
  the SafeClient doesn't support, and the detection signal is
  probabilistic. Not high-fidelity enough for "Challenge all".
- **JWT `kid` SQL injection / path traversal**, **`jku` external
  JWKS**, **`x5c` smuggling**. These are valuable but each needs
  its own crafted payload + an attacker-controlled JWKS host. We
  already cover alg=none + RSA→HMAC; these are second-order.
- **CRLF response-splitting in redirect headers**. Modern HTTP
  libraries refuse to inject CRLF — the bug exists primarily on
  legacy stacks where our fingerprinting probes already raise
  flags.
- **Subdomain takeover via dangling CNAME**. The orchestrator's
  scope is locked to one FQDN; subdomain enumeration belongs in a
  separate recon stage.
- **Insecure deserialization (Python pickle / Java / .NET)**. Hard
  to test non-destructively without RCE on the target. The existing
  B2B eval + sandbox-escape probes cover the JS branch, which is
  what most modern apps run.
- **HTTP request smuggling**. CL.TE / TE.CL detection requires raw
  socket access; SafeClient only speaks via urllib. Belongs in a
  dedicated low-level probe family.

These can each become their own future round once we have a
deterministic-enough signal.
