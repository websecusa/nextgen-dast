# Enhanced Testing — Round 12 Action Plan

**Author:** Tim Rice <tim.j.rice@hackrange.com>
**Project:** nextgen-dast 2.1.1
**Source list:** `/tmp/things_to_test.md` (100 scenarios, .NET / PHP / Tomcat / AEM target stack)
**Date created:** 2026-05-05
**Status:** Draft for review — no code written yet.

---

## 1. Scope & Methodology

The current `enhanced_testing/probes/` directory ships 108 probes. The goal of
Round 12 is to extend that set with the high-value scenarios from
`/tmp/things_to_test.md` that are NOT already covered with high fidelity, while
deliberately skipping any scenario whose detection signal is already produced
by an existing probe.

**Disposition rules used below:**

- **SKIP — covered:** an existing probe already produces the same finding via
  the same detection signal. Adding a duplicate would inflate request budget
  for no extra signal.
- **SKIP — not safely automatable:** the test as described requires an
  attacker-controlled callback host, manual archive crafting that risks
  destabilizing the target, or specialized payload generation (PHPGGC,
  ysoserial) that we shouldn't fire blind during a scan.
- **ADD — new probe:** writes a new probe under
  `src/enhanced_testing/probes/<name>.py` and `<name>.manifest.json`.
- **ADD — new variant:** existing probe covers an adjacent angle, but the
  proposed scenario adds a meaningfully different detection path.

**Probe shape** (matches existing convention, e.g.
`auth_no_brute_force_lockout.py`):
- Subclass of `Probe` from `lib`, returns a `Verdict`.
- Manifest file with `safety_class`, `request_budget_typical`,
  `request_budget_max`, `validates` (CWE list), `matches_titles`,
  `matches_tools`.
- Author always Tim Rice; no Claude/Anthropic references anywhere.

**Implementation rule** — when these probes are written:

1. Source goes into `/data/pentest/src/enhanced_testing/probes/` (mirrored
   into `/data/pentest/enhanced_testing/probes/` for local testing).
2. `enhanced_testing/` is COPY-baked at `Dockerfile:172` — every change
   requires image rebuild + retag 2.1.1 + container recreate. No bind mount.
3. Pipeline: mirror → build → push → deploy from registry → commit → push to
   `master` and `2.1.1` branches.
4. Probe count after Round 12 should be ~108 + (count below).

---

## 2. Disposition Summary

| Bucket | Count | Notes |
|---|---:|---|
| Already covered (skip) | 22 | Existing probe matches same signal |
| Not safely automatable (skip) | 5 | Out-of-band callback, archive bombs handled minimally only |
| New probes to add | **73** | Grouped by category in §4 |
| **Net new probes** | **73** | Brings total from 108 → 181 |

---

## 3. Per-Scenario Disposition Table

Format: `T<n>` = test number from source list.

### 3.1 Authentication & Session (T1–T10)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T1 | Session token entropy analysis | **ADD** | No existing probe analyzes RNG quality of session IDs. Combine with T69. |
| T2 | Session fixation via URL parameter | **ADD** | `auth_session_fixation_no_rotation` checks rotation, not URL-param accept. |
| T3 | Concurrent session handling | **ADD** | No probe checks whether old session survives password change. |
| T4 | Password reset token reuse | **ADD** | Existing reset probes check Referer leak + weak question, not reuse. |
| T5 | Username enumeration via timing | **SKIP — covered** | `auth_username_enum_timing` is the exact match. |
| T6 | Auth bypass via HTTP method manipulation | **ADD — variant** | `authz_method_override_admin` covers admin endpoints; this adds OPTIONS/HEAD/TRACE on protected endpoints. |
| T7 | Remember-me token weakness | **ADD** | No existing probe analyzes persistent-login cookies. |
| T8 | OAuth state parameter manipulation | **ADD** | `auth_oauth_password_from_email` covers a different OAuth flaw. |
| T9 | JWT algorithm confusion | **SKIP — covered** | `auth_jwt_alg_none` + `auth_jwt_rsa_hmac_confusion` + `auth_jwt_kid_injection` cover this. |
| T10 | MFA bypass | **ADD** | `auth_2fa_status_unauthenticated` is enrollment leak, not flow bypass. Two probes: skip-via-state and bruteforce-no-lockout. |

### 3.2 Authorization & Access Control (T11–T20)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T11 | Horizontal IDOR | **SKIP — covered** | Six `authz_*_idor_walk` + `authz_pii_idor_user_enum` already cover this. |
| T12 | Vertical privesc via role parameter | **SKIP — covered** | `authz_role_mass_assignment` + `authz_mass_assignment_widened`. |
| T13 | Mass assignment / object injection (broad) | **SKIP — covered** | Mass-assignment angle covered. PHP-specific object injection handled separately at T84. |
| T14 | GraphQL authorization bypass | **ADD** | `info_graphql_introspection_schema` only flags introspection; this probes field-level authz on sensitive fields (passwordHash, ssn). |
| T15 | Function-level access control missing | **SKIP — covered** | `authz_admin_section_force_browse` + `authz_api_legacy_v1_auth_bypass`. |
| T16 | Tenant isolation bypass | **ADD** | No multi-tenant probe exists. |
| T17 | Path traversal in authz context | **ADD** | Existing path-traversal probes target file reads, not the `/api/users/1/../../admin` authz-escape pattern. |
| T18 | Metadata-based access control bypass | **SKIP — not safely automatable** | AEM JCR mixin write requires authenticated POST that mutates server state. |
| T19 | WebSocket authz check absence | **ADD** | `config_websocket_origin_validation` checks origin; this checks anonymous-connect / privileged-channel-subscribe. |
| T20 | Resource ownership manipulation | **ADD** | Specific `owner_id` field tamper not covered by generic mass-assignment probe. |

### 3.3 Business Logic Flaws (T21–T30)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T21 | Race condition in financial transactions | **ADD** | No race-condition probe exists. |
| T22 | Coupon/promo code abuse | **ADD** | High-value class, no existing coverage. |
| T23 | Price manipulation in cart/checkout | **ADD — variant** | `authz_basket_manipulation` covers cart authz; this adds price/quantity/decimal tampering and negative qty. |
| T24 | Workflow / state machine bypass | **ADD** | Skip-payment, jump-to-confirm pattern not covered. |
| T25 | Inventory / stock manipulation | **ADD** | No race-on-last-stock probe. |
| T26 | Referral/affiliate system abuse | **ADD** | Self-referral check not covered. |
| T27 | Reward/points system exploitation | **ADD** | Negative-redemption + race not covered. |
| T28 | Rate limit bypass techniques | **ADD** | Critical and missing. XFF rotation, case folding, trailing slashes. |
| T29 | Subscription/trial abuse | **ADD** | `authz_deluxe_membership_tamper` covers Juice-Shop-specific flag; this adds X-Feature-Flags header / trial-end manipulation. |
| T30 | Email/notification system abuse | **ADD** | CRLF in email field (Bcc injection) and template injection in invite emails not covered. |

### 3.4 Input Validation & Injection (T31–T40)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T31 | Second-order SQL injection | **ADD** | All current SQLi probes are first-order. Stored-then-rendered detection is hard but worth a best-effort probe. |
| T32 | NoSQL injection | **SKIP — covered** | `auth_nosql_login_bypass`, `nosql_operator_injection_any_filter`, `nosql_review_dos_where`, `nosql_review_operator_injection`. |
| T33 | LDAP injection | **ADD** | Not currently covered. |
| T34 | XXE | **SKIP — covered** | `xxe_any_xml_upload` + `xxe_file_upload`. |
| T35 | SSTI | **SKIP — covered** | `ssti_any_template_engine` + `ssti_pug_username`. |
| T36 | Expression Language injection (Spring EL / OGNL) | **ADD** | High-value for Java/AEM stack; not covered. |
| T37 | Command injection in file processing | **ADD — variant** | `cmdi_filename_param_in_query` checks query params; this checks filename-on-upload. |
| T38 | HTTP header injection / response splitting | **ADD** | Not covered. |
| T39 | Unicode / character encoding attacks | **ADD** | Two probes — homoglyph login bypass and overlong-UTF-8 traversal. |
| T40 | Prototype pollution | **SKIP — covered** | `prototype_pollution_any_patch` + `prototype_pollution_user_patch`. |

### 3.5 API Security (T41–T50)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T41 | Broken object property level authorization | **ADD** | `?fields=password,ssn` returning extra fields not covered. |
| T42 | API version exploitation | **ADD — variant** | `authz_api_legacy_v1_auth_bypass` is one specific endpoint; this discovers /v0, /beta, version headers, query-param versions across the API surface. |
| T43 | Batch / bulk API abuse | **ADD** | GraphQL batching + REST batch endpoints not covered. |
| T44 | GraphQL DoS via complex queries | **ADD** | Two probes — depth nesting and alias amplification. Capped to safe payload sizes. |
| T45 | API key / token leakage discovery | **SKIP — covered** | `info_key_material_exposed` + `angular_secrets_in_bundle` + `info_source_map_exposed`. |
| T46 | Unsafe deserialization in API | **SKIP — partially covered** | `deserialization_b2b_eval` + `deserialization_b2b_sandbox_escape` cover Node.js. .NET ViewState handled at T81. ysoserial Java payloads = SKIP not safely automatable. |
| T47 | REST API mass assignment via nested objects | **ADD** | Nested-object angle (`{"account":{"role":"admin"}}`) is meaningfully different from flat mass-assignment probes. |
| T48 | CORS misconfiguration | **SKIP — covered** | `config_cors_wildcard` + `cors_reflected_origin_with_creds`. |
| T49 | API endpoint discovery | **SKIP — covered** | `info_swagger_exposed` covers OpenAPI/Swagger. Generic wordlist brute-forcing is a scanner job, not a probe. |
| T50 | JSON / XML content-type confusion | **ADD** | Not covered. |

### 3.6 File Handling & Upload (T51–T60)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T51 | File upload type bypass | **ADD** | Extension/double-ext/Content-Type bypass not covered. |
| T52 | Path traversal in file operations | **SKIP — covered** | Five `path_traversal_*` probes already cover this. |
| T53 | SVG file upload → XSS / SSRF | **ADD** | Not covered. |
| T54 | PDF file upload exploits | **ADD** | PDF /URI external-action canary. |
| T55 | Symlink / hardlink file attacks | **ADD** | ZIP-with-symlink probe (small, safe payload). |
| T56 | ZIP slip vulnerability | **ADD** | Small archive with `../` entries; checks if extracted artifacts appear at unintended paths. |
| T57 | ImageMagick / Ghostscript vulnerabilities | **ADD** | MVG with `url(callback)` to a sink we control inside the scanner network — no external internet needed. |
| T58 | Office document macro injection | **SKIP — not safely automatable** | Server-side Office processing is rare; detection requires complex artifact inspection. |
| T59 | File size / decompression bombs | **ADD** | Modest probe — upload a known-bomb (42-byte zip → 4MB) and observe response. Capped. |
| T60 | HTML / SVG sanitization bypass | **MERGE into T53** | SVG handling is the realistic vector here; HTML upload variant folds into the SVG probe. |

### 3.7 Cryptography & Data Protection (T61–T70)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T61 | Weak encryption / hashing detection | **SKIP — covered** | `testssl_recheck` (under `toolkit/probes/`) handles TLS. ECB/hash-mode detection in app payloads is too varied for a generic probe. |
| T62 | Padding oracle attacks | **ADD** | Specifically targets ASP.NET `WebResource.axd` / `ScriptResource.axd` (.NET stack focus). Also covers T82. |
| T63 | JWT secret key weakness | **ADD** | Crack HS256 JWTs against a small, deterministic wordlist of common secrets. |
| T64 | Sensitive data in JWT claims | **ADD** | Decode payload and grep for SSN/CC/email/internal-IP patterns. |
| T65 | Information disclosure via error messages | **SKIP — covered** | `info_verbose_error`. |
| T66 | Cryptographic key exposure | **SKIP — covered** | `info_key_material_exposed`. |
| T67 | Timing attack on secret comparison | **ADD — variant** | `auth_username_enum_timing` is username-only; this targets generic token verification endpoints. |
| T68 | Hash length extension | **SKIP — not safely automatable** | Requires knowing exact MAC scheme + feeding extended messages. False-positive heavy. |
| T69 | Insecure RNG | **MERGE into T1** | Same probe — collect tokens, measure entropy. |
| T70 | Client-side encryption bypass | **ADD** | Send plaintext to endpoint and observe whether server accepts. |

### 3.8 Server Configuration (T71–T80)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T71 | SSRF | **ADD — variant** | `ssrf_profile_image_url` + `ssrf_url_field_persisted` are app-specific. Add a generic SSRF sweep with cloud-metadata + 127.x + decimal-IP + IPv6 bypass list. |
| T72 | Open redirect | **SKIP — covered** | `redirect_allowlist_bypass`. |
| T73 | Host header injection | **SKIP — covered** | `auth_host_header_password_reset` + `config_cache_poison_xforwarded_host`. |
| T74 | Exposed administrative interfaces | **SKIP — covered** | `info_admin_login_at_common_paths` + `info_diagnostic_endpoints_exposed` + `aem_*` + `java_jenkins_script_console`. |
| T75 | Debug/dev endpoints exposed | **ADD — variant** | `info_diagnostic_endpoints_exposed` covers some. Add `/elmah.axd` (.NET-specific) and Spring Actuator (split out at T90). |
| T76 | Information disclosure via HTTP headers | **ADD** | No probe currently flags `Server:` / `X-Powered-By:` / `X-AspNet-Version:` banners. |
| T77 | Backup file discovery | **SKIP — covered** | `info_backup_files_root`. |
| T78 | Source code disclosure (.git/.svn/etc.) | **ADD** | `info_source_map_exposed` covers source maps; add `.git/`, `.svn/`, `.idea/`, `.vscode/`, `.DS_Store`. |
| T79 | Directory listing | **SKIP — covered** | `info_directory_listing`. |
| T80 | Default credentials | **SKIP — covered** | `auth_default_admin_credentials` + `auth_vendor_default_credentials`. |

### 3.9 Framework-Specific (T81–T90)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T81 | .NET ViewState exploitation | **ADD** | Detect unencrypted/unsigned `__VIEWSTATE`. |
| T82 | .NET padding oracle (POET) | **MERGE into T62** | Same probe targets `WebResource.axd`. |
| T83 | PHP type juggling | **ADD** | Two probes — magic-hash (`0e215962017`) and array-comparison (`password[]=anything`). |
| T84 | PHP object injection | **ADD** | Canary serialized payload (no chain — just detection of unserialize errors / behavior changes). |
| T85 | Tomcat Ghostcat (CVE-2020-1938) | **ADD** | Detect AJP port 8009 reachable. |
| T86 | Tomcat manager path traversal | **SKIP — partially covered** | `auth_default_admin_credentials` + `java_tomcat_examples_left_in` cover the realistic detection signal; deploying a WAR is exploit territory. |
| T87 | AEM dispatcher bypass | **ADD — variant** | `aem_sling_dotjson_selectors` covers `.json` selector bypass; add the `;%0a.css` and `.infinity.json/.1.json/.-1.json` extension matrix. |
| T88 | AEM default servlets exposure | **SKIP — covered** | `aem_crx_de_lite` + `aem_felix_console` + `aem_querybuilder_full_dump`. |
| T89 | AEM content grabbing | **ADD** | `/home/users.1.json` user enum, `/etc.json`, `/libs.json` not covered. |
| T90 | Spring Boot Actuator exploitation | **ADD** | High-value, not covered. |

### 3.10 Client-Side Security (T91–T100)

| # | Scenario | Disposition | Reasoning |
|---|---|---|---|
| T91 | DOM-based XSS | **ADD** | Static analysis of JS bundles for sinks (`innerHTML`, `eval`, `document.write`, `location.href`). |
| T92 | postMessage vulnerabilities | **ADD** | Static analysis for `addEventListener('message', ...)` without `e.origin === ...` check. |
| T93 | WebSocket security issues | **ADD — variant** | `config_websocket_origin_validation` covers handshake origin. Add cross-origin handshake test (CSWSH). |
| T94 | Client-side storage of sensitive data | **ADD** | Static analysis for `localStorage.setItem('token'/'jwt'/'password'/'apiKey', ...)`. |
| T95 | Clickjacking | **SKIP — covered** | `config_clickjacking_frame_ancestors`. |
| T96 | JSONP callback injection | **ADD** | Reflected `?callback=alert(1)` in response body. |
| T97 | Flash/Silverlight crossdomain policy | **ADD** | Two-line check — `crossdomain.xml` and `clientaccesspolicy.xml` for `domain="*"`. |
| T98 | Service worker hijacking | **ADD** | Check `sw.js` scope and HTTP `importScripts()` calls. |
| T99 | Browser cache poisoning | **SKIP — covered** | `config_cache_poison_xforwarded_host` + `config_cache_deception_path_extension`. |
| T100 | Content Security Policy bypass | **ADD — variant** | `config_csp_missing_or_unsafe` flags missing/unsafe; add a deeper analyzer that catches whitelisted-CDN-with-JSONP patterns and missing `base-uri`/`object-src`. |

---

## 4. New Probe Catalog (73 probes)

Each entry below maps to a probe file (`<name>.py` + `<name>.manifest.json`)
under `src/enhanced_testing/probes/`. The `Budget` column gives
`request_budget_typical / request_budget_max`.

### 4.1 Authentication & Session (11 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 1 | `auth_session_token_entropy` | T1, T69 | Collects 50 session tokens; flags Shannon entropy < 3.5 bits/char or repeating patterns | CWE-330, CWE-331 | read-only | 50 / 60 |
| 2 | `auth_session_id_in_url_accepted` | T2 | POSTs login with `?JSESSIONID=` / `?PHPSESSID=` / `?ASP.NET_SessionId=` and confirms session bound to attacker-supplied ID | CWE-384 | read-only | 4 / 8 |
| 3 | `auth_old_session_after_password_change` | T3 | Logs in twice (two cookie jars), changes password on session A, verifies session B still authenticates a profile read | CWE-613 | requires_post (mutates password — needs documented test account) | 6 / 10 |
| 4 | `auth_password_reset_token_reuse` | T4 | Requests reset, uses token, then re-uses; flag if second use returns 200 / changes password again | CWE-640 | requires_post | 5 / 8 |
| 5 | `auth_method_bypass_options_head_trace` | T6 | Calls a known-protected endpoint with OPTIONS/HEAD/TRACE; flag if 200 with body content where GET requires auth | CWE-285, CWE-289 | read-only | 8 / 12 |
| 6 | `auth_remember_me_token_weak` | T7 | Requests "remember me" cookies for two distinct accounts; checks for base64-of-username, predictable timestamps, lack of MAC | CWE-330, CWE-539 | read-only | 4 / 6 |
| 7 | `auth_oauth_state_missing_or_replay` | T8 | Sends OAuth callback with empty state and with a previously-used code; flag 200 outcome | CWE-352 | read-only | 4 / 6 |
| 8 | `auth_mfa_skip_via_state_param` | T10 | After first-factor login, accesses dashboard / sensitive endpoints with the partially-authenticated session | CWE-287, CWE-303 | requires_post | 6 / 10 |
| 9 | `auth_mfa_no_lockout_on_codes` | T10 | 20 sequential incorrect MFA codes for a known seed account; flag absence of 429 / lockout | CWE-307 | requires_post | 22 / 30 |
| 10 | `auth_jwt_secret_weak_hmac` | T63 | Pulls a JWT from login, attempts HS256 verification against a 200-entry common-secrets list (offline crack) | CWE-326, CWE-798 | read-only | 1 / 1 (CPU only) |
| 11 | `auth_jwt_pii_in_claims` | T64 | Decodes JWT payload; regex-matches SSN, CC, internal IP, email-as-claim-key, password-shaped fields | CWE-200, CWE-522 | read-only | 1 / 2 |

### 4.2 Authorization (6 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 12 | `authz_graphql_field_level` | T14 | After confirming GraphQL endpoint, queries `{ users { passwordHash, ssn, internalNotes } }`; flag any non-null sensitive field returned | CWE-285 | read-only | 4 / 6 |
| 13 | `authz_tenant_id_header_swap` | T16 | If request triggers tenant-aware response, retries with `X-Tenant-ID: <other>` and `?tenant_id=` overrides; compares response shape | CWE-639 | read-only | 6 / 10 |
| 14 | `authz_path_traversal_to_admin` | T17 | Tests `/api/users/1/../../admin`, `/api/users/1/..%2f..%2fadmin`, `/user/profile/..;/admin`; flags 200 with admin-shaped body | CWE-22, CWE-285 | read-only | 8 / 12 |
| 15 | `authz_websocket_unauthenticated` | T19 | Opens WS handshake without cookies / auth header; flags successful upgrade + accepted message frames | CWE-306 | read-only | 4 / 6 |
| 16 | `authz_resource_owner_field_tamper` | T20 | PUTs a known resource with `owner_id` set to a different user's ID; flags 200 + owner change confirmed by GET | CWE-639 | requires_post | 6 / 10 |
| 17 | `authz_object_property_field_inflation` | T41 | Issues `GET ...?fields=id,email,password_hash,ssn` (or GraphQL equivalent); flags presence of any "should-be-hidden" field in response | CWE-213, CWE-285 | read-only | 4 / 8 |

### 4.3 Business Logic (10 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 18 | `bizlogic_race_condition_transfer` | T21 | 30 concurrent transfers from same account — flags if total transferred > balance OR all 30 returned 200 | CWE-362, CWE-367 | requires_post (needs test account) | 30 / 40 |
| 19 | `bizlogic_coupon_reuse_or_stack` | T22 | Applies same coupon 5x and stacks 3 different codes; flags total discount accumulation | CWE-840 | requires_post | 8 / 12 |
| 20 | `bizlogic_negative_quantity_total` | T23 | Adds item with `quantity=-1`; flags successful checkout or negative total | CWE-840 | requires_post | 4 / 6 |
| 21 | `bizlogic_workflow_skip_payment` | T24 | POSTs to `/order/confirm` (or similar) with order id but no preceding payment step; flags 200 + paid status | CWE-840, CWE-841 | requires_post | 5 / 8 |
| 22 | `bizlogic_inventory_oversell_race` | T25 | 50 concurrent add-to-cart of item with stock=1; flags >1 success | CWE-362, CWE-840 | requires_post | 50 / 60 |
| 23 | `bizlogic_self_referral_credit` | T26 | Signs up new account using own referral code; flags credit awarded | CWE-840 | requires_post | 4 / 6 |
| 24 | `bizlogic_points_negative_redeem` | T27 | Calls `/redeem` with `points=-1000`; flags 200 + balance increase | CWE-840 | requires_post | 3 / 4 |
| 25 | `bizlogic_rate_limit_bypass_headers` | T28 | Hits a rate-limited endpoint past the limit while rotating `X-Forwarded-For` / `X-Real-IP` / `X-Originating-IP`; flags continued 200 responses | CWE-770, CWE-799 | read-only | 30 / 50 |
| 26 | `bizlogic_subscription_feature_flag_header` | T29 | Sends `X-Feature-Flags: premium=true` / `?subscription=premium` to a free account; flags premium content returned | CWE-285, CWE-840 | read-only | 6 / 10 |
| 27 | `bizlogic_email_header_injection` | T30 | Submits forms with CRLF (`%0d%0a`) in email field followed by `Bcc:`; flags 200 + no input rejection | CWE-93, CWE-1281 | requires_post | 4 / 6 |

### 4.4 Injection (7 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 28 | `sqli_second_order_via_profile` | T31 | Registers test account with bio/username containing benign-but-distinctive SQL fragment (`'/*round12*/`); later requests profile-render endpoints; flags SQL error class in response | CWE-89 | requires_post | 8 / 12 |
| 29 | `ldap_injection_login_bypass` | T33 | POSTs login with `*)(uid=*))(|(uid=*` and `admin)(&)`; flags 200 / authenticated session | CWE-90 | read-only | 4 / 6 |
| 30 | `eli_spring_ognl_canary` | T36 | POSTs Spring EL `${T(Math).max(7,7)}` and OGNL `%{7*7}` canaries to common search/render endpoints; flags `49` reflected | CWE-917 | read-only | 8 / 12 |
| 31 | `cmdi_upload_filename_metacharacter` | T37 | Uploads tiny file with name `test;sleep5;.jpg` and `\$(sleep5).jpg`; flags response delay > 4s | CWE-78 | requires_post | 4 / 6 |
| 32 | `header_injection_response_split` | T38 | Hits redirect/download endpoints with `%0d%0aX-Round12: 1`; flags reflected header in response | CWE-113, CWE-93 | read-only | 6 / 8 |
| 33 | `unicode_homoglyph_login` | T39 | Attempts login with Cyrillic `аdmin` (U+0430) / `аdministrator`; flags 200 + auth | CWE-176, CWE-1007 | read-only | 4 / 6 |
| 34 | `unicode_overlong_utf8_traversal` | T39 | GETs `/download?file=..%c0%af..%c0%afetc/passwd` and ZWJ/RLO variants; flags `root:` in body | CWE-176 | read-only | 4 / 6 |

### 4.5 API Security (5 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 35 | `api_version_legacy_discovery` | T42 | Fetches `/api/v0/users`, `/api/v1/users`, `/api/v2/users`, `/api/beta/users` and version-header variants; flags older versions accessible without auth that newer requires | CWE-285, CWE-1059 | read-only | 12 / 20 |
| 36 | `api_batch_endpoint_authz_bypass` | T43 | Sends GraphQL batch `[{...},{...}]` and REST `{"requests":[...]}` to known endpoints; flags rate-limit not applied OR per-request authz skipped | CWE-770, CWE-285 | read-only | 6 / 10 |
| 37 | `api_graphql_dos_nesting` | T44 | Sends 6-level nested query (capped); flags 200 with full nested response (no depth-limit middleware) | CWE-770, CWE-674 | read-only | 2 / 4 |
| 38 | `api_graphql_alias_amplification` | T44 | Sends query with 50 aliases on same field (`u1:user(id:1) u2:user(id:2) ...`); flags 200 with all aliases returned | CWE-770 | read-only | 2 / 4 |
| 39 | `api_content_type_confusion` | T50 | POSTs JSON-shaped fields as XML / form-urlencoded to a JSON endpoint with `admin:true`; flags privileged field accepted | CWE-1287, CWE-269 | requires_post | 6 / 10 |
| 40 | `api_rest_mass_assignment_nested` | T47 | PUTs profile with `{"name":"x","account":{"role":"admin"}}` / `{"organization":{"plan":"enterprise"}}`; flags nested write applied | CWE-915 | requires_post | 6 / 10 |

### 4.6 File Upload (6 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 41 | `upload_extension_bypass_double` | T51 | Uploads benign-content files named `harmless.php.jpg`, `harmless.jpg.php`, `harmless.PHP`, `harmless.php%00.jpg`; flags 200 + file fetchable with `.php` MIME | CWE-434 | requires_post | 8 / 12 |
| 42 | `upload_svg_xss_or_ssrf` | T53, T60 | Uploads SVG with `<script>` and SVG with `<image xlink:href="http://...">`; flags upload accepted and served with `Content-Type: image/svg+xml` (XSS path) or external fetch attempted (SSRF path via OOB beacon) | CWE-79, CWE-918 | requires_post | 4 / 6 |
| 43 | `upload_pdf_external_action` | T54 | Uploads minimal PDF with `/OpenAction /URI (http://...)`; flags upload accepted (server-side PDF rendering = high risk) | CWE-918, CWE-829 | requires_post | 2 / 4 |
| 44 | `upload_zip_symlink` | T55 | Uploads ZIP containing symlink → `/etc/hostname`; if server extracts and serves, flags content of hostname returned | CWE-59, CWE-22 | requires_post | 4 / 6 |
| 45 | `upload_zipslip_traversal` | T56 | Uploads ZIP with entry `../round12_canary.txt`; afterwards fetches `/round12_canary.txt` to confirm extraction outside intended dir | CWE-22 | requires_post | 4 / 6 |
| 46 | `upload_imagemagick_mvg_canary` | T57 | Uploads 1KB MVG file referencing internal callback URL hosted by the scanner network (no internet egress); flags accepted-without-rejection AND optional callback hit | CWE-918, CWE-94 | requires_post | 2 / 4 |
| 47 | `upload_decompression_ratio` | T59 | Uploads 42-byte zip that expands to 4MB (tame, not 42.zip); flags successful processing without ratio rejection | CWE-409, CWE-770 | requires_post | 2 / 4 |

### 4.7 Cryptography (3 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 48 | `crypto_padding_oracle_aspnet_axd` | T62, T82 | Sends modified `WebResource.axd?d=` / `ScriptResource.axd?d=` requests; classifies responses as padding-valid vs padding-invalid; flags distinguishable oracle | CWE-209, CWE-310 | read-only | 12 / 20 |
| 49 | `crypto_timing_token_compare` | T67 | Sends 30 token-verification requests each with one byte mutated; flags significant timing difference (mean-stddev > 2x) — indicates `==` rather than constant-time compare | CWE-208 | read-only | 30 / 50 |
| 50 | `crypto_client_side_encryption_optional` | T70 | Pulls login JS, looks for client-side encrypt call; if found, sends a plaintext password via the same endpoint; flags 200 / authenticated | CWE-311, CWE-602 | requires_post | 4 / 8 |

### 4.8 Server Configuration (5 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 51 | `ssrf_metadata_endpoint_sweep` | T71 | Sweeps any URL-accepting parameter with: `http://169.254.169.254/latest/meta-data/`, `http://127.1`, `http://0.0.0.0`, `http://[::1]`, `http://2130706433` (decimal IP), `file:///etc/hostname`; flags reflected metadata content | CWE-918 | read-only | 12 / 20 |
| 52 | `info_powered_by_banner` | T76 | Inspects response headers for `Server:`, `X-Powered-By:`, `X-AspNet-Version:`, `X-AspNetMvc-Version:`, `X-Generator:`, `Via:` | CWE-200, CWE-209 | read-only | 2 / 3 |
| 53 | `info_git_directory_exposed` | T78 | Probes `/.git/HEAD`, `/.git/config`, `/.git/index`; flags Git-format response | CWE-538, CWE-540 | read-only | 4 / 6 |
| 54 | `info_svn_directory_exposed` | T78 | Probes `/.svn/entries`, `/.svn/wc.db`; flags SVN content | CWE-538 | read-only | 3 / 4 |
| 55 | `info_ide_metadata_exposed` | T78 | Probes `/.idea/workspace.xml`, `/.vscode/settings.json`, `/.DS_Store`, `/Thumbs.db` | CWE-538 | read-only | 4 / 6 |

### 4.9 Framework-Specific (8 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 56 | `dotnet_viewstate_unencrypted` | T81 | Fetches an `.aspx` page; pulls `__VIEWSTATE`; checks for unsigned/unencrypted (decodable to readable BinaryFormatter structure without MAC validation indicators) | CWE-345, CWE-502 | read-only | 4 / 6 |
| 57 | `dotnet_elmah_axd_exposed` | T75 | Probes `/elmah.axd`, `/elmah.axd/detail`; flags ELMAH error log accessible | CWE-538 | read-only | 3 / 4 |
| 58 | `dotnet_trace_axd_exposed` | T75 | Probes `/trace.axd`; flags ASP.NET trace log accessible | CWE-538 | read-only | 2 / 3 |
| 59 | `php_type_juggling_magic_hash` | T83 | POSTs login with known magic-hash MD5 candidates (`240610708`, `0e215962017`, etc.); flags 200 / authenticated | CWE-697, CWE-1023 | read-only | 6 / 10 |
| 60 | `php_array_param_strcmp_bypass` | T83 | POSTs login with `password[]=anything` / `username[]=admin`; flags 200 — indicates loose comparison or strcmp-with-array | CWE-697 | read-only | 4 / 6 |
| 61 | `php_object_injection_canary` | T84 | Sends serialized PHP object (`O:8:"stdClass":0:{}`) as cookie / param; flags PHP unserialize warning in body or behavioral change | CWE-502 | read-only | 4 / 6 |
| 62 | `tomcat_ghostcat_ajp_exposed` | T85 | Attempts TCP connect to port 8009 on the target host (capped to single connection, 2s timeout); flags reachable AJP | CWE-200, CWE-749 | read-only | 1 / 2 |
| 63 | `aem_dispatcher_selector_extension_bypass` | T87 | Tests `/content/page.html;%0a.css`, `/page.infinity.json`, `/page.1.json`, `/page.-1.json`, `/page.html?debug=true`; flags content disclosure | CWE-200, CWE-22 | read-only | 8 / 12 |
| 64 | `aem_user_enum_home_users` | T89 | Fetches `/home/users.1.json`, `/home/users/a.1.json`, `/etc.json`, `/libs.json`, `/var.1.json`; flags JSON user list | CWE-200 | read-only | 6 / 10 |
| 65 | `spring_actuator_exposed` | T90 | Probes `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops`, `/actuator/threaddump`, `/env`, `/trace`; flags 200 with actuator-shaped content | CWE-200, CWE-538 | read-only | 8 / 14 |

### 4.10 Client-Side (8 probes)

| # | Probe name | Maps to | Detects | CWE | Safety | Budget |
|---|---|---|---|---|---|---|
| 66 | `clientjs_dom_xss_sinks` | T91 | Pulls primary JS bundles linked from index.html; static-grep for sinks (`innerHTML`, `outerHTML`, `eval`, `document.write`, `Function(`, `setTimeout(<string>`, `location.href = <var>`); flags occurrences with neighboring user-input source | CWE-79 | read-only | 6 / 10 |
| 67 | `clientjs_postmessage_no_origin_check` | T92 | Static-grep JS for `addEventListener('message',` / `window.onmessage`; checks 30-line window for `e.origin ===` / `event.origin ===` strict equality; flags absence | CWE-345, CWE-940 | read-only | 4 / 6 |
| 68 | `clientjs_localstorage_sensitive` | T94 | Static-grep JS for `localStorage.setItem(` / `sessionStorage.setItem(` with keys matching `token`, `jwt`, `password`, `apiKey`, `secret`, `creditCard` | CWE-922, CWE-312 | read-only | 4 / 6 |
| 69 | `clientjs_jsonp_callback_reflected` | T96 | Probes endpoints with `?callback=alert(1)//` and `?jsonp=alert(1)//`; flags reflection in response body where Content-Type is js/jsonp | CWE-79 | read-only | 6 / 10 |
| 70 | `clientjs_crossdomain_xml_wildcard` | T97 | GETs `/crossdomain.xml`; flags `domain="*"` | CWE-942 | read-only | 1 / 2 |
| 71 | `clientjs_clientaccesspolicy_wildcard` | T97 | GETs `/clientaccesspolicy.xml`; flags `*` allow-from | CWE-942 | read-only | 1 / 2 |
| 72 | `clientjs_service_worker_scope` | T98 | Pulls `/sw.js` (and any registered SW path); flags broad scope (`/`) AND `importScripts()` over HTTP | CWE-913, CWE-829 | read-only | 3 / 5 |
| 73 | `clientjs_csp_unsafe_directives` | T100 | Parses CSP header into directives; flags `unsafe-inline` / `unsafe-eval` in `script-src`, missing `base-uri`, missing `object-src`, whitelisted-CDN known to host JSONP | CWE-1021 | read-only | 2 / 3 |

---

## 5. Total Request Budget Impact

Summed `request_budget_typical` for the 73 new probes ≈ **530 requests per
premium scan**. Current premium-profile budget is dominated by sqlmap/dalfox
(thousands of requests), so a +530-request increase is small (~3–5% of
typical premium-scan request count). Several probes (token-entropy,
race-condition, MFA-no-lockout) are bursty — those are capped with explicit
`request_budget_max` ceilings in their manifests.

---

## 6. Findings Parser Impact

`app/findings.parse_enhanced_testing` reads each probe's stdout JSON. New
probes will use the existing Verdict shape, so no parser changes are needed
except possibly:

- **CWE coverage:** the existing `app/findings.py` CWE → severity map should
  be checked against new CWEs introduced (e.g. CWE-176, CWE-409, CWE-840,
  CWE-1023). If any are unmapped they'll fall through to default severity.
  Confirm and extend the map as part of implementation.
- **Title dedup:** existing parser de-dups on probe name + URL. Several new
  probes produce per-URL findings (e.g. `info_powered_by_banner` runs once
  per discovered host), so the existing keying should be sufficient.

---

## 7. Implementation Roadmap

Suggested order — biggest signal first, lowest risk first:

**Phase 1 — read-only, high-value, low-effort (28 probes, ~1 day):**
T76, T78×3, T97×2, T100, T90, T75×2, T63, T64, T70, T39×2, T36, T38, T44×2,
T96, T98, T87, T89, T81, T75 elmah, T75 trace, T85, T62, T67

**Phase 2 — read-only, framework-specific (12 probes, ~1 day):**
T1+T69, T6, T7, T8, T14, T16, T17, T19, T33, T42, T71, T83×2, T84

**Phase 3 — `requires_post`, mutating but bounded (20 probes, ~2 days):**
T3, T4, T10×2, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30, T31,
T37, T47, T50, T57

**Phase 4 — file-upload class (6 probes, ~1 day):**
T51, T53/T60 merged, T54, T55, T56, T59

Each phase ships as one image rebuild (retag 2.1.1) + one master + 2.1.1
branch push. Per-phase rebuild lets you smoke-test premium scans against
Juice Shop / DVWA / WebGoat between phases.

---

## 8. Implementation Conventions (resolved)

- **Test accounts**: every `requires_post` probe takes a `--target-email`
  (or per-probe equivalent) flag defaulting to `admin@juice-sh.op`, matching
  the existing `auth_no_brute_force_lockout` pattern.
- **OOB callbacks**: not used. All detection is response-shape only —
  status codes, body content, headers, response timing — never relies on
  attacker-controlled DNS or HTTP callback infrastructure.
- **`app/findings.py`**: severity / OWASP entries added inline as each
  probe is wired up. Defaults to `medium` if a probe forgets `severity_uplift`.
- **Phasing**: all 73 probes ship in a single image rebuild (one retag of
  2.1.1, one push to master + 2.1.1 branches).
- **Ghostcat AJP probe**: uses Python stdlib `socket.create_connection` —
  same `Probe` subclass shape, just bypasses `SafeClient` for the TCP probe.

---

*End of plan.*
