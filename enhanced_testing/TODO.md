# enhanced_testing — probe roadmap

_Author: Tim Rice <tim.j.rice@hackrange.com>_

Ordered by severity (most-serious first). Each item has a deterministic
detection signal verifiable against OWASP Juice Shop in
`tests/probe_stack.yml` — that's the bar for "high fidelity". Anything
fuzzy or LLM-judgment-dependent is intentionally not on this list.

> **Status legend** — `[ ]` not started, `[~]` in progress, `[x]` shipped.
> Implemented probes move out of this file into `probes/` with a passing
> positive + negative test pair.

## Reference probe (already shipped)

- [x] **info_directory_listing** — generic web-server directory listing
  on `/ftp/`, `/uploads/`, `/backup/`, etc. (Juice Shop's `/ftp/`
  exposes acquisitions.md, eastere.gg, package.json.bak.) `Critical` →
  `validated=True` with confidence 0.95. Negative-tested against
  hardened nginx.

---

## Critical (15 probes)

These produce immediate, exploitable consequences (account takeover,
RCE, full data extraction, or unauthenticated admin access).

- [ ] **nosql_login_auth_bypass** — `POST /rest/user/login` with
  `{"email":{"$ne":"x"},"password":{"$ne":"x"}}` returns HTTP 200 with
  a JWT in `authentication.token`. Token presence on a typed-object
  payload = validated. *Why scanners miss it:* sqlmap mutates string
  payloads, never substitutes a `{"$ne":...}` operator object.
- [ ] **login_sql_injection_auth_bypass** — `POST /rest/user/login` with
  `{"email":"' OR 1=1--","password":"x"}` returns 200 + JWT *and the
  decoded JWT contains `data.role=="admin"`*. Pattern-match scanners
  flag the SQLi but don't follow up to confirm the issued token grants
  admin.
- [ ] **jwt_alg_none_accepted** — Forge a token with header
  `{"alg":"none"}` and payload `{"data":{"email":"jwtn3d@juice-sh.op"}}`,
  empty signature; `GET /rest/user/whoami` returns 200 with the forged
  email echoed in `user.email`. *Why scanners miss:* requires JWT
  synthesis + claim-to-response correlation.
- [ ] **jwt_rsa_to_hmac_key_confusion** — Fetch
  `/encryptionkeys/jwt.pub`, HMAC-sign a JWT using that PEM as the
  secret with `alg=HS256`, replay against `/rest/user/whoami`; HTTP
  200 + email echo = validated. Classic key-confusion attack.
- [ ] **ssrf_profile_image_url_internal** — Authenticated `POST
  /profile/image/url` with `imageUrl=http://169.254.169.254/...`; the
  server stores the URL on the user record. Validate via `GET
  /api/Users/<id>` → `profileImage` matches the supplied URL.
- [ ] **xxe_file_upload_billion_laughs** — Multipart upload to
  `/file-upload` with an `.xml` file containing `file:///etc/passwd`
  external entity; response body or error contains `root:x:0:0`. Use
  the data-access (file:///) form, not billion-laughs, to keep it
  non-destructive.
- [ ] **deserialization_b2b_order_rce_marker** — `POST /b2b/v2/orders`
  with `{"orderLinesData":"(function(){return 7*191})()"}`; the server
  evaluates via `vm` and the response echoes `1337`. Pure-arithmetic
  payload keeps it safe.
- [ ] **deserialization_exec_javascript_sandbox** — vm2 / safe-eval
  sandbox escape: `orderLinesData =
  "this.constructor.constructor('return 7*191')()"` → echoes `1337`.
- [ ] **user_role_mass_assignment_admin_registration** — `POST
  /api/Users` with `{"email":"<random>@probe.test", "password":"x",
  "role":"admin"}` returns 201 with `data.role=="admin"`. Random email
  per run keeps it idempotent.
- [ ] **admin_section_force_browse** — Unauthenticated `GET /api/Users`
  returns 200 with a JSON body containing `admin@juice-sh.op` and
  password hashes. Endpoint should require auth; that it doesn't is
  the textbook A01.
- [ ] **basket_idor_sequential_walk** — Register user A, login,
  iterate `GET /rest/basket/{1..6}` with A's token. At least one
  basket id returned has `data.id != caller_basket_id` and a populated
  `Products` array — i.e. another user's basket.
- [ ] **basket_manipulation_other_user** — Authenticated `POST
  /api/BasketItems` with `{"BasketId": <victim_basket_id>}` returns
  200 and the response's `data.BasketId` equals the victim id (server
  accepted a foreign-key field it should have overridden).
- [ ] **oauth_password_derived_from_email** — `POST /rest/user/login`
  with `{"email":"bjoern@owasp.org","password":"<base64('bjoern@owasp.org')>"}`
  returns 200 with a JWT for that account. App-specific OAuth fallback
  bug; no scanner has a signature for "password = base64(email)".
- [ ] **exposed_encryptionkeys_directory** — `GET /encryptionkeys/`
  returns 200 with a directory listing including `premium.key`. Probe
  could be a parameterised call into `info_directory_listing`, but the
  consequences here (encryption key exposure) merit a dedicated
  high-confidence probe with a narrower verdict.
- [ ] **ftp_poison_null_byte_bypass** — `GET
  /ftp/package.json.bak%2500.md` returns 200 with the actual
  `package.json` backup body (contains `"dependencies"`), while
  `/ftp/package.json.bak` returns 403. The `%2500.md` suffix bypasses
  the `.md/.pdf` extension allowlist — Juice-Shop-specific path
  pattern not in standard wordlists.

## High (24 probes)

Either: (a) lead to data exfiltration / privilege escalation but
require an authenticated session first, or (b) are pre-conditions for
a Critical chain.

### Authorization / IDOR / BOLA

- [ ] **feedback_idor_userid_assignment** — `POST /api/Feedbacks` as
  user A with `{"UserId": <other>}` returns 201 with `data.UserId ==
  <other>`. Server should override UserId from the session.
- [ ] **five_star_feedback_admin_delete** — `DELETE /api/Feedbacks/<id>`
  as a regular user returns 200 + `{"status":"success"}`. Subsequent
  GET confirms the row is gone. (Skip in CI to keep idempotent;
  guard with a sentinel review.)
- [ ] **product_review_edit_other_user** — `PATCH
  /rest/products/reviews` with `{"id":"<review_of_user_B>","message":"X"}`
  returns 200 + `modified:1`; subsequent GET shows the change applied.
- [ ] **address_idor_sequential_read** — Iterate `GET
  /api/Addresss/{1..20}` (note typo'd plural that evades wordlists);
  at least one entry returns 200 with `UserId != caller`.
- [ ] **basket_checkout_arbitrary_user** — `POST
  /rest/basket/<victim>/checkout` returns 200 with an
  `orderConfirmation` token. Path-parameter authz isn't compared
  against the caller's basket id.
- [ ] **order_history_admin_view_all** — Regular user `GET
  /rest/order-history/orders` returns orders with foreign emails.
- [ ] **http_method_override_admin** — `POST /api/Users/<id>` with
  `X-HTTP-Method-Override: PATCH` and `{"role":"admin"}` succeeds and
  the change persists on re-GET.
- [ ] **deluxe_membership_price_tamper** — `PATCH /api/Users/<own_id>`
  with `{"role":"deluxe"}` returns 200; `GET /rest/user/whoami` reflects
  `role:"deluxe"` on a free-tier account.
- [ ] **user_email_change_other_account** — `PUT /api/Users/<other_id>`
  with `{"email":"x@x.test"}` returns 200 + persisted email change.

### Authentication / session

- [ ] **password_reset_weak_security_question** — `POST
  /rest/user/reset-password` with `{"email":"jim@juice-sh.op","answer":"Samuel"}`
  (no `new` field) returns a different error than wrong-answer; the
  differential proves the answer was accepted. Idempotent because we
  don't supply `new`.
- [ ] **jwt_unverified_email_claim_admin** — Forge `alg=none` JWT with
  `data.email="admin@juice-sh.op"` and `role="admin"`; whoami echoes.
- [ ] **default_admin_credentials** — `POST /rest/user/login` with
  `admin@juice-sh.op / admin123` → 200 + JWT decoding to `role="admin"`.
- [ ] **two_factor_setup_without_current_password** — `GET
  /rest/2fa/status` returns 200 unauthenticated (should be 401).
- [ ] **jwt_no_expiration_enforced** — Server accepts a JWT with `exp`
  set to a past Unix timestamp.
- [ ] **logout_does_not_invalidate_jwt** — Login → whoami(200) →
  logout → whoami with same token returns 200 again.

### Injection (long tail)

- [ ] **nosql_orders_review_operator_injection** — `GET
  /rest/products/reviews?id[$ne]=-1` returns reviews from multiple
  distinct product IDs (>1 unique `product` value), proving operator
  injection.
- [ ] **nosql_orders_dos_where_payload** — Time-based: `PATCH
  /rest/products/reviews` with `{"message":{"$where":"sleep(2000)"}}`
  delays ≥1.8 s vs <300 ms baseline.
- [ ] **redos_b2b_orderlinesdata_regex** — Catastrophic-backtracking
  payload (≤55 chars) on `orderLinesData` produces ≥2 s delay vs
  <100 ms baseline.
- [ ] **prototype_pollution_sanitize_html** — `PUT /api/Users/<own_id>`
  with `{"__proto__":{"jsTpolluted":"YES_42"}}`, then `GET
  /rest/admin/application-version` → response includes the polluted
  property.
- [ ] **path_traversal_ftp_download** — `GET
  /ftp/coupons_2013.md.bak%2500.md` returns 200 with non-markdown
  content (covers both .bak and quote-bypass variants).
- [ ] **ssti_pug_user_email_username** — `PUT /api/Users/<own_id>`
  setting `username` to `#{7*191}`; subsequent GET returns the literal
  `1337`. Pug-specific interpolation that other SSTI fuzzers don't try.
- [ ] **xss_rest_user_email_stored** — `GET /rest/saveLoginIp` with
  header `True-Client-IP: <iframe src=...>`; later `GET
  /api/Users/<own_id>` echoes the literal payload in `lastLoginIp`.
- [ ] **command_injection_video_subtitle_path** — `GET
  /video?subtitles=../../../../etc/passwd` returns text/* with
  `root:x:0:0` in the body.

### Modern-web / misconfig

- [ ] **swagger_api_docs_unauthenticated** — `GET /api-docs/swagger.json`
  returns 200 with a valid `swagger`/`openapi` JSON enumerating internal
  admin routes.
- [ ] **source_map_exposure_main_js** — Parse the index page for
  `<script src="main.<hash>.js">`, then `GET
  /main.<hash>.js.map` returns 200 with `webpack:///` source paths.
- [ ] **cors_wildcard_with_credentials_surface** — `OPTIONS
  /rest/user/whoami` with `Origin: https://evil.example` returns
  `Access-Control-Allow-Origin: *` AND the endpoint accepts
  `Authorization`. Auth-bearing endpoint with `*` is the high-confidence
  finding.
- [ ] **redirect_allowlist_bypass_open_redirect** — `GET
  /redirect?to=https://github.com/bkimminich/juice-shop?pwned=https://evil.example`
  returns 302/200 redirecting to `evil.example`. Substring-allowlist
  bypass via embedded allowed URL.

## Medium (10 probes)

Posture issues, anti-automation absence, and fingerprinting that don't
themselves grant access but lower the cost of every other attack.

- [ ] **login_username_enumeration_via_oauth_branch** — Statistical
  timing differential (`mean(known)/mean(unknown) > 3x`,
  `unknown < 30 ms`) on `POST /rest/user/login` reveals which emails
  exist. Requires 5+ trials per branch.
- [ ] **no_brute_force_lockout** — 25 sequential failed logins for a
  known account all return 401 within 10 s; no 429, no `Retry-After`,
  no captcha, no IP block.
- [ ] **session_cookie_missing_secure_httponly_samesite** — Login
  flow's `Set-Cookie: token=...` lacks `HttpOnly` / `Secure` (when
  HTTPS) / `SameSite`. Auth-cookie-specific check; testssl/nikto
  inconsistently parse the multi-Set-Cookie case.
- [ ] **password_change_missing_current_password** — Register a
  throwaway user, then `GET /rest/user/change-password?new=...&repeat=...`
  with no `current` parameter returns 200. Throwaway → discardable.
- [ ] **hsts_header_missing** — `GET /` over HTTPS returns no
  `Strict-Transport-Security` header.
- [ ] **verbose_error_stack_trace_disclosure** — `GET
  /rest/products/search?q=%27` returns 500 with body containing
  `SQLITE_ERROR` and a Node stack trace with absolute paths
  (`/juice-shop/...`).
- [ ] **exposed_metrics_prometheus** — `GET /metrics` returns 200
  with Prometheus exposition format including `nodejs_version_info`
  and `app_name="juice-shop"`. Stack-fingerprint + workload telemetry
  leak.
- [ ] **robots_txt_admin_path_leak** — `GET /robots.txt` returns
  `Disallow: /ftp` — feeding directly into the directory-listing
  finding the reference probe already covers; correlate the two.
- [ ] **graphql_endpoint_fingerprint** — Both `/graphql` and
  `/api/graphql` return 404 on Juice Shop; probe asserts expected
  absence as a control test. (Inverts cleanly: a 200 with `__schema`
  on a different target = real finding.)
- [ ] **well_known_security_txt** — `GET /.well-known/security.txt`
  returns 200 with `Contact:`. Informational; flagged because
  `/.well-known/` is rarely enumerated and Juice Shop's challenge
  proves the file is reachable.

---

## Implementation order

Recommended ordering for the next batches:

1. **Round 1 (info-disclosure family, 5 probes):**
   `swagger_api_docs_unauthenticated`,
   `source_map_exposure_main_js`,
   `exposed_metrics_prometheus`,
   `verbose_error_stack_trace_disclosure`,
   `cors_wildcard_with_credentials_surface`. All are
   single-request, unauth, deterministic — perfect to validate the
   batch-scaling pattern after the reference probe lands.

2. **Round 2 (auth/session, 5 probes):**
   `default_admin_credentials`,
   `jwt_alg_none_accepted`,
   `jwt_unverified_email_claim_admin`,
   `jwt_rsa_to_hmac_key_confusion`,
   `no_brute_force_lockout`. Highest-impact auth class.

3. **Round 3 (NoSQL & login bypass):**
   `nosql_login_auth_bypass`,
   `login_sql_injection_auth_bypass`,
   `oauth_password_derived_from_email`,
   `nosql_orders_review_operator_injection`,
   `default_admin_credentials` (if not done).

4. **Round 4 (authorization/IDOR):** the basket / address /
   feedback / order-history family. Requires the multi-identity
   register-A-and-B harness pattern; one helper in `lib/` then ~6
   probes that lean on it.

5. **Rounds 5–N:** injection long tail, modern-web specifics, and
   the medium-severity posture findings.

The `premium` profile cuts public when the catalog hits ~25 probes;
each subsequent batch ships with the next image rebuild. Users on the
`premium` profile get coverage that grows automatically without
needing to re-pick a profile.
