# enhanced_testing — probe roadmap

_Author: Tim Rice <tim.j.rice@hackrange.com>_

Ordered by severity (most-serious first). Each item has a deterministic
detection signal verifiable against OWASP Juice Shop in
`tests/probe_stack.yml` — that's the bar for "high fidelity". Anything
fuzzy or LLM-judgment-dependent is intentionally not on this list.

> **Status legend** — `[ ]` not started, `[~]` in progress, `[x]` shipped.
> The trailing `→ probes/<file>.py` pointer is the implementation; the
> roadmap entry stays in the file as the spec the probe was written to.

## Reference probe

- [x] **info_directory_listing** → `probes/info_directory_listing.py` —
  generic web-server directory listing on `/ftp/`, `/uploads/`, `/backup/`,
  etc. (Juice Shop's `/ftp/` exposes acquisitions.md, eastere.gg,
  package.json.bak.) `Critical` → `validated=True` with confidence 0.95.
  Negative-tested against hardened nginx.

---

## Critical (15 probes — all shipped)

These produce immediate, exploitable consequences (account takeover,
RCE, full data extraction, or unauthenticated admin access).

- [x] **nosql_login_auth_bypass** → `probes/auth_nosql_login_bypass.py` —
  `POST /rest/user/login` with `{"email":{"$ne":"x"},"password":{"$ne":"x"}}`
  returns HTTP 200 with a JWT. Token presence on a typed-object payload
  = validated.
- [x] **login_sql_injection_auth_bypass** → `probes/auth_sql_login_bypass.py` —
  `POST /rest/user/login` with `{"email":"' OR 1=1--","password":"x"}`
  returns 200 + JWT *and the decoded JWT contains `data.role=="admin"`*.
- [x] **jwt_alg_none_accepted** → `probes/auth_jwt_alg_none.py` — Forge
  a token with `{"alg":"none"}`, marker email; `GET /rest/user/whoami`
  echoes the marker.
- [x] **jwt_rsa_to_hmac_key_confusion** → `probes/auth_jwt_rsa_hmac_confusion.py`
  — Fetch `/encryptionkeys/jwt.pub`, HMAC-sign with that PEM as the
  secret, replay against `/rest/user/whoami`.
- [x] **ssrf_profile_image_url_internal** → `probes/ssrf_profile_image_url.py`
  — Authenticated `POST /profile/image/url` with marker URL; verify
  via GET on /api/Users/<id>.
- [x] **xxe_file_upload_billion_laughs** → `probes/xxe_file_upload.py` —
  Multipart upload to `/file-upload` with `file:///etc/passwd` external
  entity; response contains `root:x:0:0`. Data-access form only.
- [x] **deserialization_b2b_order_rce_marker** →
  `probes/deserialization_b2b_eval.py` — `POST /b2b/v2/orders` with
  arithmetic IIFE; response echoes `1337`.
- [x] **deserialization_exec_javascript_sandbox** →
  `probes/deserialization_b2b_sandbox_escape.py` — vm2 / safe-eval
  sandbox escape via `this.constructor.constructor`.
- [x] **user_role_mass_assignment_admin_registration** →
  `probes/authz_role_mass_assignment.py` — `POST /api/Users` with
  `role: admin`; response confirms admin role on the new account.
- [x] **admin_section_force_browse** →
  `probes/authz_admin_section_force_browse.py` — Unauthenticated `GET
  /api/Users` returns the user list with email + password-hash fields.
- [x] **basket_idor_sequential_walk** → `probes/authz_basket_idor_walk.py`
  — Register user A; iterate `GET /rest/basket/{1..6}`; foreign basket
  with populated `Products` array confirms the IDOR.
- [x] **basket_manipulation_other_user** →
  `probes/authz_basket_manipulation.py` — `POST /api/BasketItems` with
  foreign `BasketId`; response stores the foreign id.
- [x] **oauth_password_derived_from_email** →
  `probes/auth_oauth_password_from_email.py` — Login with
  `password=base64(email)` for known OAuth-shaped accounts.
- [x] **exposed_encryptionkeys_directory** →
  `probes/info_key_material_exposed.py` — Named-path probe for keys
  material on /encryptionkeys, /keys, /id_rsa, etc.
- [x] **ftp_poison_null_byte_bypass** →
  `probes/path_traversal_extension_bypass.py` — `%2500.md` extension-
  allowlist bypass on /ftp/ and similar.

## High (24 probes — all shipped)

Either: (a) lead to data exfiltration / privilege escalation but
require an authenticated session first, or (b) are pre-conditions for
a Critical chain.

### Authorization / IDOR / BOLA

- [x] **feedback_idor_userid_assignment** →
  `probes/authz_feedback_userid_assignment.py` — `POST /api/Feedbacks`
  with foreign `UserId`; server stores the supplied id.
- [x] **five_star_feedback_admin_delete** →
  `probes/authz_feedback_delete.py` — Regular-user `DELETE
  /api/Feedbacks/<id>`. Off by default; `--allow-destroy` required.
- [x] **product_review_edit_other_user** →
  `probes/authz_product_review_edit.py` — `PATCH
  /rest/products/reviews` for a foreign review id. Off by default.
- [x] **address_idor_sequential_read** →
  `probes/authz_address_idor_walk.py` — Walk `GET /api/Addresss/{1..N}`.
- [x] **basket_checkout_arbitrary_user** →
  `probes/authz_basket_checkout_arbitrary.py` — `POST
  /rest/basket/<victim>/checkout`. Off by default.
- [x] **order_history_admin_view_all** →
  `probes/authz_order_history_view_all.py` — Regular user `GET
  /rest/order-history/orders` returns >1 distinct owner.
- [x] **http_method_override_admin** →
  `probes/authz_method_override_admin.py` — `POST /api/Users/<id>` +
  `X-HTTP-Method-Override: PATCH` with `role: admin`. Off by default.
- [x] **deluxe_membership_price_tamper** →
  `probes/authz_deluxe_membership_tamper.py` — `PATCH
  /api/Users/<own_id>` with `role: deluxe`. Off by default.
- [x] **user_email_change_other_account** →
  `probes/authz_user_email_change_other.py` — `PUT /api/Users/<other_id>`
  with marker email. Off by default.

### Authentication / session

- [x] **password_reset_weak_security_question** →
  `probes/auth_password_reset_weak_question.py` — Reset-password
  endpoint differential between right and wrong answers.
- [x] **jwt_unverified_email_claim_admin** →
  `probes/auth_jwt_unverified_email_admin.py` — alg=none JWT with
  known admin email accepted by whoami.
- [x] **default_admin_credentials** →
  `probes/auth_default_admin_credentials.py` — Documented seed
  credentials issuing an admin session.
- [x] **two_factor_setup_without_current_password** →
  `probes/auth_2fa_status_unauthenticated.py` — `GET /rest/2fa/status`
  reachable without auth.
- [x] **jwt_no_expiration_enforced** →
  `probes/auth_jwt_no_expiration.py` — Re-issue with past `exp`;
  also classifies `signature_not_verified` subclass.
- [x] **logout_does_not_invalidate_jwt** →
  `probes/auth_logout_does_not_invalidate.py` — Token still works
  after logout.

### Injection (long tail)

- [x] **nosql_orders_review_operator_injection** →
  `probes/nosql_review_operator_injection.py` — `id[$ne]=-1` on the
  reviews GET returns reviews spanning multiple product ids.
- [x] **nosql_orders_dos_where_payload** →
  `probes/nosql_review_dos_where.py` — Time-based `$where: sleep(1000)`
  delays the response.
- [x] **redos_b2b_orderlinesdata_regex** →
  `probes/redos_b2b_orderlines.py` — Catastrophic-backtracking payload
  on orderLinesData triggers >=1.5 s delay.
- [x] **prototype_pollution_sanitize_html** →
  `probes/prototype_pollution_user_patch.py` — `__proto__` payload
  leaks into an unrelated endpoint's response. Off by default.
- [x] **path_traversal_ftp_download** →
  `probes/path_traversal_ftp_download.py` — Named-file probe for
  /ftp leakage (companion to the generic extension-bypass probe).
- [x] **ssti_pug_user_email_username** →
  `probes/ssti_pug_username.py` — `#{7*191}` in the username field
  rendered as `1337`. Off by default.
- [x] **xss_rest_user_email_stored** →
  `probes/xss_stored_lastloginip.py` — `True-Client-IP: <iframe>`
  persists into the user record verbatim.
- [x] **command_injection_video_subtitle_path** →
  `probes/cmdi_video_subtitles.py` — `/video?subtitles=../../etc/passwd`
  returns `/etc/passwd` content.

### Modern-web / misconfig

- [x] **swagger_api_docs_unauthenticated** →
  `probes/info_swagger_exposed.py`.
- [x] **source_map_exposure_main_js** →
  `probes/info_source_map_exposed.py` — Parse the index page, fetch
  `<bundle>.js.map`, look for `webpack:///` markers.
- [x] **cors_wildcard_with_credentials_surface** →
  `probes/config_cors_wildcard.py`.
- [x] **redirect_allowlist_bypass_open_redirect** →
  `probes/redirect_allowlist_bypass.py` — Substring-allowlist smuggle.

## Medium (10 probes — all shipped)

Posture issues, anti-automation absence, and fingerprinting that don't
themselves grant access but lower the cost of every other attack.

- [x] **login_username_enumeration_via_oauth_branch** →
  `probes/auth_username_enum_timing.py` — Statistical timing
  differential between known and unknown emails.
- [x] **no_brute_force_lockout** →
  `probes/auth_no_brute_force_lockout.py` — N sequential failed
  logins, no 429 / Retry-After / lockout.
- [x] **session_cookie_missing_secure_httponly_samesite** →
  `probes/config_session_cookie_flags.py` — Trigger a login + audit
  every Set-Cookie line.
- [x] **password_change_missing_current_password** →
  `probes/auth_password_change_no_current.py` — Off by default.
- [x] **hsts_header_missing** →
  `probes/config_hsts_missing.py`.
- [x] **verbose_error_stack_trace_disclosure** →
  `probes/info_verbose_error.py`.
- [x] **exposed_metrics_prometheus** →
  `probes/info_metrics_exposed.py`.
- [x] **robots_txt_admin_path_leak** →
  `probes/info_robots_txt.py`.
- [x] **graphql_endpoint_fingerprint** →
  `probes/info_graphql_endpoint.py` — POST introspection query;
  asserts expected absence on Juice Shop, fires on real GraphQL.
- [x] **well_known_security_txt** →
  `probes/info_security_txt.py`.

---

## Implementation order (historical)

The roadmap was shipped over the following batches:

1. **Round 1 (info-disclosure family, 5 probes):**
   swagger_api_docs_unauthenticated, source_map_exposure_main_js,
   exposed_metrics_prometheus, verbose_error_stack_trace_disclosure,
   cors_wildcard_with_credentials_surface.

2. **Round 2 (auth/session, 5 probes):**
   default_admin_credentials, jwt_alg_none_accepted,
   jwt_unverified_email_claim_admin, jwt_rsa_to_hmac_key_confusion,
   no_brute_force_lockout.

3. **Round 3 (critical follow-on):** nosql_login_auth_bypass,
   login_sql_injection_auth_bypass, oauth_password_derived_from_email,
   nosql_orders_review_operator_injection, plus the SSRF/XXE/desserial
   /mass-assignment criticals.

4. **Round 4 (authorization/IDOR):** the basket / address / feedback /
   order-history family.

5. **Rounds 5-8:** auth/session, injection long tail, modern-web
   specifics, and medium-severity posture findings.

All roadmap items are now shipped. Each new probe lands in `probes/`
with a manifest, a row in `tests/test_round3_probes.py`, and an entry
in `scripts/orchestrator._PROBES_NEEDING_POST` if it issues non-GET
methods. New ideas should be added to this file as fresh `[ ]` entries
under a new "Backlog" section so the next batch has a clear next-up
list.
