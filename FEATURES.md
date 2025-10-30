# nextgen-dast 2.1.1 — Features

_Author: Tim Rice <tim.j.rice@hackrange.com>_

This document is the canonical inventory of every user-visible feature
in nextgen-dast 2.1.1. The companion document `HOWTO.md` covers the
operational steps to use them.

The product is a multi-tool, AI-assisted Dynamic Application Security
Testing (DAST) orchestrator. It pairs a battery of OSS scanners with a
high-fidelity probe framework (the *toolkit*) for false-positive
suppression, an authenticated-session capture layer for SSO targets,
software-composition analysis, and a PDF report generator. It ships as
a single Docker image plus a MariaDB sidecar.


## 1. Scanning engine

### 1.1 Scan profiles

Three profiles map to a fixed scanner sequence and depth:

| Profile     | Scanners run (in order)                                                                | Typical wall-clock |
|-------------|----------------------------------------------------------------------------------------|--------------------|
| `standard`  | sca → testssl → nuclei → nikto → wapiti                                                | 5–25 min           |
| `thorough`  | ffuf → sca → testssl → nuclei → nikto → wapiti                                         | 30–90 min          |
| `premium`   | ffuf → sca → testssl → nuclei → nikto → wapiti → sqlmap → dalfox → enhanced_testing    | 1–4 h              |

Scanner depth knobs (e.g. `nuclei` template tags, `nikto` plugin set,
`wapiti` module set, `testssl` checklist) are widened in the higher
profiles. `ffuf` runs first when present so SCA and the rest of the
pipeline can crawl ffuf's discovered paths.

### 1.2 Underlying scanners

| Scanner          | Purpose                                                          |
|------------------|------------------------------------------------------------------|
| **testssl.sh**   | TLS configuration audit (cert chain, ciphers, protocol versions) |
| **nuclei**       | Templated CVE / misconfig detection (community + custom)         |
| **nikto**        | Server / framework misconfiguration                              |
| **wapiti**       | Web-app fuzzing across XSS / SQLi / SSRF / etc.                  |
| **sqlmap**       | Confirmation + extraction on wapiti's SQLi candidates            |
| **dalfox**       | Reflected-XSS payload fuzzer                                     |
| **ffuf**         | Content discovery (vendored wordlists ship in image)             |
| **sca**          | Software-composition analysis (retire.js + osv-scanner)          |
| **enhanced_testing** | 55-probe deep checks (auth/authz/JWT/IDOR/SSRF/etc.)         |

### 1.3 Authenticated scanning

* Form-login support: stored `creds_username` + `creds_password` per
  assessment. `auth.form_login_cookie()` resolves a session cookie and
  every scanner inherits it for the run.
* HTTP basic-auth fallback when the login form fingerprint can't be
  detected.
* SSO targets (Okta / Azure AD / SAML / WS-Fed): solved via the
  capture-then-replay proxy — see §3.
* Per-assessment custom User-Agent — see §6.7.

### 1.4 Scope locking

Every scanner subprocess is fenced to the assessment's hostname via
the `scope` setting. Subdomain crawl-out is opt-in. Probes inherit
the same scope list and refuse to issue requests off-target.

### 1.5 Per-tool rate limiting

`max_rps` is enforced at the SafeClient layer that every probe shares,
and at the scanner spawn layer for tools that honor an upstream rate
flag. Default is 5 rps; configurable per-assessment.


## 2. Findings workflow

### 2.1 Three-column workspace (`/assessment/<id>`)

Per-assessment workspace with:

* **Left** — filterable, selectable findings list (status tabs, severity
  dropdown, sort, free-text title search, bulk-action toolbar).
* **Centre** — selected finding's detail panel (description, evidence
  URL, request/response capture, reproduce-&-verify steps).
* **Right** — *At a glance* card, validation card, PDF report card,
  underlying-scans block, action buttons (Test / Validate / Challenge).

Selection state lives in `location.hash` so refresh / back-button keep
the same finding visible.

### 2.2 Filter dropdown

Severity dropdown options:

* Critical / High / Medium / Low / Info (real severities)
* False positives (status pseudo-severity — overrides the Open/Closed/All
  tab and shows every suppressed finding)
* Resolved (status=fixed)
* Archive (status=accepted_risk)

### 2.3 Status tabs

* **Open** — `status IN ('open','confirmed')`
* **Closed** — everything else (false_positive, fixed, accepted_risk)
* **All** — every row

Counts are displayed live in each tab label.

### 2.4 Per-finding actions

| Button | What it does | Safety |
|--------|--------------|--------|
| **Test** | One-click, scope-locked live HTTP request from the reproduce modal. TLS-aware variants for `testssl` / cert findings. Nuclei findings replay via the matched template. | Read-only |
| **Validate** | Runs the matched **read-only** toolkit probe, shows a verdict (validated / not validated / inconclusive) and writes to `validation_evidence`. | Read-only |
| **Challenge** | Same as Validate, but for probes whose `safety_class` is not read-only — shows the real safety class, takes an analyst confirmation. | Per-probe |
| **Mark FP / Resolve / Archive / Reopen** | Manual triage outcomes that update `findings.status`. | Metadata only |

### 2.5 Bulk actions

* **Resolve** / **Archive** / **Delete** the checkboxed rows (any number).
* **Challenge all findings** — header button. Spawns
  `scripts.challenge_runner` over every open, unvalidated finding that
  has a matched probe; runs every probe class (including
  payload-injecting ones) after analyst confirmation.

### 2.6 Auto-validate at end of scan

The orchestrator's final step (after consolidation) runs
`challenge_runner --safe-only`. Every read-only probe that matches an
open finding fires; a verdict of `validated=False, confidence>=0.8`
auto-flips the finding to `status=false_positive`. Higher-risk probes
are reserved for the manual Challenge button.

### 2.7 Reproduce-&-verify panel

For every finding with a captured request/response, the panel renders:

* The `curl` reproduction command (one-line, scope-locked).
* The captured request and response (in modals, with a copy-to-clipboard
  affordance and a syntax highlight for JSON / HTML / XML bodies).
* A scrubbed view if the response contained captured credentials —
  passwords are masked in the on-screen view AND in the PDF.

### 2.8 Severity rollup + live risk score

* KPI strip on the assessment page: live risk score (`/100`), total
  findings, per-severity dot count, separate tiles for false-positive /
  resolved / archived.
* Triaged findings (FP / resolved / archived) are excluded from the
  rollup AND the live risk score so the score reflects the
  *currently-actionable* posture.
* "Hide info-severity findings" toggle persists per-assessment and
  affects the page AND the next generated PDF.


## 3. Capture-then-replay proxy

A pinned-port mitmproxy instance bundled into the image, used to
solve SSO targets that cannot be driven headlessly.

* **Reverse-proxy mode** (recommended for SAML): the analyst routes a
  test domain through the proxy port, completes the IdP challenge in
  a real browser, and the proxy captures the post-auth flow.
* **Forward-proxy mode**: classic browser proxy settings; useful for
  capturing arbitrary off-domain behaviour during a manual walkthrough.
* Captured cookies are converted into per-assessment `auth_profile`
  rows and become the session source for downstream scans (no
  per-run re-login).
* Per-flow detail page with request / response views, copy as `curl`,
  and "Send to scan" / "Send to challenge" buttons.

UI: `/proxy` (config + start/stop/clear), `/flows` (list), `/flow/<id>`.


## 4. Toolkit (validation probes)

A locally-developed probe framework runs adversarial-style checks
against a finding to confirm or refute it. Two pools:

### 4.1 Core toolkit (`/data/pentest/toolkit/probes`)

| Probe                  | Validates / Challenges                                          | Safety class       |
|------------------------|-----------------------------------------------------------------|--------------------|
| `admin_exposure`       | "Administrative interface exposed" — public vs auth-gated       | Read-only          |
| `breach_compression`   | Nikto BREACH precondition check (TLS + compression + reflection)| Read-only          |
| `cert_wildcard`        | Wildcard-cert findings (testssl `cert_trust_wildcard` family)   | Read-only          |
| `csrf_validation`      | Wapiti CSRF: cross-session token swap                           | Mutating (POST)    |
| `htaccess_bypass`      | Real bypass vs 404 / unrestricted / 401 / 403 / login-form 200  | Read-only          |
| `info_disclosure`      | Stack traces / secrets / debug pages in body or headers         | Read-only          |
| `login_page_check`     | Confirms a "login page found" candidate is a real login page    | Read-only          |
| `sca_finding_validate` | Diff banner-version vs CVE range/fixed-version (JS libraries)   | Read-only          |
| `sca_js_libraries`     | Initial detector — retire.js content-fingerprint sweep          | Read-only          |
| `sqli_boolean`         | Boolean-based SQLi via response-difference analysis             | Mutating (payloads)|
| `testssl_recheck`      | Re-runs testssl narrowly to confirm a HIGH/CRITICAL is current  | Read-only          |
| `xss_reflect`          | Reflected XSS via unique-nonce injection + context analysis     | Mutating (payloads)|

### 4.2 enhanced_testing pool (`/data/pentest/enhanced_testing/probes`)

55 deep-check probes invoked as the final scanner stage on the
`premium` profile. Probe families and counts:

| Family                                | Count | Examples                                                  |
|---------------------------------------|-------|-----------------------------------------------------------|
| `auth_*` (login / JWT / 2FA / OAuth)  | 14    | `auth_jwt_alg_none`, `auth_username_enum_timing`          |
| `authz_*` (IDOR / privilege boundary) | 12    | `authz_basket_idor_walk`, `authz_role_mass_assignment`    |
| `info_*` (info disclosure)            | 8     | `info_swagger_exposed`, `info_source_map_exposed`         |
| `config_*`                            | 3     | `config_cors_wildcard`, `config_hsts_missing`             |
| `nosql_*`                             | 2     | `nosql_review_dos_where`, `nosql_review_operator_injection` |
| `path_traversal_*`                    | 2     | `path_traversal_extension_bypass`, `path_traversal_ftp_download` |
| Single-issue probes                   | 14    | `xss_stored_lastloginip`, `ssrf_profile_image_url`, `xxe_file_upload`, `redirect_allowlist_bypass`, `redos_b2b_orderlines`, `cmdi_video_subtitles`, `ssti_pug_username`, `prototype_pollution_user_patch`, `deserialization_b2b_eval`, `deserialization_b2b_sandbox_escape`, `sca_runtime_check` |

### 4.3 Probe routing

A finding is matched to a probe by:

1. `(source_tool, cwe)` pair (e.g. nikto + CWE-200 → `info_disclosure`)
2. Title regex (e.g. titles starting with `jquery` → `sca_finding_validate`)
3. CWE alone, scoped to read-only probes

Top-level OWASP categories (e.g. "A05") in a probe's `validates`
list are filtered out of routing — they're catch-alls and would claim
every finding of the category.

### 4.4 Per-probe budget + safety class

Manifest fields enforce predictable behaviour:

* `request_budget_typical` / `request_budget_max` — request count caps
  enforced by SafeClient. Probe is killed on overrun.
* `safety_class` — `read-only` vs `mutating-readonly` vs `mutating`.
  Read-only is run automatically post-scan; the others require analyst
  confirmation in the modal.
* `requires_post` — gates probes that need a POST endpoint and refuses
  to run them on findings that lack one.


## 5. SCA — Software Composition Analysis

### 5.1 Detection stage

* Crawls the target's JavaScript surface using the assessment's known
  paths plus ffuf's discoveries.
* Runs **retire.js** with content-fingerprint signatures against every
  fetched JS asset. Signatures are loaded from
  `/opt/sca/retire/jsrepository.json` (baseline, baked into the image)
  with optional overlay at `/data/sca/retire/jsrepository.json`.
* Runs **osv-scanner** against any SBOM-like manifest (`package.json`,
  `package-lock.json`, etc.) the crawler finds.
* Each `(component, version, CVE)` tuple becomes one finding; library
  detections are info-severity, CVE matches inherit the advisory's
  severity.
* Results are cached by content hash for reuse across assessments and
  to keep retire.js / osv-scanner update churn off the hot path.

### 5.2 Validation stage

The `sca_finding_validate` probe (read-only) is auto-invoked at the
end of every scan against every SCA finding:

1. Fetch the cited JS file (one HTTP request).
2. Sniff version banner using a curated regex catalogue
   (jQuery / Bootstrap / Vue / React / Angular / Lodash / Moment / …)
   plus a generic banner sniff and a retire.js fallback.
3. Compare detected version to `vulnerable_range` and `fixed_version`
   from the cached vuln record.
4. Auto-flip the finding to `false_positive` when `confidence >= 0.8`
   and `validated=False`. Otherwise leave it for human triage.

### 5.3 SCA admin pages

* `/admin/sca` — signature DB status (last update, source, asset count).
* `/admin/sca/log` — raw retire.js / osv-scanner log.
* `/admin/sca/update` — manual signature refresh.
* `/admin/sca/vuln` — manual override or annotation of a specific CVE.
* `/admin/sca/config` — knobs for signature TTL, crawl depth, asset cap.


## 6. Reporting

### 6.1 PDF report

* One PDF per assessment, regenerable at any time.
* Filename: `<fqdn>_<YYYY-MM-DD>.pdf`.
* Tiered exploitability gate: high-risk findings escalate to a
  prominent "exploitable" callout when validation has confirmed them;
  unvalidated findings stay in their original severity.
* Captured-password masking: any credential captured during a scan is
  masked in the PDF (server-side scrub before render).
* Realistic overall grade: per-category cap, diminishing-returns curve,
  coverage bonus, validation-floor adjustment so the grade reflects
  *what's been validated*, not raw scanner output volume.
* Branded chrome (logo, classification footer, accent colors) — see §6.6.
* Print-readable link colour (default: navy blue) overridable via
  `pdf_link_color`.

### 6.2 CSV / JSON export

* Per-finding JSON via `GET /finding/<id>/export`.
* Bulk machine-readable view via the REST API (§7).

### 6.3 Trend chart (`/`, `/assessments`)

* Time-series chart of open findings per severity, per assessment.
* Dual-side Y-axis labels, hover tooltip, true-typeahead filter.
* Defaults to dropping info-severity from the trend so the chart
  reflects actionable risk only.

### 6.4 Live risk score

Computed on-the-fly from the current state of findings on every page
load. Excludes triaged outcomes (FP / fixed / accepted_risk). The
LLM-written value at consolidation time (`a.risk_score`) is preserved
for historical reference but no longer drives the UI.

### 6.5 "Resolved by age" card

Visualises how quickly findings move from open → resolved /
accepted_risk on each assessment. Helps surface stuck queues.

### 6.6 Branding

* Per-deployment branding: web logo, PDF logo, accent / primary colors,
  classification footer text, link colors.
* Logo upload supports PNG / SVG up to 1 MB; uploaded width is clamped
  for the sidebar render.
* Web and PDF brand surfaces are configured separately at
  `/admin/branding/web` and `/admin/branding/pdf`.

### 6.7 User Agents

`/user-agents` — manage the User-Agent strings used by scanners and
probes. Per-deployment default + per-assessment override. Useful when
a target is configured to allowlist a specific test agent.


## 7. REST API

Available under `/api/v1/*`, OpenAPI 3.1 at `/docs` (Swagger UI vendored
in-image — no outbound CDN). Postman collection at
`/api/v1/postman.json`.

### 7.1 Endpoints

| Method | Path                                  | Purpose                                            |
|--------|---------------------------------------|----------------------------------------------------|
| `POST` | `/api/v1/scans`                       | Kick off a new assessment                          |
| `GET`  | `/api/v1/scans`                       | List scans (filters: `fqdn`, status, profile)      |
| `GET`  | `/api/v1/scans/{id}`                  | Single-scan summary                                |
| `GET`  | `/api/v1/scans/{id}/results`          | Findings list (filters: `include_info`, `include_accepted_risk`) |
| `GET`  | `/api/v1/scans/{id}/report`           | Stream the PDF report                              |
| `POST` | `/api/v1/schedules`                   | Create a recurring schedule                        |
| `GET`  | `/api/v1/schedules`                   | List schedules                                     |
| `POST` | `/api/v1/schedules/{id}/run`          | Force-fire a schedule once now                     |
| `DEL`  | `/api/v1/schedules/{id}`              | Delete a schedule                                  |
| `GET`  | `/api/v1/postman.json`                | Postman v2.1 collection                            |

### 7.2 Tokens

* Per-token enable/disable + per-token `scope` (read-only, write).
* Token list / create / disable / delete in `/admin/api-tokens`.
* `application_id` field on assessments lets API callers reference
  external tickets (Jira / ServiceNow) without hard-coding the FQDN.


## 8. Schedules

Cron-driven recurring scans.

* Create / edit / pause / run-now / delete via `/schedules` and
  `/schedule/<id>`.
* `cron_expr` accepts standard 5-field cron; `start_after` defers the
  first fire.
* `keep_only_latest` flag auto-deletes prior assessments for the same
  target/profile so a daily schedule doesn't pile up duplicates.
* Server computes `next_run_at` server-side via croniter; UI shows it
  back to the user (no client-side cron parsing).
* All schedules surface in the global queue alongside ad-hoc scans.


## 9. Auth & multi-user

### 9.1 Authentication

* Form-login (`POST /login`) + session cookie (HMAC-signed via
  `APP_SECRET`).
* CSRF middleware on every state-changing endpoint.
* Audit log of state-changing actions (`audit` table).
* Blank-password footgun closed — `/setup` refuses to seed an empty
  password.

### 9.2 User roles

| Role | Capabilities                                                         |
|------|----------------------------------------------------------------------|
| `admin`  | Full read/write, schema admin, branding, API tokens, DB ops.     |
| `viewer` | Read-only view of assessments, findings, reports, trend charts.  |

### 9.3 User management (`/admin/users`)

* List all users with role + disabled flag.
* Create user, change role, disable / enable, force-reset password,
  delete.
* Per-user "change my password" flow at `/me/password`.


## 10. Database backup / restore

`/admin/database` — operator console for the running DB.

* **Backup** — `mariadb-dump`-style snapshot with `--max-allowed-packet=1G`
  (matched to the server's `--max_allowed_packet=1G`) so single
  multi-megabyte `raw_data` blobs never overflow.
* **List backups** — sortable list with size + timestamp.
* **Download** — gzipped `.sql.gz` over an authenticated route.
* **Delete**.
* **Restore** — uploads a `.sql` / `.sql.gz`, validates header/format,
  restores into the live DB. Refuses cross-major-version files.


## 11. LLM client

Pluggable LLM endpoint for two stages:

* **Consolidation** (post-scan): per-flow deep analysis + executive
  summary. Tier-1 = headlines only; Tier-2 = per-flow narrative with
  remediation and exploitability re-rating.
* **Enrichment**: per-finding extra context (background, business
  impact, suggested ticket title) on demand from the workspace panel.

Endpoints configured at `/llm`. Multiple endpoints can be registered;
the active one is selected per call. Per-finding enrichment can be
"locked" so the analyst's edits are not overwritten by a re-run.


## 12. Cleanup

* `/assessment/<id>/delete` — purges DB rows, scan output files, PDF
  reports, challenge logs, and the orchestrator log for that
  assessment.
* Periodic orphan sweep: removes scan files / log files whose
  assessment row has been deleted.
* DB row-level cleanup respects foreign-key shape and reaps in
  parent-first order.


## 13. CLI / Day-2 helpers (`pentest.sh`)

Wraps `docker compose` so the random env-file name doesn't have to be
remembered.

| Command          | Purpose                                                            |
|------------------|--------------------------------------------------------------------|
| `bootstrap`      | First-time setup: env file, build, start, run reset                |
| `reset`          | Re-seed admin password + write new secrets file                    |
| `reset-full`     | `TRUNCATE` every table first, then reset                           |
| `up` / `down`    | Compose passthrough                                                |
| `pull`           | Pull a newer image without bringing the stack down                 |
| `logs` / `ps`    | Compose passthrough                                                |
| `exec`           | Compose passthrough (run a command in the running container)       |
| `build`          | Compose passthrough (local rebuild — registry rebuild is separate) |
| `restart`        | Compose passthrough                                                |


## 14. Health + observability

* `/health` — JSON endpoint returning DB ping + scanner-binary
  availability. Cheap to poll from a probe / load balancer.
* `assessments.current_step` — one-line progress message updated by
  every stage of the orchestrator; surfaced in the assessment header
  badge so analysts see live progress without a log tail.
* `/scan/<id>/output` — raw scanner stdout, streamed.
* `/admin/sca/log` — SCA-specific log tail.
* Per-assessment orchestrator log on disk: `/data/logs/orchestrator_<id>.log`.
* Per-assessment challenge log: `/data/logs/challenge_all_<id>.log`.


## 15. Hardening posture

* Random env-file name (`/data/pentest/.env_<hex>`) so automated
  scrapers can't `find /data -name .env`.
* Secrets file at `/data/.sensitive_secrets_info_<hex>`, `chmod 600`.
* APP_SECRET (256-bit) is generated at bootstrap and never reused
  across deployments.
* Refuses to start with placeholder / weak values from `.env.example`.
* CSRF enforced on every POST.
* Per-route role gates (admin vs viewer).
* Probes default to read-only; mutating probes require explicit
  per-finding analyst confirmation.
* SafeClient enforces request budget + scope per probe; runaway probes
  are killed.


## 16. Image / deployment story

* Single image, single tag: `dockerregistry.fairtprm.com/nextgen-dast:2.1.1`.
* Image is **self-sufficient**: a registry pull on a fresh host with
  zero source files works.
* Vendored: ffuf wordlists, retire.js signature DB baseline, Swagger
  UI assets — no runtime CDN or registry dependency for normal
  operation.
* Compose stack: `nextgen-dast` (the image) + `mariadb:11`.
* Only `./data` is bind-mounted from host. `app/`, `toolkit/`,
  `scripts/`, and `db/` are baked via `COPY` so an image rebuild is
  required to ship code changes.


---

_Last updated: 2025-10-30. Tracking the same release line as the
companion `CHANGELOG.md`._
