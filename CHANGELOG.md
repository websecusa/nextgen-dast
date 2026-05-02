# Changelog

All notable changes to **nextgen-dast 2.1.1**.

This project ships from a single rolling `2.1.1` line — every entry
below is on that release. Items are grouped by the month they landed
in `master`; dates are the calendar date of the merging commit.

The format borrows from [Keep a Changelog](https://keepachangelog.com/),
adjusted for a rolling release where every change is folded into the
running 2.1.1 image at `dockerregistry.fairtprm.com/nextgen-dast:2.1.1`.

— Tim Rice <tim.j.rice@hackrange.com>


## 2025-04 — Bootstrap

- **2025-04-30** — Initial repository: orchestrator, FastAPI server,
  scanner runners (zap, nikto, testssl, nuclei, dalfox, ffuf-skeleton),
  MariaDB schema, and the pentest.sh controller.


## 2025-05 — Triage workflow lands

- **2025-05-02** — Tag the initial release as **2.1.1** and freeze
  the rolling line; image tag and git branch will not be bumped
  without explicit owner approval.
- **2025-05-04 / 05-05** — README cleanups (registry pull is public,
  drop noisy Support section).
- **2025-05-07** — **Challenge / False-Positive workflow** on the
  finding detail page. Per-finding "Challenge" button calls a matched
  toolkit probe and writes the verdict back to the finding row.
- **2025-05-09** — Authenticated Challenge: re-use the assessment's
  stored creds, run a dual-baseline (anonymous vs authenticated) probe
  so login-required findings are exercised correctly.
- **2025-05-11** — `htaccess_bypass` recognises the
  *200 + login form* anti-pattern as effectively-protected.
- **2025-05-12 / 05-14** — Exclude false-positive findings from the
  severity rollup and PDF report; surface them as a separate KPI tile
  on the assessment-detail page.
- **2025-05-16** — Final UK→US English sweep across UI, reports, and
  comments (catches the residual `-ise` / `-isation` forms).
- **2025-05-18** — **Bulk Challenge** button on the assessment page;
  high-confidence "not reproduced" verdicts auto-flip the finding to
  `status=false_positive`.
- **2025-05-20** — `testssl`: drop noisy "test does not apply on this
  host" WARN rows from the parsed findings.
- **2025-05-21** — PDF report: top-of-page placement, one report per
  assessment, `<fqdn>_<date>.pdf` naming.
- **2025-05-23** — Per-assessment **"hide info-severity findings"**
  toggle (persists; affects page AND PDF).
- **2025-05-25** — Orchestrator: fix `NameError` on the entrypoint
  path so queued assessments actually start.
- **2025-05-27** — `enhanced_testing/` scaffolding: reference probe
  + Juice Shop test fixture + 50-probe TODO roadmap.
- **2025-05-28** — Server reaps zombie assessments after a container
  restart so a crash mid-scan no longer leaves rows wedged in
  `running`.
- **2025-05-30** — **Premium profile**: 5 new probes, orchestrator
  wiring, UI exposure, schema migration.


## 2025-06 — Toolkit, ffuf, REST API

- **2025-06-01** — Orchestrator defaults `findings.evidence_url` to
  the scan target when a tool didn't emit one; breach-compression probe
  matches the bare "BREACH" finding title.
- **2025-06-03** — Re-add `premium` to the `/assess` profile validator
  after the previous tightening dropped it.
- **2025-06-05** — **Default-credential probes**: generic backbone +
  vendor-specific catalog (covers the most common admin / management
  endpoints).
- **2025-06-06** — Orchestrator: implement the `dalfox` case in
  `run_tool` so the scanner is actually scheduled (was previously a
  no-op).
- **2025-06-08** — Round-2 enhanced_testing probes: 5 new + parser
  wiring.
- **2025-06-10 / 06-12** — `htaccess_bypass`: manifest CLI-arg drift
  fix, US-English spelling cleanup.
- **2025-06-13 / 06-15** — **ffuf for content discovery** in the
  thorough + premium profiles, plus a vendored ffuf wordlist so an
  offline rebuild reproduces the same coverage.
- **2025-06-19** — `/assess` form: document `host:port` form in the
  FQDN field hint.
- **2025-06-20** — **REST API + `application_id` field + report
  polish.** Adds the `/api/scans` line of endpoints and gives every
  assessment a stable application identifier separate from the FQDN.
- **2025-06-22** — Vendor Swagger UI assets so `/docs` works with no
  outbound CDN dependency.
- **2025-06-24** — `/docs`: per-field help modal; `GET /scans` accepts
  an `fqdn` filter.
- **2025-06-26** — `GET /scans/{id}/results` accepts `include_info`
  filter.
- **2025-06-27** — Cleanup: deletion sweeps reports, challenge logs,
  and orphan files (the previous code only removed the DB rows).
- **2025-06-29** — **Modern dashboard shell** + `/` overview page.


## 2025-07 — Workspace UI + live risk score

- **2025-07-01** — **Three-column findings workspace** + tightened
  sidebar logo.
- **2025-07-03 / 07-04 / 07-06** — UI polish: oversized CTA icon fix,
  stale-CSS cache invalidation, select-all checkbox restored,
  Untitled UI stroke icons for Archive / Export.
- **2025-07-08** — `GET /scans/{id}/results` accepts
  `include_accepted_risk` filter (mirrors `include_info`).
- **2025-07-10** — `findings`: drop empty Dalfox results at parse
  time (the old behaviour wrote a bare row with no payload).
- **2025-07-12** — **`csrf_validation` probe** + per-manifest
  `requires_post` gate (probes that need a POST opt in explicitly).
- **2025-07-13** — Server: resolve relative `evidence_url` against the
  scan target before invoking probes.
- **2025-07-15** — **Live risk score**: recompute from the current
  state of findings, exclude `false_positive`/`fixed`/`accepted_risk`
  from the rollup.
- **2025-07-17 / 07-19** — Extend live risk + triage exclusion to the
  `/` dashboard and the `/assessments` listing page.
- **2025-07-20 / 07-22 / 07-24** — Trend chart + listing improvements:
  filter typeahead, drop info-severity from the chart by default,
  Resolved-by-age card, dual-side Y-axis labels, hover tooltip,
  legend below the date row.
- **2025-07-26** — Orchestrator: register `scan_id` with the
  assessment row before spawning the scanner subprocess (so a crash
  mid-spawn doesn't lose the link).
- **2025-07-27** — UI: stop assessment-row click from accidentally
  toggling its bulk-action checkbox.
- **2025-07-29** — `findings`: drop nikto end-of-scan summary lines
  from the parsed output.
- **2025-07-31** — **Reproduce-&-verify panel** with request /
  response modals on the finding detail page.


## 2025-08 — Validate / Test surface, login_page_check

- **2025-08-02** — `findings`: extract path prefix from nikto lines
  into `evidence_url` (was previously the bare host).
- **2025-08-04** — **Inline Validate button** + modal for read-only
  probes on the workspace panel.
- **2025-08-05** — **Auto-validate at end of scan**: orchestrator
  runs every read-only toolkit probe against its matched findings and
  auto-flips high-confidence FPs.
- **2025-08-07 / 08-09** — **Test button**: one-click, scope-locked
  live request from the reproduce modal; surfaced on the standalone
  finding page too.
- **2025-08-11 / 08-12 / 08-14** — Modal polish: surface the specific
  weakness + scan evidence; TLS-aware Test for `testssl` findings;
  collapse "Edit Guidance"; cert-info Test for non-testssl SSL/TLS
  findings.
- **2025-08-16** — Better validation for the
  *"Administrative interface exposed"* family.
- **2025-08-18** — Better validation + faster Test (TLS handshake-only
  path) for cert-shape findings.
- **2025-08-19** — **`login_page_check` probe** + tighten
  `admin_exposure` routing so admin findings are claimed by the right
  probe class.
- **2025-08-21 / 08-23** — Test (nuclei) for nuclei findings; suppress
  Nikto pre-scan noise; fix the case where Test refused finding 925
  because of an "is HTTP" mis-classification.
- **2025-08-25** — Toolkit: stop tier-2/3 routing on top-level OWASP
  categories (catch-alls were claiming everything).
- **2025-08-27** — UI: "Send to agent" button matches sibling action
  buttons; search-refraction icon.
- **2025-08-28** — `findings`: capture full request/response on
  default-cred hits + 75-pair catalog (so the reproduce-&-verify modal
  has actual evidence to render).
- **2025-08-30** — **DB backup/restore** + real reproduce-&-verify per
  source tool.


## 2025-09 — SCA, auth hardening, branding pass

- **2025-09-01** — Rewire enhanced_testing probes for Validate /
  Challenge + thorough SQLi walkthrough.
- **2025-09-03** — UI: Challenge button shows the real
  `safety_class` from the manifest (was hard-coded "Read-only").
- **2025-09-04** — Surface Challenge button + probe chip in the
  workspace panel.
- **2025-09-06 / 09-10** — Reproduce-&-verify steps and Challenge
  button align flush left.
- **2025-09-08** — **`testssl_recheck` probe** — Validate button on
  every TLS finding.
- **2025-09-12** — Tighten probe routing + surface the real Challenge
  reason in the verdict UI.
- **2025-09-13** — **Auth hardening**: CSRF middleware on every
  state-changing endpoint, audit log, close the blank-password
  footgun on `/setup`.
- **2025-09-15 / 09-17** — Report: PDF link color is print-readable
  blue (not the brand primary which can be unreadable on print);
  expose `pdf_link_color` as an explicit theming control.
- **2025-09-18** — `enhanced_testing`: every probe in the TODO.md
  roadmap is now shipped.
- **2025-09-20** — **Rename pentest-proxy → nextgen-dast.** Drop the
  bootstrap-creds hint banner now that the seeded password is shown
  once via `pentest.sh reset` only.
- **2025-09-22** — Report: drop the inline color override on
  reference links so they pick up the print-readable theme variable.
- **2025-09-24** — **SCA stage**: software-composition analysis with
  retire.js + osv-scanner + LLM cache (vulnerable JS / npm libraries
  detected per scan, cached by content hash).
- **2025-09-26** — SCA: escape literal `%` in `LIKE` patterns for
  PyMySQL formatting.
- **2025-09-27** — SCA: broaden the JS-asset crawl, content
  fingerprint match, suppress noise rows that always reproduce.
- **2025-09-29** — Report: realistic overall grade — per-category cap,
  diminishing returns, coverage bonus, validation floor.


## 2025-10 — SCA validation, schedules, branding

- **2025-10-01** — Report: tiered exploitability gate + captured
  password masking in the PDF.
- **2025-10-03** — **`sca_finding_validate` probe**: targeted
  validation that fetches the cited JS file and compares the banner
  version to the CVE's vulnerable range. Useful PDF reproduction for
  SCA findings now embeds the diff.
- **2025-10-05** — `sca_js_libraries`: fix `Response` attribute names
  (`.status` / `.body`, not `.status_code` / `.content`).
- **2025-10-06** — **Challenge All button** + **False positives**
  filter option on the assessment-detail page. Adds a one-click bulk
  Challenge that runs every matched probe class (including the
  payload-injecting probes), and a pseudo-severity in the filter
  dropdown that lists every suppressed finding regardless of the
  Open/Closed/All tab.
- **2025-10-08** — **Cron-driven schedules**: per-assessment cron
  schedule + `keep_only_latest` auto-dedupe so a recurring scan
  doesn't pile up duplicate rows.
- **2025-10-10** — Docs: expand `pentest.sh` Day-2 reference with the
  full operations table.
- **2025-10-11 / 10-13 / 10-15 / 10-17** — **Branding pass**:
  optional classification footer, auto-heal schema for new branding
  columns, logo redirect fix; surface the web logo on sidebar +
  login; clamp uploaded-logo width; harden icon + sidebar-logo
  sizing against missing or blocked CSS.
- **2025-10-19** — Bulk-challenge runner re-runs `errored` /
  `inconclusive` rows (not just unvalidated); modal delete confirm
  replaces `window.confirm()`.
- **2025-10-20 / 10-22** — Sidebar: stack brand logo above company
  name, then center the pair.
- **2025-10-24 / 10-26** — Rename "Send to agent" → "Challenge";
  Font Awesome scale-balanced icon; inline Challenge button (no
  confirm popup, in-place status badge).
- **2025-10-28** — Assessment filter dropdown: "Resolved"
  pseudo-severity (separate from severities, filters by status).
- **2025-10-29** — Assessment filter dropdown: "Fixed" and
  "Archive (accepted risk)" join Resolved as pseudo-severities.


## 2026-05 — High-fidelity CSRF rule, anomaly_5xx_validation, 404 short-circuits, Re-scan prefill

- **2026-05-02** — **Enhanced-AI weakness-discovery: 10 additional
  scenarios.** Doubled the seeded weakness-discovery roster from 10
  to 20 to cover attack classes off-the-shelf DAST engines either
  skip outright or score one finding at a time. New scenarios:
  Sensitive File and Backup Artifact Exposure (stack-aware: AEM
  `?.json`, `wp-config.php.bak`, `.git/`, `dump.sql`, etc.); Exposed
  Admin Panels and Management Consoles (cPanel, WHM, Plesk, Webmin,
  Tomcat Manager, JBoss, phpMyAdmin, Adminer, Spring Actuator,
  Jenkins, Solr, Kibana, PgAdmin, RabbitMQ, Consul, k8s Dashboard,
  with default-credential analysis); Hardcoded Secrets and Tokens in
  Captured Responses (greps Wapiti / Nikto / Nuclei response bodies
  for AWS/GCP/Azure keys, SaaS tokens, JWTs with alg/iss decode,
  DSNs, private keys, PII — redacts the secret in the stored finding
  so we don't leak it twice); Verbose Error and Debug-Mode Disclosure
  (Werkzeug, Symfony profiler, Rails, Django, ASP.NET YSOD, Spring
  whitelabel, AEM Sling, GraphQL stack traces); HTTP Cache Poisoning
  and Web Cache Deception; Holistic Cookie / CORS / CSP Architecture
  (scores headers as a system, escalates when combinations enable
  chains); Subdomain Takeover and Dangling DNS Resources; HTTP
  Request Smuggling, Desync, and Header Trust Boundary; Insecure
  Deserialization Surface Detection (Java rO0AB, .NET ViewState,
  PHP `O:`, Python pickle, Ruby Marshal, Node node-serialize, YAML);
  CMS and Off-the-Shelf Stack Anti-Patterns with explicit AEM
  coverage. All 10 fire unconditionally on every scan; operators can
  disable individual rows in /admin/ai-prompts when token cost
  matters. No schema change — existing 2.1.1 databases pick up the
  new rows automatically via `seed_defaults_if_empty` on next boot
  (matched by slot+name, missing rows inserted, existing untouched).
  Doc comment in `db/schema.sql` updated from "11 default rows" to
  "21 default rows" (20 weakness + 1 fidelity).
- **2026-05-02** — **Enhanced-AI anti-hallucination guard +
  SPA-fallback fingerprinter.** Two paired guards on the
  `enhanced_ai_testing` weakness-discovery pass to suppress the
  largest false-positive class we have seen in the wild: a
  CDN-fronted SPA that returns the same `index.html` (HTTP 200) for
  every unmatched path, which lets path-presence scanners (nikto and
  similar) report "X admin interface identified at /X.jsp" purely
  because the path 200s — and the LLM weakness pass then escalates
  that into a CVE chain. (1) New `app/spa_fallback.py` probes
  random junk paths on each unique target host once per run and
  caches a body signature; the renderer tags any
  `evidence_url` whose body matches the signature with
  `[SPA-FALLBACK ECHO]`, and a new `{spa_fallback_warning}`
  placeholder lists affected hosts in a dedicated prompt block.
  (2) New `_filter_hallucinations` step in `enhanced_ai.py` runs
  before insertion: every LLM-emitted finding's `evidence` field
  must be a verbatim (whitespace-normalized, case-insensitive)
  substring of the rendered input corpus, OR the finding is
  dropped as ungrounded. Findings whose URLs match the SPA-fallback
  signature are also dropped. A runtime safety preamble
  (`_RUNTIME_SAFETY_PREAMBLE`) is prepended to every
  weakness-discovery user prompt so the rules apply even when an
  operator has customized the system prompt or removed the
  placeholder from the user template. The seed `HEADER` in
  `enhanced_ai_prompts.py` also gains four new G1-G4 grounding
  rules (verbatim quote, "200 OK is not evidence", no
  cross-tool escalation, SPA-fallback URLs carry no signal); existing
  installs pick these up via `Restore to default` on the AI-Prompts
  admin page, but the runtime preamble enforces the same floor
  unconditionally. New `spa_fallback_warning` placeholder is
  registered in `PLACEHOLDERS_BY_SLOT` so the AI-Prompts editor
  recognizes it.

- **2026-05-02** — **Theme toggle (Dark / Light), per-user
  persistence.** New `theme` column on the `users` table (enum
  `dark`/`light`, default `dark`) plus a `/theme` page reachable
  from a new sidebar entry below API tokens. Selection saves
  server-side so it follows the analyst across browsers without
  any client-side cookie. `body class="theme-{{ user_theme }}"` on
  every render swaps the CSS variable palette so existing
  components inherit the new colors automatically; severity colors
  stay constant across themes for accessibility. Schema additions
  are idempotent (the canonical CREATE block carries the column,
  the legacy ALTER ADD COLUMN IF NOT EXISTS path covers older DBs,
  and `verify_schema.py` learns about the new column for the
  startup-time drift heal).

- **2026-05-02** — **PDF narrative excludes triaged findings.**
  Two pieces. (1) `consolidation._fetch_buckets` now filters out
  rows with `status IN ('false_positive','fixed','accepted_risk')`
  before handing the bucket list to the LLM that writes the
  executive narrative. At first-run consolidation (immediately
  after a scan) nothing is triaged, so this is a no-op; on a
  re-run the LLM only sees what the analyst still considers
  actionable. (2) `reports.generate()` now calls a new
  `_refresh_narrative_if_stale()` helper before rendering the PDF
  template. When any finding has been triaged since the cached
  `exec_summary` was written, consolidation is re-run so the
  narrative matches the live finding list the rest of the report
  shows. Best-effort: skipped cleanly when no LLM endpoint is
  configured or the API is unreachable, so PDFs still render with
  the cached narrative in degraded paths.

- **2026-05-02** — **Letter-grade column on Assessments tables.**
  New `Grade` column on both the dashboard's Assessments card and
  the standalone `/assessments` listing. A new `_score_to_grade()`
  helper maps the live 0-100 risk score to A/B/C/D/F; the badge
  reuses the existing severity-tier color palette so an A is the
  same green as info, an F is the same red as critical. Mapping
  is 0-19 → A, 20-39 → B, 40-59 → C, 60-79 → D, 80-100 → F. Each
  row carries a `grade` dict (`{letter, cls}`) so the template
  can render `<span class="sev sev-{{ grade.cls }}">{{ letter
  }}</span>` without recomputing thresholds.

- **2026-05-02** — **Main column fills viewport.** Removed the
  hard `max-width: 1400px` cap on `main.main`. On wider displays
  the dashboard now uses the full width between the 240-px sidebar
  and the right edge instead of leaving dead space. The padding
  rule and per-card internal layouts are unchanged so readable
  line lengths inside cards stay consistent.

- **2026-05-02** — **Filter-row layout: dropdowns left, search
  right.** Two pieces of feedback on the previous Assessments
  layout: (1) the status / page-size / Apply controls were
  rendering *under* the search field on narrow viewports because
  flex-wrap kicked in once the form's intrinsic width exceeded the
  card-header's slack, and (2) the search field was too narrow for
  customer FQDNs that routinely run 30+ characters. Reordered the
  form children so the dropdowns + Apply sit first, with the search
  input pushed to the right via `margin-left: auto` on its wrapper.
  Wrapped the input in a new `.typeahead-wrap` span that owns its
  own `position: relative`, so the typeahead suggestion popup
  anchors directly under the input regardless of where the input
  lives in the row (previously the popup anchored to the form's
  left edge). Suggestion popup now also takes `width: 100%` of its
  wrapper so it visually matches the input's footprint. Search
  input widened from 200 px to 320 px in the Assessments filter
  context; the trend-chart filter keeps its 240-px default. Cache
  buster bumped to 20260502b.

- **2026-05-02** — **Filter-row spacing + /assessments parity.**
  Two follow-ups to the dashboard overhaul. (1) The Assessments
  filter row (FQDN search, status dropdown, page-size dropdown,
  Apply button) now stays on a single line via
  `flex-wrap: nowrap` on `.assessments-filter`, with a matching
  ghost style applied to the `<select>` controls so they line up
  visually with the input on the left and the Apply button on the
  right. The card header itself can wrap below the h2 on narrow
  viewports without splitting the form's children. (2) The
  standalone `/assessments` page now uses the same
  `_assessments_table_data` helper as the dashboard card, picking
  up the typeahead FQDN search, status filter, 25/50/100 page-size
  selector, sortable columns, and pagination. The standalone page's
  query params are NOT prefixed with `a_` because there's no second
  form on the page to disambiguate from. The Delete button and LLM-
  tier column are preserved.

- **2026-05-02** — **Dashboard UX overhaul.** Five related changes
  to the / page and the left nav: (a) the **PLATFORM** section
  header in the sidebar is gone and the first nav entry was renamed
  from **Overview** to **Dashboard** (URL stays `/`). (b) The
  **Unresolved findings by age** and **Resolved findings by age**
  cards now share a row in a 2-col `.grid` so they stop stacking
  full-width and reclaim vertical real estate. (c) The trend chart
  is now titled **Risk Trending** and exposes a window selector with
  7 / 14 / 21 / 30-day options; the server-side helper accepts a
  `trend_days` parameter (whitelisted, clamps to 30) and the SQL
  / day-list both honor it. (d) The bottom **Recent assessments**
  card was renamed to **Assessments** and grew real filtering: a
  typeahead FQDN search (reusing the existing `form.typeahead` JS
  hook so no new client code), a status dropdown (Done, Running,
  Queued, etc.), a 25 / 50 / 100 page-size selector, and pagination
  links. (e) Five sortable columns — ID, Target, App, Profile,
  Status, When — toggle direction on click; the active column lights
  up its arrow indicator. Open and Risk are intentionally not
  sortable because their values come from a per-assessment live
  finding aggregate that SQL ORDER BY cannot rank consistently
  across pages. All Assessments-table query params are namespaced
  with `a_` so the chart filter form and the table form can coexist
  in the same URL without clobbering each other. Sortable columns
  are validated against an allowlist (`_ASSESSMENTS_SORT_COLUMNS`)
  before reaching the SQL ORDER BY.

- **2026-05-02** — **Removed Target Security card from the
  dashboard.** The two-column row at the bottom of the index page
  used to pair "Target Security" (top six targets by live risk
  score) with "Unresolved findings by age". The targets card
  duplicated information already accessible from the assessments
  list and KPI strip; removing it lets the age matrix run full
  width and matches the layout of the Resolved-by-age card right
  below it. Dropped: the `target_rows` query and `targets` key in
  `_dashboard_data`, the surrounding `<div class="grid">` wrapper,
  and the corresponding section in `templates/index.html`. The
  layout comment at the top of `index.html` was updated to match.

- **2026-05-02** — **Wapiti `--max-scan-time` raised from 4 h to
  12 h.** The previous 14400-second ceiling was clipping deep
  authenticated runs against larger customer surfaces, which then
  surfaced as truncated wapiti reports without a clear "we hit our
  cap" signal in the assessment. Per-attack cap stays at 30 min
  (`--max-attack-time 1800`); only the whole-scan ceiling moves to
  43200 s.

- **2026-05-02** — **`sca_finding_validate` quality pass — three
  bugs surfaced while re-validating the assessment 31 SCA findings.**
  (1) **Phantom detection**: when the named component (e.g.
  bootstrap) was in the regex catalog and its dedicated regex did
  not match the file, `_detect_version` fell through to "try every
  other regex" and returned the first hit — typically jQuery's
  banner from the same multi-library bundle, mislabeled as the
  named component's version. The verdict surfaced as e.g. "detected
  bootstrap 3.7.1" which does not exist as a release. Step 2 is now
  gated: it runs only when the component name is NOT in the catalog
  (the original "alias resolution" use case); for catalog-known
  components a regex miss now falls through to the component-scoped
  generic banner, then retire.js, and finally returns None so the
  verdict cleanly flags "no validation evidence". (2) **Head window
  too small for bundle files**: the previous 8 KB cap covered
  single-library JS files but missed Bootstrap's banner buried 600+
  KB into a real-world `core.min.js`. Raised to 1 MiB; the regex
  pass stays cheap on full-file scans. (3) **OSV vulnerability data
  never extracted**: `_enrich_from_raw_data` only read
  `raw_data.cached_vuln`, the retire.js / LLM-augmented shape. OSV-
  scanner stores under `raw_data.vulnerability` with a structured
  affected/ranges/events tree, so every OSV-derived finding entered
  the probe with empty `fixed_version` / `vulnerable_range` /
  `cve_id` and the comparator returned "could not determine". Added
  a `_derive_osv_range()` helper that walks affected[] entries
  (matching by ecosystem + name, with npm/SEMVER aliasing), picks
  the range whose [introduced, fixed) interval contains the
  detected version (two-pass: targeted match wins over best-effort
  first range), and emits a SemVer string the existing
  `_matches_range` accepts. CVE id resolves to the first `CVE-…`
  alias, falling back to the OSV / GHSA id. Net effect: OSV
  findings now get real range / fixed / CVE data and produce
  validated / false-positive verdicts where they used to land at
  inconclusive.

- **2026-05-02** — **`fire_when` short-circuit parser bug** — the
  expression evaluator at `evaluate_fire_when()` combined parsed
  operands with Python's native `and` / `or`, which short-circuit.
  When the left operand of an `AND` evaluated False (or the left
  operand of an `OR` evaluated True), Python skipped the right
  operand's `parse_atom()` call entirely, leaving its tokens
  un-consumed. The terminal check at the end of `parse_or` then
  raised `trailing tokens after expression` and the whole
  fire_when returned False, silently dropping the scenario from the
  weakness-discovery loop. On advanced-tier scans this skipped
  any scenario whose fire_when contained `<flag> AND <comparison>`
  unless every preceding flag in the chain happened to be true.
  Fixed by parsing the right operand into a local before the
  boolean combine, so token consumption is independent of the
  running boolean value. Added a 14-case unit test fixture covering
  AND / OR short-circuits in both directions, three-way chains,
  and parenthesised groups.

- **2026-05-02** — **Enhanced AI weakness-discovery prompt
  rendering** — the per-scenario `system_prompt` rows in `ai_prompts`
  carry a literal JSON example (single `{`/`}` braces) showing the
  expected response shape. The runtime used to call
  `str.format_map()` on the stored prompt to substitute `{fqdn}`,
  which mistook the JSON example for a Python format field and
  raised `ValueError: Invalid format specifier`. Every weakness
  scenario crashed and the run aborted with `enhanced_ai_testing
  crashed: ...` in the assessment's `error_text`. Switched the
  substitution to a literal `str.replace("{fqdn}", ...)` so the
  format mini-language is no longer involved — JSON example braces
  and any operator-pasted content stay inert.

- **2026-05-02** — **SCA evidence URL preserved through synthetic
  lockfile path** — when osv-scanner runs against the synthetic
  `package-lock.json` we generate from content-fingerprint hits,
  every produced finding used to record `evidence_url` as the bare
  target hostname (the synthetic manifest_hits entry was registered
  with `url=target`). The `sca_finding_validate` probe then refetched
  the homepage HTML, found no JS banner, and returned an
  inconclusive verdict for libraries we knew exactly which JS file
  contained. `scripts/sca_runner.py` now builds a
  `(ecosystem, name, version) -> source_url` map from the
  fingerprint results and rewrites the synthetic-derived OSV
  records' `manifest_url` to the real on-target asset before
  normalization. New scans get accurate `evidence_url` values; the
  validate probe lands on the right file on the first try.

- **2026-05-02** — **`sca_finding_validate` HTML fan-out and
  no-proof verdicts** — when the URL handed to the probe resolves
  to an HTML page (legacy data with bare-hostname `evidence_url`,
  or any case where SCA pointed at a wrapper page), the probe now
  parses `<script src=...>` attributes and follows up to five
  candidate scripts within its existing 6-request budget, sniffing
  each for the named component before concluding. When no banner
  is recoverable from any followed script, the verdict's summary
  is reworded from "Original SCA finding stands; manual review
  needed" to an explicit "no validation evidence" framing that
  surfaces in the validation_notes column, and the evidence block
  records a `scripts_checked` list so the audit trail shows every
  asset the probe inspected.

- **2026-05-01** — **Re-scan button prefill** — the "Re-scan / new
  target" link on the assessment detail page is renamed to
  **Re-scan** and now carries `?from=<aid>`. The `/assess` GET
  handler reads the source assessment and pre-populates the form
  with the prior scan's settings: FQDN, application id, schemes
  (http/https), profile, LLM tier + endpoint, user-agent, login
  URL, creds_username, and keep-only-latest. The credentials
  password is **never** echoed into the DOM. When the source
  assessment has a stored password the field shows a fixed-length
  asterisk sentinel as a visual cue, plus a hidden
  `prefill_creds_from=<aid>` token; the POST handler resolves the
  stored password server-side from the source assessment, but
  only after verifying the source FQDN matches the FQDN being
  scanned (so a tampered token cannot pull another target's
  credentials). The user can leave the sentinel intact (use stored
  password), clear the field (anonymous re-scan), or type a new
  password (override the stored one). The greenfield "Assess a
  target" path is unchanged when no `from` parameter is supplied.


- **2026-05-01** — **`admin_exposure` v1.2** and **`info_disclosure`
  v1.2** — add 404 short-circuits. When a discovery scanner (ffuf,
  nikto) flags a path as "admin path discovered" or "configuration /
  metadata path discovered" but the URL now returns HTTP 404, the
  path does not exist and the finding is a definitive false
  positive (commonly a stale hit from an earlier deployment, or a
  custom 404 that the scanner mis-scored). Both probes now return
  `validated=False` at confidence 0.95 in this case (maps cleanly
  to `false_positive`) instead of falling through to the catch-all
  `inconclusive` branch. Also: `info_disclosure` now upgrades the
  no-disclosure-markers verdict to confidence 0.9 when the response
  status is 401/403 (the path is access-controlled and the body we
  CAN see has no markers — definitively not disclosure), keeping
  the older 0.7 confidence only on 200 responses where the catalog
  may still miss subtle leaks.


- **2026-05-01** — **`anomaly_5xx_validation` probe v1.0** — new
  validator for wapiti / nuclei / nikto "anomaly: Internal Server
  Error" findings. Replays the captured HTTP request, scans the
  5xx response body for real information disclosure (stack traces,
  framework banners, internal paths, SQL errors), and uses a
  same-wire-length benign control payload to disambiguate
  content-driven 5xx (a real robustness bug) from upstream buffer
  / proxy header overflow (the common false-positive mode where a
  long parameter is reflected into a redirect Location header that
  exceeds nginx's proxy_buffer_size).
  - Module-aware sanity: `file`-module / LFI findings against a
    Python / Node / Java stack also note that `php://filter`
    chains are semantically impossible regardless of the 5xx
    behaviour.
  - Sizes the control payload by the parameter's WIRE length
    (url-encoded bytes), not its decoded length, since the
    upstream-buffer overflow is triggered by encoded bytes.
  - Routed via `matches_titles` for "anomaly: Internal Server
    Error", "anomaly: 502 Bad Gateway", etc. and via
    `matches_tools` (wapiti / nuclei / nikto) so multi-tool
    pipelines all hit it.

- **2026-05-01** — **`csrf_validation` probe v1.2** — full rewrite
  of the verdict logic so wapiti CSRF findings are no longer left
  `inconclusive` when the form has no synchronizer token.
  - Drop the "first hidden field is the token" fallback that
    mis-identified post-login redirect inputs (`next`, `redirect_to`)
    as CSRF tokens, then bailed when they were empty.
  - Add an Origin/Referer enforcement battery (cross-origin POST,
    no-Origin POST) that runs whether or not a synchronizer token is
    present — so apps that defend via Origin checking instead of a
    form token are correctly classified as defended.
  - Distinguish auth-failure responses (401, "invalid credentials"
    body) from CSRF-rejection responses (403/419, "forbidden",
    "cross-origin", "csrf token mismatch", etc.). The earlier code
    lumped them together and false-flagged auth-rejected baselines
    as CSRF-rejected.
  - Tighten the bypass classification: only "smoking-gun" tampering
    (no-token / garbage / cross-session swap / cross-origin POST)
    triggers `validated=True`. Informational gaps (no-Origin
    requests, cross-session cookie jar against an unauthenticated
    form) are recorded in evidence but no longer escalate the
    verdict, since they don't correspond to a realistic
    modern-browser attack.
  - Capture cookie SameSite attributes in evidence so analysts can
    see browser-side defense-in-depth at a glance.
  - Manifest budgets bumped to typical=9 / max=16 to cover the new
    Origin tests, plus a new `--attacker-origin` knob.

## Pending — not yet released

- Tier-3 advanced LLM consolidation pass (per-flow deep analysis hook
  is wired in `consolidation.run` but not yet enabled).
