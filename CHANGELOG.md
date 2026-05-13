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

- **2026-05-13** — **Documentation: UI screenshots checked into the
  repo, expanded coverage + walkthroughs.** New `screenshots/`
  directory under the source tree holds a PNG for every
  operator-facing page in the 2.1.1 web UI:

    - **01–24** Top-level pages reachable without route parameters
      (login, dashboard, proxy, flows, scan, auth profiles, assess,
      assessments, schedules, llm, user-agents, security/MFA, theme,
      and the ten `/admin/*` pages).
    - **25–33** Detail pages that need a row id (assessment, finding,
      scan, flow, AI prompt) plus SCA log/config and
      `/admin/branding`. Ids are discovered at run time by scraping
      the corresponding listing page.
    - **40–41** TOTP walkthrough: `/security` in the "not enrolled"
      and "scan this QR" states. The verify form is deliberately
      never submitted, so the enrolment leaves no DB record. The
      QR + manual-entry secret are also blacked out via PIL before
      the screenshot is written to disk.
    - **50–51** SAML 2.0 SSO configuration walkthrough: `/admin/sso`
      with Generic labels, then again with the "Use Okta" radio
      toggled, which relabels every IdP field client-side to match
      Okta's "View SAML setup instructions" panel.
    - **60–63** Theme walkthrough: `/theme` in dark, then in light,
      plus the dashboard and assessments list re-rendered in light
      mode. The script flips the operator's theme inside a
      `try/finally` so a mid-run crash still restores the original
      choice.

  Captures are produced by `screenshots/capture.py`, a Playwright /
  headless-Chromium driver that signs in with operator creds and
  walks every route. PII redaction is built into the script:
  usernames on `/admin/users` are blacked out per row, and the TOTP
  secret + QR on the enrolment screenshot are redacted with a
  labelled overlay. The README gains a Screenshots section with the
  highlights and links into the three walkthroughs.

  None of these files are referenced from the Dockerfile, so the
  deploy footprint is unchanged.

- **2026-05-12** — **Round-6 validation-aware agentic candidate
  selection.** The per-finding deep-dive pass now skips findings
  that the deterministic auto_validate pass (or the LLM fidelity
  grader) has already confirmed -- there's no value in spending
  agent tokens to re-prove what testssl already confirmed via the
  TLS handshake.

  New helper `_select_dive_candidates(aid, dive_count)`:

  1. Clusters the open crit/high/medium pool by
     `dedup_signature_v2` so 15 testssl cipher rows that all
     describe the same TLS-endpoint weakness collapse to one dive
     candidate (the canonical row of the cluster: lowest
     fidelity-tier number, highest severity, lowest id).

  2. Drops clusters whose canonical row's `validation_status` is
     `validated` (already confirmed) or `false_positive` (already
     refuted). Eligible statuses are `unvalidated`, `inconclusive`,
     and `errored` -- the cases where the agent's reasoning is
     where the value lives.

  3. Picks the top `dive_count` eligible clusters by severity, with
     id-based deterministic tiebreak.

  Surfaces selection stats in the run summary so the orchestrator
  log records `dove 3 of 15 requested; 33 clusters skipped (all
  already-validated)` instead of just `dove 15` -- an operator who
  wonders why the agent under-used its quota can see the reason.

  Cost impact, measured against assessment 66's actual data
  (severity=critical/high/medium pool of 280 rows):
    - clusters_total=107 (down from 280 due to signature
      clustering)
    - clusters_skipped_validated=33
    - clusters_eligible=74
    - rows_collapsed_by_dedup=91

  With the old logic the per-finding pass dove on 15 already-
  validated testssl cipher rows for ~$45. With Round 6 the same
  15-slot quota would have gone to the JWT-bypass / PII-leak /
  /encryptionkeys-leak / SQL-injection candidates that actually
  needed deeper analysis. No change to the budget knob or the
  Stop button.

- **2026-05-12** — **Hotfix: orchestrator log.info NameError +
  operator "Stop agentic_ai_testing" button.**

  Bug fix: the Round-4 cross-source dedup pass at
  `scripts/orchestrator.py` lines 938 / 946 used `log.info(...)` /
  `log.warning(...)` against a name that doesn't exist in the
  orchestrator module (the orchestrator writes to its log via
  `print()`, not a `logging` logger). Result: every scan that
  reached the dedup pass crashed with `NameError: name 'log' is not
  defined` -- the agentic findings landed safely but the
  consolidation pass never ran, and the assessment row went to
  `status='error'`. Fix: replace both calls with `print(...)` to
  the same stream the rest of the orchestrator uses. Caught after
  it bit assessment 66 (recovered manually by running
  `dedup.apply_cross_source_dedup(66)` + `consolidation.run(66, ep)`
  via docker-exec; 37 clusters demoted, $0.25 consolidation spend,
  risk_score 96).

  Feature: operator kill switch for the agentic_ai_testing phase.
  Long-running agentic runs (per-finding x N + free-roam) can rack
  up meaningful LLM spend on installs that pre-date Round 5 (no
  per-turn budget gate). The "Stop agentic_ai_testing" button on
  the workspace flips `assessments.agentic_stop_requested=1`; the
  agent polls that column at the top of each turn + before each
  per-finding dive and exits gracefully with
  `stopped_by_operator=true` in its summary. The orchestrator then
  continues to dedup + consolidation as if the agent had finished
  naturally -- the already-spent budget is not recovered, but the
  rest of the pass is. The button only renders during the agentic
  phase (`current_step LIKE 'agentic_ai:%' AND status IN
  ('running','queued')`); once the agent acknowledges the stop and
  the orchestrator moves to dedup, the button disappears and a
  brief "stop requested -- agent will exit on its next turn"
  indicator takes its place until the page next polls.

  Schema: `assessments.agentic_stop_requested TINYINT(1) NOT NULL
  DEFAULT 0`, boot migration
  `m_2026_05_12_add_agentic_stop_requested` (idempotent).

- **2026-05-12** — **Round-5 shared LLM budget + downstream
  reservation, admin button to backfill exploit-chain enrichment
  on legacy rows.** Two related fixes for "the agentic pass can
  silently overspend the per-assessment cap and starve
  consolidation / enrichment of the budget they need to close out
  the assessment cleanly."

  Shared accountant (`app/llm_budget.py`, new). All four LLM
  consumers -- enhanced_ai, agentic_ai, enrichment, consolidation
  -- now write to one per-assessment `BudgetState` keyed by
  assessment id. Cost is computed via the existing `llm.cost()`
  pricing table so the accumulator and the on-page cost chip
  agree.

  Reservation rule (hybrid floor + percentage): `reserved =
  max($2.50, 0.10 * cap)`. The floor protects small budgets from
  consolidation getting starved; the percentage scales naturally
  for large budgets. Both env-overridable
  (`NEXTGEN_DAST_LLM_RESERVED_USD_FLOOR`,
  `NEXTGEN_DAST_LLM_RESERVED_PCT`) so ops can tune without
  rebuilding. At the default $50 cap that's $5 reserved / $45
  available to the agent + weakness pass. At $500 cap: $50 / $450.

  Policy split:
  - `enhanced_ai_testing` + `agentic_ai_testing` are GATED on
    `remaining_for_pass()` (which subtracts the reservation). They
    stop early when their slice is exhausted, leaving headroom
    for the closing passes. Agentic adds a per-turn projection
    using `llm_budget.project_turn_cost()` and exits the loop
    gracefully with a `budget_exhausted` rationale instead of
    looping until the HTTP / turn caps.
  - `enrichment` + `consolidation` ALWAYS run while their work is
    critical for the assessment to be readable. If cumulative
    spend has pushed past the cap, they log a single warning via
    `llm_budget.warn_if_over_cap()` and proceed -- an assessment
    with $0.40 of overrun beats one with no exec summary and stub
    remediation rows.

  Cost chip on the assessment workspace now shows
  `$<spent> / $<cap> (<pct>%)` when a cap is configured, with the
  chip border tinted amber at >= 80% and red at >= 100% so the
  analyst sees the budget pressure at a glance. Uncapped
  assessments keep the original `$<spent>` shape. Tooltip carries
  per-model breakdown plus the reservation explanation.

  Backfill admin button (`/llm`). For rows that were enriched
  before the 2026-05-12 exploit-chain feature shipped and still
  carry an empty `exploit_chain_json`, a superadmin "Backfill
  exploit-chain enrichment" widget shows the count + estimated
  cost. One click re-calls the LLM for each stale signature whose
  finding(s) are still open at crit/high/medium severity, updates
  ONLY the new exploit-chain / attacker-workflow / likelihood
  columns, and leaves the curated `description_long`, `impact`,
  and `remediation_long` untouched. Bounded at 250 rows per click
  so wall time stays around 30-60 seconds; larger backlogs need
  repeated clicks (the widget updates after each pass). Audit-
  logged with the actor, scanned/refreshed/failed counts, and
  spend.

  Behavioral note: agentic / weakness passes stop EARLIER than
  before on a given cap because the reservation effectively
  shrinks their slice. That's deliberate -- the trade is fewer
  agent turns for a guaranteed clean consolidation. Increase
  `enhanced_ai_budget_usd` on the assess form, or raise the
  system default, if you need both at higher volume.

- **2026-05-12** — **Round-4 cross-source dedup, agent visibility
  preamble, hard pre-emit gate, and enrichment for AI-emitted
  findings.** Three-layer fix for the "agentic pass emits 27 near-
  duplicate TLS findings while testssl already had the canonical
  one" problem.

  Layer 1 -- visibility preamble (`app/dedup.py`,
  `app/agentic_ai.py`). The per-finding and free-roam agent passes
  now build an "already confirmed by other scanners" bullet list at
  the top of the user prompt, clustered by the new
  `dedup_signature_v2`. The directive tells the agent to spend its
  budget on new bugs or on chaining the listed bugs into deeper
  impact, not on re-testing them.

  Layer 2 -- pre-emit hard gate (`_insert_agentic_finding` +
  `_insert_weakness_findings`). Every emit / insert computes a
  severity-free signature and looks it up in a live index built at
  the top of the run. When the same signature is already covered by
  a higher-fidelity source (testssl, nuclei, enhanced_testing,
  nikto, wapiti, dalfox, sqlmap, ffuf, sca -- tiers 1+2), the row
  is refused with a tool_result that names the canonical id and
  source: "Refused as duplicate of finding #3187 (already confirmed
  by enhanced_testing)." The agent then pivots instead of retrying
  the same payload under a new phrasing. Same gate runs across
  prior emissions in the SAME run so the agent's own re-statements
  of one bug under different titles also collapse.

  Layer 3 -- post-hoc cross-source soft demote
  (`dedup.apply_cross_source_dedup`, called from the orchestrator
  just before consolidation). Walks every open finding on the
  assessment, clusters by the same signature, picks the lowest-
  tier (highest-fidelity) row as canonical, and sets
  `dedup_of=<canonical_id>` on the losers. Soft demote -- nothing
  is deleted; the demoted row's raw_data + exploit-chain reasoning
  is preserved for forensic recovery. The workspace listing, the
  severity rollup, the dashboard counts, the PDF report, and the
  REST `/scans/{id}/results` endpoint all filter on
  `dedup_of IS NULL` by default. Reversible if a signature was
  wrong: clear the column on the affected rows.

  Signature builder details (`dedup.dedup_signature_v2`):
  - Title-only vuln-class classification (evidence body
    excerpts were producing spurious matches -- HSTS findings
    clustering as `cors_wildcard` because the response body echoed
    "Access-Control-Allow-Origin: *").
  - Host-level vuln classes (`hsts_missing`, `tls_null_cipher`,
    `tls_weak_cipher`, `cors_wildcard`) emit a path-free signature
    since these are properties of the endpoint, not a URL path.
    Without this, "TLS aNULL/AECDH ..." extracts "/aecdh" as a
    path and stops collapsing against "Anonymous TLS Cipher Suite
    ..." from a different source.
  - URL host:port prefixes are stripped before path extraction so
    `https://host/` doesn't get parsed as a `//host/` "path" that
    then collides every finding on the same host onto one bucket
    (the catastrophic failure mode in the first dry-run pass).
  - MIME-type / extension fragments (`/png`, `/zip`, `/json`,
    `/html`, ...) are filtered from candidate paths since they're
    almost always noise captured from response bodies.

  Enrichment for AI-emitted findings (`app/agentic_ai.py` +
  `app/enhanced_ai.py`). Crit/high/medium findings emitted by the
  agentic pass and the LLM weakness pass now flow through
  `enrichment.get_or_create()` so the rich "Attacker workflow &
  exploitability" block (Likelihood + Why + Prerequisites +
  Exploit chain + End-to-end narrative + Remediation) renders on
  them the same way it does on deterministic scanner findings.
  Cache-keyed by signature so a finding type that recurs across
  scenarios pays one LLM call total. Low/info severities skip
  enrichment to keep the bill bounded. Best-effort: a transient
  LLM failure logs a warning and leaves `enrichment_id` NULL --
  the finding row still lands.

  Schema (`db/schema.sql` + boot migration
  `m_2026_05_12_add_dedup_of`): adds `findings.dedup_of INT NULL`
  + `idx_dedup_of` on existing 2.1.1 deployments.

- **2026-05-12** — **Agentic AI deep-dive pass — per-finding
  re-examination + opt-in free-roaming agent.** Adds a tool-using LLM
  stage that runs after `enhanced_ai_testing` and before
  consolidation. Two modes share the same per-assessment budget:
  - **Per-finding deep-dive** (default). Re-examines the top-N
    critical/high findings; N is set per-scan by the new
    `agentic_deep_dive_count` field (default 5, range 0-25; 0 skips
    the pass). The agent inherits the finding's URL, evidence, and
    validation status, and decides whether to upgrade / downgrade
    severity or emit a fresh adjacent finding.
  - **Extra Agentic (more cost)**. Toggled by the new `agentic_extra`
    checkbox. Runs a free-roaming agent that picks its own requests
    based on what it has seen across the assessment -- useful for
    multi-step business-logic abuse no single probe targets.

  Safety rails are enforced in `app/agentic_ai.py`, not just in the
  prompt: `DELETE` and any path containing
  `/delete | /destroy | /transfer | /withdraw | /reset-password |
  /forgot-password | /api/cancel | /api/refund` are refused before
  the request leaves the container; request bodies are scanned for
  the same destructive markers; all HTTP calls go through
  `SafeClient` so `Budget`, `AuditLog`, and `scope_hosts` apply just
  as for the deterministic scanners. Per-finding pass: <=25 HTTP
  calls, <=30 model turns; free-roam: <=80 HTTP calls, <=60 turns;
  each tool result body truncated to 8 KB.

  Findings emitted by the agent carry
  `source_tool='agentic_ai_testing'` and a `raw_data.agent_mode` of
  `per_finding` or `free_roam`. Token usage is logged to
  `llm_analyses` (target_type `enhanced_ai_weakness`) so the on-page
  cost chip and the audit trail attribute spend correctly across
  both agentic modes and the deterministic LLM passes.

  Model is read from `NEXTGEN_DAST_AGENTIC_MODEL` with
  `claude-sonnet-4-6` as the built-in default. Swapping models (e.g.
  if the default is deprecated) is an env-file + restart, not a code
  edit -- the loop reads the variable at scan start.

  Schema: `agentic_deep_dive_count INT NOT NULL DEFAULT 5` and
  `agentic_extra TINYINT(1) NOT NULL DEFAULT 0` on both `assessments`
  and `scan_schedules`. Idempotent boot migration
  `m_2026_05_12_add_agentic_columns` adds them on existing
  deployments. The `/assess` form, schedule materializer, and three
  POST endpoints (`/api/v1/assessments`,
  `/api/v1/schedules` create + update) all accept and clamp the
  values; the schedules layer's allowlist + `_normalize` + INSERT
  paths are kept in lockstep so a scheduled scan inherits the same
  configuration as a one-off.

- **2026-05-12** — **Round-2 parity push against external DAST
  tooling on Juice Shop -- enhanced 5 existing enhanced_testing
  probes whose detection criteria did not match the actual bug
  shapes, added 5 net-new probes for findings the catalog did not
  cover, and broadened the LLM weakness pass's telemetry with a
  request+response-paired placeholder for mass-assignment
  reasoning.**

  Probe enhancements (existing files, no new manifest entries):
  - `bizlogic_negative_quantity_total`: accept "POST response body
    echoes the persisted negative-quantity row" as a third validation
    signal alongside the existing reduced-cart-total and
    negative-line-in-cart-view checks. Catches stacks where the bad
    row is written under a null / orphan basket and never surfaces in
    the user's cart view, but the response from the write itself
    proves persistence.
  - `redirect_allowlist_bypass`: now also tests the OWASP Juice Shop
    bypass shape -- attacker host with a trusted prefix EMBEDDED as a
    query string (e.g. `https://evil.com/?https://github.com/juice-
    shop/juice-shop`). The original shape (trusted prefix as host,
    evil as `?pwned=`) is preserved. Added a baseline-rejection step
    that fires the bare evil URL first; the differential (baseline
    rejected, smuggled accepted) is enough to confirm bypass even when
    the server fetches the redirect server-side and returns 200
    rather than emitting a Location header.
  - `angular_secrets_in_bundle`: added four generic literal-assignment
    patterns to the existing canonical-shape catalog -- hardcoded
    `testingPassword="..."` / `testingUsername="email@..."` /
    `api_key="..." | client_secret="..."` / bearer-token literals.
    Catches the OWASP Juice Shop `main.js` leak (`testingUsername=
    "testing@juice-sh.op"; testingPassword="IamUsedForTesting"`) that
    none of the cloud-vendor-shape regexes matched.
  - `nosql_review_operator_injection`: now also issues a PATCH
    /rest/products/reviews with a `$in` selector whose values are
    synthetic non-existent IDs (so the safe outcome is
    `{"modified": 0, ...}` -- proof the operator was honoured without
    actually modifying any review records). Confirms NoSQL-injection
    on the JSON body's `id` field even when the GET-with-bracket
    syntax variant returns 500. Added to `_PROBES_NEEDING_POST` so
    SafeClient permits the write verb.
  - `prototype_pollution_any_patch`: added two new detection signals
    beyond the marker-leak-on-unrelated-endpoint one. (1) Sequelize /
    ORM error body that names the polluted child key -- the merge
    reached the query generator and crashed citing an attribute that
    came from Object.prototype (the OWASP Juice Shop POST
    /api/Feedbacks shape). (2) Process-cascade canary: baseline GETs
    on /, /api/Products, /api/about, /robots.txt before the payload,
    same GETs after; a 2xx -> 5xx flip on any of them is strong
    evidence the Node process is in a post-pollution unstable state.
    Endpoint catalog also expanded to include POST /api/Users /
    /api/Feedbacks / /api/Complaints (write-shaped pollution surfaces
    that the previous PATCH-only catalog missed).

  New probes (4x `.py` + `.manifest.json` under enhanced_testing/probes/):
  - `info_admin_config_exposed` (read-only): walks a catalog of
    conventional admin / application-configuration paths
    (/rest/admin/application-configuration, /api/admin/config, etc.)
    and emits a finding when an unauthenticated GET returns a
    configuration-shaped JSON body (top-level config / application /
    server envelope OR >=3 admin-flavoured field tokens).
  - `authz_authentication_details_exposes_all_users` (read-only +
    POST-gated): registers a fresh low-privilege user, GETs
    /rest/user/authentication-details (and similar), and flags the
    endpoint when the response returns >=2 distinct user records WITH
    auth-flavoured fields (deluxeToken, totpSecret, lastLoginIp, role)
    visible to a non-admin caller.
  - `info_memories_exposes_nested_user_pii` (read-only + POST-gated):
    registers a fresh user, walks feed-shaped endpoints (memories /
    posts / activity / photos), and emits a finding when any row
    carries a nested `User`-keyed object with a sensitive field
    (password hash, role, deluxeToken, etc.) -- the canonical
    "serializer ships the eager-loaded ORM row" bug.
  - `authz_product_price_mass_assignment` (probe class, POST-gated):
    registers a low-priv customer, PUT /api/Products/{id} with a
    benign description suffix, verifies via follow-up GET, then
    restores the original description before exiting. Confirms
    vertical authorization failure on the catalog-update path that
    almost certainly permits price / name mutations through the same
    code path (deliberately not exercised to avoid touching financial
    state).
  - `config_true_client_ip_spoofable` (read-only + POST-gated):
    registers a fresh user, then probes /rest/saveLoginIp (and
    similar) with five spoofable IP headers (True-Client-IP,
    X-Forwarded-For, X-Real-IP, X-Originating-IP, CF-Connecting-IP)
    set to canary 10.0.0.x values. Flags the endpoint when the
    stored audit-trail IP matches the spoofed value.

  Orchestrator: 5 new probe names added to `_PROBES_NEEDING_POST` so
  SafeClient permits their write or auth-gated phases (the
  `allow_destructive=True` budget setting that lets POST/PUT/PATCH
  through). No change to read-only probes' default plumbing.

  LLM telemetry placeholder (B):
  - New helper `_render_mutating_endpoints_full` in app/enhanced_ai.py
    that emits, per mutation, BOTH the captured request body AND the
    captured response body (with response status), one entry per
    distinct endpoint, capped at 24 entries and PER_FINDING_QUOTE_MAX
    chars per body. Surfaced as a new `{mutating_endpoints_full}`
    placeholder added to `PLACEHOLDERS_BY_SLOT` for
    `advanced_ai_testing.weakness_discovery`.
  - The Mass Assignment / Auto-Binding scenario user-template now
    quotes `{mutating_endpoints_full}` alongside the existing
    `{mutating_requests}` block, with explicit instructions to look
    for privilege-bearing fields echoed back in the response (the
    request-only view cannot show that, which is why mass-assignment
    findings were so commonly missed by the LLM previously). Other
    scenarios can opt-in by adding the placeholder to their own
    user_template -- since the data was already in the per-finding
    raw_data, this is a renderer-only change and adds zero new
    network requests.

- **2026-05-12** — **New weakness-discovery scenario: "Collection
  Endpoint Authorization Audit"** (sort_order 105, slot
  `advanced_ai_testing.weakness_discovery`, category `bola_idor`).
  Fires when the assessment has captured credentials AND
  (`has_state_mutating_endpoint` OR `findings_count >= 5`). Targets
  the BOLA-on-list-endpoint class specifically: `GET /api/{Resource}`
  paths (no id in the URL) where the server authenticates the caller
  but fails to filter the response set by ownership. The per-record
  BOLA scenario (sort_order 20) was missing these because its prompt
  asks the LLM to swap object IDs and it ignores no-id collection
  paths entirely.

  The new prompt instructs the LLM to walk every authenticated GET
  collection endpoint, locate its body in the captured response
  samples, and emit a finding ONLY when the verbatim excerpt proves
  cross-tenant exposure (UserId / OwnerId / TenantId fields that
  don't match the session's identity, admin records visible to a
  non-admin session, etc.). Hard-rule: reproduction must be a
  non-destructive GET piped through `jq` for distinct-owner counting;
  remediation must name the missing server-side filter clause. One
  finding per distinct collection endpoint -- not per leaked record.
  Severity rubric maps to OWASP A01 with critical reserved for
  auth-metadata exposure across users (deluxeToken, totpSecret,
  password hash) and high for PII / business-activity records.

  Seeded into the `ai_prompts` table on next container boot via the
  existing per-row `seed_defaults_if_empty` path -- no schema
  migration needed. Operators who want to disable the scenario can
  flip `is_active=0` from /admin/ai-prompts as with every other
  seeded prompt. The "Restore to default" admin action re-syncs the
  in-code body / user_template after edits.

- **2026-05-12** — **Cross-scenario dedup for LLM-emitted findings.**
  The Enhanced-AI weakness pass runs up to 20 scenario prompts per
  assessment, and the same underlying issue (Prometheus `/metrics`
  exposed, CORS wildcard, etc.) can surface from multiple scenarios
  with slightly different titles -- producing 3-4 near-duplicate rows
  in the findings table that the consolidation roll-up cannot collapse
  because `enrichment_id` is keyed off the rephrased title. On
  assessment 64, the `/metrics` finding appeared four times and CORS
  twice.

  Fix: `_insert_weakness_findings` now computes a stable signature
  per candidate before inserting. Signature precedence:
  `severity|owasp|<vuln_class>|<url_path>` when both are detected
  (tight match for "exposed /metrics across scenarios"); falls back
  to `severity|owasp|<vuln_class>` (groups every same-class finding),
  then `severity|owasp|url:<path>` (when no class fires but a URL
  does), and finally a sorted content-token set. Signatures already
  emitted for this assessment cause subsequent matching candidates to
  be skipped silently and logged at INFO level with the skip count
  per scenario.

  Vuln-class regex catalogue covers the OWASP-Top-10 staples:
  stored/reflected/DOM XSS (kept as distinct subtypes -- they have
  different remediation), SQL/NoSQL/UNION SQLi, IDOR/BOLA,
  mass-assignment, prototype pollution, XXE, SSRF, open redirect,
  JWT `alg:none` / `no-exp` / key-confusion (each distinct), exposed
  Prometheus metrics / Swagger / `/rest/admin/*`, permissive CORS,
  verbose-error / framework version disclosure, directory listing,
  hardcoded secrets in client bundles, missing rate-limit / brute
  force. Smoke-tested against the verbatim assessment-64 titles --
  four `/metrics` rephrasings collapse to one signature, two CORS
  rephrasings collapse to one, six genuinely-different findings stay
  separate, three XSS subtypes stay separate.

- **2026-05-12** — **Severity calibration on two over-rated
  enhanced_testing probes** that were emitting `critical` for
  evidence that did not constitute end-to-end compromise. Reserving
  `critical` for findings that demonstrate full account takeover,
  unauthenticated RCE, or arbitrary write/exfil — read-only IDOR or
  exposure-only findings without a chained exploit now downgrade to
  `high`.
  - `authz_basket_idor_walk`: read-only cross-tenant exposure of
    purchase intent. Significant privacy impact and OWASP A01, but
    not full ATO on its own — chained with mass-assignment or
    privesc elsewhere is what makes it critical. Now `high`.
  - `info_key_material_exposed`: split by what was actually found.
    Private key material (PEM/OpenSSH/PGP PRIVATE markers) keeps
    `critical` because possessing the signing key is itself a
    compromise of every credential signed with it. Public signing
    keys (RSA PUBLIC, PEM PUBLIC) and AES-shaped blobs now emit
    `high`, with a `severity_basis` field in evidence explaining
    that weaponization requires a separate signature-validation
    flaw to chain against. The full chain (e.g., exposed `jwt.pub` +
    `alg=HS256` confusion + accepted forged token) still surfaces
    as critical via the dedicated `auth_jwt_no_expiration`
    `signature_not_verified` branch, which DOES demonstrate the
    end-to-end exploit and remains `critical`.

  Other probes that emit `critical` (60 total) were spot-audited
  and left alone — `auth_default_admin_credentials`,
  `auth_sql_login_bypass`, `authz_role_mass_assignment`,
  `xxe_file_upload`, etc. all genuinely demonstrate the impact their
  severity claims.

- **2026-05-12** — **Stop LLM-emitted findings from getting trapped on
  `validation_status='errored'`.** The auto-validation pass that runs
  inside `enhanced_ai.run()` was probing freshly-emitted LLM findings
  with toolkit probes, but those findings ship with `evidence_url=NULL`
  (the LLM rarely conforms to the strict probe schema), so the probe
  could not construct a valid request and returned an `errored`
  verdict. That verdict was written onto the finding row, and the
  fidelity grader's selection then excluded `errored` rows, so the
  LLM's most actionable critical/high findings sat permanently in
  limbo — neither validated nor refuted, invisible to the next
  triage pass. On assessment 64 alone this affected 7 of 13 LLM
  findings (auth_jwt_no_expiration, info_metrics_exposed x3,
  info_directory_listing, info_verbose_error, info_disclosure,
  config_cors_wildcard x2). The fix is in three parts:
  - `scripts/challenge_runner.py` no longer overwrites
    `validation_status` to `errored` when the probe errors on a
    finding with `source_tool='enhanced_ai_testing'`. The probe error
    transcript is still written to `validation_evidence` so an
    analyst can see what was attempted, but the row stays at its
    default `unvalidated` state so the fidelity grader can see it.
  - `app/enhanced_ai.py` widens the fidelity selection from
    `validation_status IN ('unvalidated','inconclusive')` to also
    include `'errored'`. This catches the case where a non-LLM-source
    finding genuinely failed probe validation (transient network
    failure, target offline) and gives the LLM grader a chance to
    triage it from evidence alone.
  - Migration `2026_05_12_unstick_llm_errored_validations` rewinds
    existing `enhanced_ai_testing` rows stuck at `errored` back to
    `unvalidated` on already-deployed databases so the fix lands
    without requiring a full re-scan. Non-LLM-source `errored` rows
    are left alone (they often reflect real probe failure worth
    keeping visible). Idempotent; re-runs are no-ops.

- **2026-05-12** — **LLM-driven exploit-chain validation and attacker
  workflow demonstrations on every finding.** The per-finding
  enrichment pipeline now asks the configured LLM endpoint not just
  for description / impact / remediation but for a calibrated risk
  story: a qualitative `likelihood` band (very-low ... very-high)
  with a written `likelihood_rationale`, a `detection_difficulty`
  hint (easy / moderate / hard), an ordered `prerequisites` list of
  conditions that must line up for the exploit to succeed, an
  ordered `exploit_chain` of `{phase, action, evidence}` kill-chain
  steps, and a free-text `attacker_workflow` narrative that names
  the realistic tools (Burp, sqlmap, ffuf, jwt_tool, etc.) a
  moderately skilled attacker would use to weaponize the finding
  into business impact. Phases follow a fixed vocabulary
  (Reconnaissance, Initial Access, Discovery, Exploitation,
  Privilege Escalation, Lateral Movement, Impact) so the PDF can
  group by kill-chain stage. The prompt also gives the model
  explicit calibration guidance — chained prerequisites lower
  likelihood, unauthenticated RCE with public PoCs raises it — so
  the band is honest rather than inflated by default.

  Six new columns on `finding_enrichment` (`prerequisites_json`,
  `exploit_chain_json`, `attacker_workflow`, `likelihood`,
  `likelihood_rationale`, `detection_difficulty`) persist the
  enrichment so the LLM is only billed once per signature.
  Migration `2026_05_12_add_exploit_chain_columns` adds the columns
  on existing 2.1.1 databases idempotently (per-column
  `information_schema` gating, ALTERs done one at a time so a partial
  failure mid-list retries the rest on the next boot). The web
  finding-detail page renders an **Attacker workflow &
  exploitability** card (color-coded likelihood badge,
  detection-difficulty pill, rationale paragraph, prerequisites
  list, numbered kill-chain with per-step "Signal" evidence, and the
  full attacker workflow narrative). The slide-out side panel
  renders a compact mirror so analysts triaging in the finding-list
  view see the same context without leaving the row. The PDF
  report's per-finding card renders the same block, with print-
  friendly colors for the likelihood badge and a per-phase
  rollover chip on each chain step so a manager scanning the PDF
  sees instantly whether the finding is a "real attacker would walk
  in here" item or a "interesting but needs five prerequisites"
  item. The bug-report markdown export (Jira / ServiceNow / GitHub)
  also includes the exploit chain so the ticket assignee gets the
  attacker context inline. Admin manual-edit form on the finding-
  detail page exposes all six fields (with `Phase | Action |
  Evidence` line format for the chain), and a manual edit locks the
  row so future automatic enrichment will not overwrite the
  analyst's environment-specific take. LLM `max_tokens` raised from
  2048 to 4096 to accommodate the larger response without
  truncation.

- **2026-05-11** — **Estimated LLM cost chip on the assessment
  workspace.** New KPI tile on the assessment-detail page, anchored
  immediately to the left of the "Hide info-severity (page + PDF)"
  toggle, surfaces the running USD spend for the scan's LLM work
  (consolidation roll-up, per-finding enrichment, enhanced_ai weakness
  and fidelity passes). The number is computed live by aggregating
  `llm_analyses` per-model (input + output tokens), then running each
  bucket through `llm.cost()` so the displayed figure uses the same
  per-million-token rates that drove the per-call accounting — chip,
  PDF, and `assessments.llm_cost_usd` cannot drift. A tooltip on the
  chip lists the per-model breakdown (calls, in tokens, out tokens,
  cost). The chip is suppressed entirely when no billable LLM call
  ran for the assessment, so `llm_tier='none'` scans show the strip
  unchanged. Falls back to the cached `llm_cost_usd` /
  `llm_in_tokens` / `llm_out_tokens` totals on the assessment row
  for older scans whose `llm_analyses` rows have been pruned by the
  lifespan sweeper — the chip still renders, just without the
  per-model breakdown.

- **2026-05-11** — **Validated-only scoring + errored-retry +
  inconclusive→info.** Three-part change to make the grade reflect
  only what the challenge pass could actually prove.

  1. **Scoring is now strictly validated-only.** `reports._score_findings`
     used to apply a half-weight demerit to unvalidated findings as
     well so a "blizzard of scanner suspicions" couldn't get a free
     pass. With the challenge pass (read-only probes + LLM fidelity)
     now running on the critical path of every scan, the unvalidated
     bucket is by definition "we couldn't prove this" — and grading
     against unproven findings rewards noisy scanners and punishes
     clean ones. The `SEV_DEMERIT_UNVALIDATED` table is removed; the
     loop now skips any finding whose `validation_status` is not
     `validated`. The exploitability cap loses its
     `T4_critical >= 5 → D` clause for the same reason (volume of
     unconfirmed criticals no longer caps the grade).

  2. **Errored verdicts retry up to 3 times.** `scripts/challenge_runner.py`
     wraps each probe / fast-path invocation in a small retry loop
     keyed on `verdict_to_status(...) == 'errored'`. A transient
     subprocess crash, network blip, or rate-limit timeout used to
     park a real finding in the `errored` bucket for the rest of the
     scan; now it gets two extra attempts with a short growing delay
     before the final verdict lands. Retries are bounded so a
     persistently broken probe still finishes the batch in
     reasonable time, and the final verdict carries
     `challenge_attempts` in its evidence blob so an analyst can see
     it took N tries.

  3. **Inconclusive verdicts force severity=info.** The challenge
     runner write-path now downgrades `severity` to `info` whenever
     it records `validation_status='inconclusive'`. The probe ran
     but couldn't prove the finding; the UI / heatmap / PDF should
     stop showing a critical/high badge the evidence doesn't
     support. The original severity is preserved in
     `raw_data.original_severity` so the downgrade is auditable and
     a future re-challenge can surface it.

  Net effect: the score reflects what was proven, errored is now
  recoverable, and unproven findings present at the severity their
  evidence supports rather than the severity the source scanner
  hopefully suggested.

- **2026-05-11** — **Challenge fast-path target resolution — derive
  the test URL from raw_data / assessment fqdn when evidence_url is
  empty.** LLM-emitted findings (`enhanced_ai_testing`) frequently
  omit the top-level `evidence_url` and embed the test URL inside
  `raw_data.llm_reproduction` (the curl block) or `raw_data.llm_evidence`
  (the prose preface). Before this change, `_dispatch_finding_fast_path`
  bailed out at the very first check (`if not evidence_url: return None`)
  and the per-finding **Challenge** button surfaced the unhelpful
  `"This finding has no deterministic fast-path classifier. Use the
  toolkit Challenge or Challenge-with-LLM buttons instead."` message
  even when the title was a clean fast-path match (e.g. *"Missing
  Referrer-Policy, Permissions-Policy, COOP, COEP, CORP on
  authenticated and login responses"* on assessment 62 finding 2960
  — the LLM had cited `https://<host>/login.php` in the reproduction
  block but never promoted it to `evidence_url`).

  New helper `_resolve_finding_target(finding) -> (host, port)` tries,
  in order: `evidence_url` → first `https?://…` found in
  `raw_data.llm_reproduction` → first URL in `raw_data.llm_evidence`
  → assessment row's `fqdn` + `scan_https` (host-level header / cookie
  / TLS checks already probe `https://{host}:{port}/` and ignore the
  path on `evidence_url`, so the assessment fqdn is a perfectly valid
  fallback target). `_dispatch_finding_fast_path` now calls the helper
  and only refuses when *all four* sources come up empty.

  The bulk runner (`scripts/challenge_runner.py`) used to filter
  candidates with `WHERE evidence_url IS NOT NULL AND evidence_url <> ''`
  at the SQL level — that filter is dropped as part of the same change
  so the bulk pass and the manual click stay in agreement on what is
  eligible. The classifier is now the single source of truth for "can
  this finding be fast-pathed?", regardless of how the source tool
  chose to record the URL.

- **2026-05-09** — **Enhanced-AI weakness pass: feed it real evidence,
  let probes pre-validate candidates, stop the role text from gating
  output.** Four-part change targeting the symptom on assessment 52
  where the LLM was returning `[]` for every weakness scenario.

  (1) **`app/flow_index.py`** (new). Every scanner already runs through
  the mitmproxy addon and writes `flows.jsonl` + `flows/<id>_response.txt`
  into the scan dir, so we already had request/response evidence for
  every probe -- it just was never plumbed back into `raw_data`. The
  new module reads those captures, normalizes URLs (drops default ports,
  query, fragment), and provides a `(method, URL) → FlowRecord` lookup
  with a path-only fallback. Bodies are loaded lazily and sanitized
  for rotating secrets (CSRF tokens, session cookies, bearer tokens,
  long base64 blobs) before they reach the LLM.

  (2) **`app/enhanced_ai.py:build_telemetry`** wires the FlowIndex into
  the per-finding `_raw` dict, populating `response_body_excerpt`,
  `response_status`, `response_content_type`, and an
  `response_headers_excerpt` slice (Server, X-Powered-By, Set-Cookie,
  Location, security headers). The existing `_render_response_samples`
  helper already read these keys, so the prompt's `RESPONSE SAMPLES`
  block stops emitting `(no response bodies captured by scanners)` --
  which was the line that, combined with the prompt's verbatim-quote
  rule, was guaranteeing zero findings on every weakness call.

  (3) **`app/enhanced_ai.py` — runtime safety preamble + role-text
  sanitizer.** Rewrote rule #1 of `_RUNTIME_SAFETY_PREAMBLE` so a
  finding without a captured body excerpt is allowed through with the
  literal phrase `inferred-from-telemetry:` and a confidence cap of
  0.6 (instead of being silently omitted). Added a new rule #4 stating
  the weakness pass produces *candidates*, not verdicts — the fidelity
  pass remains the source of truth at >= 0.75 confidence. Added
  `_sanitize_role_text` which strips the recurring `ONLY SHOW FINDINGS
  WITH A CONFIDENCE SCORE OF 0.75 OR HIGHER` / `IF CONFIDENCE SCORE IS
  LESS THAN 0.75, DON'T REPORT IT` / `DON'T REPORT IT` directives that
  operators paste into the role-scope and role-restrictions fields.
  Those directives belong in the code-owned preamble; when they live
  in the role text they collide with the candidate-vs-verdict contract
  and the LLM correctly returns `[]`.

  (4) **`app/enhanced_ai.py:run` — candidate-validation pass.** After
  the weakness loop inserts candidates and before the fidelity loop
  spends LLM tokens grading them, invoke
  `scripts.challenge_runner.run(aid, safe_only=True)`. Read-only
  toolkit probes (the manifest declares `safety_class: read-only`) run
  against any new unvalidated candidate whose CWE / title matches a
  probe under `enhanced_testing/probes/`. Verdicts land in
  `validation_status` + `validation_evidence`, which the fidelity batch
  already surfaces per-finding via `prior_probe_verdict` /
  `prior_probe_evidence` (`_render_fidelity_batch:2050-2065`).
  Validated and false-positive verdicts are excluded from the fidelity
  SELECT entirely, so the net effect is *fewer* fidelity tokens spent,
  not more.

  (5) **`app/auth_recapture.py`** (new). Final lift for the case where
  scanners did not probe a high-value adjacent path (admin / api /
  settings / users / config / dashboard / grc-*). When credentials are
  configured, scores cluster URLs missing from FlowIndex by path-token
  weight and GETs the top 20 with the same session cookie
  challenge_runner uses. Single GET per URL, no redirect-follow (the
  immediate response shape — 302 to login, 401, 403 — is the LLM
  signal). Capped at `MAX_RECAPTURE=20` URLs and per-body bytes at
  `PER_FINDING_QUOTE_MAX`; injected into the same canonical
  `response_body_excerpt` keys so no new placeholder block was
  required.

  Token-economy net: in the common case (assessment with creds and a
  scanner-covered path set) added cost is one form-login + the body
  excerpts already captured -- ~0 new HTTP requests, +1-2K input
  tokens per weakness scenario, but the weakness pass goes from
  emitting `[]` to emitting validated candidates, which the fidelity
  filter then SKIPS because their verdicts are already final. Net
  spend per scan goes DOWN, not up, while findings volume goes from
  zero to real.



- **2026-05-07** — **Finding detail page: render proof + remediation
  for non-LLM probes; admin-login probe drops to info severity.** Two
  fixes that move closely together because they were filed together
  by an analyst working assessment 45.

  (1) `app/templates/finding_detail.html` previously wrapped the
  *What was detected*, *To Reproduce*, and *Remediation* cards inside
  a `{% if f.source_tool == 'enhanced_ai_testing' %}` block, which
  meant rows from the toolkit's own probes (`enhanced_testing`)
  showed only the bare URL and a collapsed-JSON dump of
  `validation_evidence`. The description and remediation columns
  were populated in the database but never reached the page. Pulled
  the description and remediation cards out of the gate so any
  source_tool with a description renders one, and added a per-probe
  **Proof** card that pretty-prints `validation.evidence` for the
  three families an analyst hits most often: `clientjs_dom_xss_sinks`
  lists each JavaScript bundle URL with the matching sink labels and
  short code excerpts; `info_admin_login_at_common_paths` lists every
  confirmed admin path with its HTTP status, final URL after
  redirects, and a *login form present* badge;
  `info_powered_by_banner` lists the leaking response headers
  verbatim with a *version-bearing* tag on any header that matched
  the strict product/version regex. A generic fallback covers all
  other probes by rendering `evidence.confirmed` and
  `evidence.attempts` as collapsible JSON. The full raw
  `validation_evidence` is still available below in the existing
  Validation card's `<details>` for audit, but the analyst no longer
  has to expand it to know which JS bundle leaked or which header
  was set. Files: `app/templates/finding_detail.html`,
  `src/app/templates/finding_detail.html`. Smoke-tested by rendering
  the new template with the live evidence from findings 2456 / 2457
  / 2458 (assessment 45).

  (2) `enhanced_testing/probes/info_admin_login_at_common_paths.py`
  emitted `severity_uplift="medium"` whenever an admin-style URL
  returned a login form on the public origin. The probe is
  surface-inventory only — the actual defects (default credentials,
  missing lockout, weak session flags, MFA gaps) are scored
  independently by the paired `auth_default_admin_credentials`,
  `auth_no_brute_force_lockout`, and `auth_username_enum_timing`
  probes, so flagging the login page itself as medium double-counted
  exposure that the rest of the auth probe family already prices in.
  Dropped `severity_uplift` to `"info"` so the row reads as
  inventory by default; analysts who want to elevate it for a
  specific engagement can still mark it via the existing
  enrichment-edit flow. Existing rows in the `findings` table on the
  current host were backfilled in the same change
  (`UPDATE findings SET severity='info' WHERE
  source_tool='enhanced_testing' AND
  title='info_admin_login_at_common_paths' AND severity='medium'`)
  so historical assessments 41, 42, 45 reflect the new classification
  immediately. Files:
  `enhanced_testing/probes/info_admin_login_at_common_paths.py:112`,
  `src/enhanced_testing/probes/info_admin_login_at_common_paths.py:112`.

- **2026-05-05** — **sca_runtime_check probe runtime fix.** The
  premium-tier SCA gap-fill probe was crashing on every assessment with
  `AttributeError: 'Response' object has no attribute 'status_code'`,
  which meant no SCA evidence ever made it into the verdict bundle. The
  probe was using the `requests` library's `.status_code` / `.content`
  names against a `SafeClient.Response` object, which only exposes
  `.status` / `.body` / `.text`. Switched to the SafeClient API; the
  probe now runs cleanly and either fingerprints versioned JS URLs or
  returns a `validated=False` "no versioned JS library URLs detected"
  verdict (the latter is expected when the page only links a single
  concatenated bundle whose libraries are not in their original
  per-file path layout).
  Files: `enhanced_testing/probes/sca_runtime_check.py:95-99`,
  `src/enhanced_testing/probes/sca_runtime_check.py:95-99`.

- **2026-05-05** — **Grade cap softened for isolated mediums + auto-validate
  picks up wapiti anomaly:5xx.** Two changes that work together to stop a
  single legitimate medium-severity finding from cratering an otherwise clean
  engagement to a D, while making the noisiest 5xx false-positive class clear
  itself before the analyst opens the workspace.

  (1) `_exploitability_grade_cap` in `app/reports.py` raised the T3
  (validated medium) threshold from 1 to 3. A single validated medium no
  longer forces D — the per-category demerit math, the per-category cap, and
  the validation floor decide the letter on their own. Three or more
  validated mediums still cap at D because that's a pattern of mid-severity
  exposure, not an isolated finding. T1 / T2 / T2b thresholds (any
  toolkit-confirmed compromise, three+ validated criticals, two+ validated
  highs, or any single validated critical/high) are unchanged. Validated
  rule of thumb on the example that motivated the change: 1 validated
  medium + 2 validated lows + 14 info-recon now grades A (was D).

  (2) `toolkit/probes/anomaly_5xx_validation.manifest.json`'s `safety_class`
  flipped from `"probe"` to `"read-only"`. The probe replays the captured
  request that the originating scanner (wapiti / nuclei / nikto) already
  sent during the scan pass — replay is not a state-mutating action in the
  sense `safety_class` is meant to gate. With the read-only classification,
  `challenge_runner.run(safe_only=True)` (the auto-validate pass that fires
  immediately after ingestion, orchestrator.py:846) now picks up these
  findings and clears the false-positive cluster before the assessment
  flips to `done`. The destructive-method gate stays open via the
  unchanged `requires_post: true` flag, so the probe can still issue the
  captured POST it needs to reproduce the 5xx — only the auto-run
  selector changes.

  Net effect on the motivating assessment (test 41, 52 findings): the
  29 wapiti `anomaly: Internal Server Error` rows are now auto-marked
  `false_positive` during ingestion instead of after a manual Challenge
  click, and the resulting 1 validated medium + 2 validated lows are
  graded A instead of D.

- **2026-05-04** — **PDF report wrap fix.** Long URLs in finding
  evidence and long tokens in the scope/document-control tables
  were running past the cell boundary and clipping at the right
  margin in WeasyPrint output. Added `overflow-wrap: anywhere` and
  `word-break: break-word` to `code, pre` and to `th, td` in
  `app/templates/report.html` so unbreakable runs (URLs, FQDNs,
  long query strings on the "Affected" line of a finding card)
  break inside their container instead of forcing the table column
  wider than the page. Template-only change — no schema or runtime
  impact, image rebuild required for the new CSS to ship.

- **2026-05-03** — **Role-aware Enhanced-AI-Testing**. New opt-in
  on the assess form (and `POST /api/v1/scans` body) gated to the
  premium + advanced corner: when `profile=premium` AND
  `llm_tier=advanced`, an `enhanced_ai_testing` checkbox appears.
  Checking it makes `creds_username` / `creds_password` / `login_url`
  and two free-text fields — *Describe the user role and what this
  user's scope is* and *What the user should NOT be able to do in
  the test* — required to submit (HTML `required` + 400 from the
  server / API). The orchestrator's existing `enhanced_ai` gate
  (was: `llm_tier == 'advanced'`) tightens to require all three of
  premium + advanced + checkbox; the role textareas are persisted on
  the `assessments` row (and on `scan_schedules` for recurring
  scans) and travel with Re-scan prefill. Both Enhanced-AI prompt
  passes consume the role context: the weakness-discovery preamble
  prepends an AUTHORIZED USER CONTEXT block instructing the model
  to suppress findings that merely demonstrate authorized
  capabilities, and the fidelity grader gains a fourth verdict —
  `expected_behavior` — that auto-tags in-scope findings with
  `validation_probe='enhanced_ai_role_scope'`, severity forced to
  `info`, leaving real out-of-scope abuses (XSS / SQLi / IDOR / SSRF
  / privilege escalation) at their original severity. Migration
  `2026_05_03_refresh_fidelity_prompt_for_role_scope` updates
  existing 2.1.1 databases' seeded fidelity prompt to the v2 text
  (operator-edited rows are detected and left alone). Schema:
  `assessments` and `scan_schedules` each grow `enhanced_ai_testing`
  TINYINT(1), `role_scope_description` TEXT, `role_restrictions`
  TEXT — declared in `db/schema.sql` (CREATE TABLE bodies + §2
  ALTER block) and surfaced in `scripts/verify_schema.py` so the
  schema-drift auto-healer creates them on existing 2.1.1 DBs the
  first time the new image boots.

- **2026-05-02** — **Empirically-chosen TLS / cipher / protocol fast
  paths + assessment-UA observance + drop overall_grade noise.**
  Benchmarked four tools on a real production target (HTTP/2 502
  Cloudhub + CloudFront edge). Numbers (median of 3-5 runs each):
  Python urllib in-process header check **150-300 ms** vs
  `curl -sI` 150-300 ms vs `testssl.sh -h` **15 s**.
  `openssl s_client -cipher` single-cipher attempt **80-120 ms** vs
  `curl --ciphers` 290 ms vs `testssl.sh -e` full enum **57 s**.
  `nmap --script ssl-enum-ciphers` **600 ms** vs testssl `-e` 57 s
  (95× faster for the same answer).
  Decision matrix encoded in `_finding_test_tls()`:
  (1) header IDs → in-process Python urllib (no subprocess).
  (2) cert IDs → in-process Python ssl + cert parse (existing).
  (3) single protocol IDs → openssl s_client -tls1_X. System
  openssl 3.x for TLS 1.2/1.3, bundled testssl openssl 1.0.2 (with
  `OPENSSL_CONF=` empty) for SSLv2/3 and TLS 1.0/1.1 because the
  modern build refuses them at compile time.
  (4) `cipherlist_*` IDs → openssl s_client -cipher, same
  modern/legacy split. Mapping covers NULL, aNULL, EXPORT, LOW,
  DES, 3DES, RC4, MD5, MEDIUM categories.
  (5) full-matrix IDs (cipher_negotiated / cipher_x* / cipher_order)
  → nmap --script ssl-enum-ciphers, parses and counts C/D/F-grade
  ciphers from the output.
  (6) heavy vuln tests (HEARTBLEED, ROBOT, SWEET32-oracle, BEAST)
  → testssl.sh subprocess as before, kept as fallback with a 180 s
  timeout.
  Each fast path also returns a `reproduce_command` field with the
  exact CLI invocation an analyst can copy-paste — closes the audit
  gap that in-process branches would otherwise have. Smoke-tested
  live: TLS1.0 protocol probe **97 ms** (and the target accepts it),
  TLS1.3 **294 ms**, 3DES cipher **68 ms** (and the target accepts
  it under TLS 1.2), nmap full enum **533 ms**.
  All HTTP-flavored fast paths now read the assessment's configured
  `User-Agent` (assessments.user_agent_id → user_agents.user_agent)
  via the new `_resolve_assessment_user_agent()` helper, so the
  Test / Validate / Quick HTTP probe traffic carries the same UA
  the original scan used. Avoids spurious diffs when a WAF/CDN
  responds differently to scanner-shaped UAs.
  Companion change: `findings.parse_testssl()` drops `overall_grade`
  rows at parse time. They're a letter-grade summary of every other
  row in the report (weak ciphers, weak protocols, missing headers)
  — pure duplication that polluted the assessment view, severity
  rollup, and PDF report. Already-stored rows on existing
  assessments are unaffected; new scans skip them.
- **2026-05-02** — **Header-presence fast path + bumped testssl
  timeout.** HSTS / CSP / X-Frame-Options / banner_server and similar
  header-presence findings no longer route through testssl.sh's slow
  `-h` flag (30-60 seconds per check). Both the server-side
  `_finding_test_tls()` fast-path table and the `testssl_recheck`
  toolkit probe now detect header-class IDs and answer them with a
  single in-process HTTPS GET. Sub-second instead of 30-60 seconds —
  smoke-tested at **305 ms** for `config_hsts_missing` on a live
  target where the testssl.sh path was hitting the 90-second
  timeout. The mapping (`_HEADER_FAST_ID_TO_HEADER`) covers the
  testssl native IDs (HSTS, HSTS_subdomains, HSTS_preload, HSTS_time,
  HPKP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection,
  Content-Security-Policy, Referrer-Policy, Permissions-Policy,
  Feature-Policy, banner_server, banner_application) AND the
  `enhanced_testing` `config_*_missing` aliases (config_hsts_missing,
  config_csp_missing, config_xfo_missing, config_xcto_missing,
  config_referrer_policy_missing, config_permissions_policy_missing,
  config_xss_protection_missing). HSTS gets a richer verdict path:
  presence is necessary but max-age must be ≥ 180 days
  (`_HSTS_MIN_MAX_AGE = 15552000`) to flip the finding to
  `not_reproduced`; below that, the header is present but vulnerable
  to first-visit downgrade and the finding stays reproduced at LOW.
  Companion change: testssl.sh subprocess timeout bumped from 90s to
  180s for the cases that genuinely need a deep run (vulnerability
  suite -U on slow targets), and the kind-aware UI hint updated to
  reflect the realistic 60–180 second range.
- **2026-05-02** — **Test button: progress feedback + Quick HTTP
  probe.** The existing `Test` button on testssl/nuclei findings was
  unusable in practice — it called a slow toolkit subprocess
  (testssl.sh narrow runs on `--vulnerable` cost 60–90s against
  HTTPS targets) and the modal showed "Sending request…" with no
  elapsed-time feedback or cancel option. The page looked frozen.
  Two paired changes:
  (1) `runTest()` now takes a `kind` arg (passed in from the button
  template — `tls`, `tls_info`, `nuclei`, or `http`) and renders a
  kind-aware progress message ("Running testssl.sh narrow scan —
  3s elapsed", "Running nuclei template — 7s elapsed", etc.) plus a
  one-line honest expectation ("typically 30–90 seconds; the page is
  not frozen") and a Cancel button wired to AbortController. Cancel
  cleanly aborts the in-flight fetch and shows "Test cancelled."
  (2) New `Quick HTTP probe` button renders alongside the slow Test
  button for any finding with an evidence URL. Calls the existing
  `/finding/<id>/run_probe` endpoint (sub-second, FQDN-scoped,
  GET/HEAD only) so analysts have a fast option to verify URL
  reachability and inspect the live response — same modal as the
  AI live-probe buttons, including the echo-comparison badge and
  auto-flip-to-FP behavior when the URL matches the finding's
  evidence URL.
- **2026-05-02** — **Live probe auto-flip on echo match.** When the
  workspace's "▶ Test METHOD /path" probe runs against a URL that
  matches a finding's evidence URL AND the response is byte-identical
  to the host's cached echo signature, the finding is now atomically
  flipped to `status='false_positive'` /
  `validation_status='false_positive'` server-side, with a
  deterministic audit trail. Path equality is host+path (query string
  ignored), so a curl with `?refresh=0` still matches. The modal shows
  a yellow banner and the workspace right rail re-fetches the aside
  so the FP badge updates without a full page reload. Idempotent: a
  finding already in any non-`open` state is left alone (won't
  clobber an explicit analyst override). Companion to the live-probe
  runner shipped earlier today.
- **2026-05-02** — **Enhanced-AI finding workflow: enriched detail page,
  prompt-preview Challenge, auto-FP, split reproduction/remediation,
  live probe runner.** Six paired changes addressing the analyst-side
  experience for `enhanced_ai_testing` rows:
  (1) **Enriched detail page.** `/finding/<id>` for AI rows now renders
  an "AI Analysis" card with the scenario name, prompt id, source
  signal cited by the model, evidence type, and a prominent
  G3-auto-downgrade audit block when applicable. Description and
  remediation render through the new Jinja `md` filter so fenced
  code blocks come out as styled monospace blocks. Includes
  `_finding_reproduce.html` so the Challenge-with-LLM button has a
  home on the standalone page.
  (2) **Two-step Challenge with LLM.** New
  `GET /finding/<id>/challenge_llm/preview` returns the rendered
  system + user prompts without sending them. The button now opens a
  modal that shows the prompt text (system read-only in a
  collapsible details, user editable in a textarea) so the analyst
  can review and tweak before paying for the call. Run posts the
  edited user prompt; verdict + confidence + reasoning render in
  the same modal.
  (3) **Auto-mark false positives.** `_apply_fidelity_verdicts` now
  also sets `findings.status='false_positive'` (in addition to
  `validation_status`) when the LLM verdict is `false_positive` with
  confidence >= 0.8. Mirrors the existing toolkit-probe
  /challenge_inline behavior so a high-confidence FP verdict
  immediately drops the row out of the severity rollup, the heatmap,
  and the PDF report. Validated/inconclusive verdicts only touch
  validation_status (no auto-promotion).
  (4) **Output schema v2: split reproduction from remediation.**
  FOOTER_TEMPLATE in `enhanced_ai_prompts.py` now requires the LLM
  to emit two separate fields: `reproduction` (curl probes / PoC
  scaffolding to validate the finding) and `remediation` (concrete
  fix guidance an engineer can apply without breaking the app). The
  detail page renders these as two distinct cards, "To Reproduce"
  and "Remediation". `_insert_weakness_findings` stores reproduction
  in `raw_data.llm_reproduction` and remediation in the existing
  `remediation` column. Backward compat: legacy `recommendation`
  field (single combined block) is still accepted and routed to the
  reproduction slot. Server boot auto-restores any seeded weakness
  prompts whose stored FOOTER predates the v2 split.
  (5) **Live probe runner.** New `POST /finding/<id>/run_probe` runs
  ONE read-only HTTP request (GET / HEAD only) against ONE URL
  scoped strictly to the assessment's fqdn, with a 10-second
  timeout, no cookies, no auth. Returns status, headers, body
  excerpt (first 4 KB), and an echo-comparison badge that fingerprints
  the response against `spa_fallback`'s host signature. The detail
  page and workspace now scan every `.markdown-body pre code` block
  for curl URLs and inject a "▶ Test METHOD /path" button row after
  each block; clicking opens a probe modal with the live response,
  an "ECHO — likely FP" or "DIFFERENT — review" badge, and
  highlighted matches against the LLM's evidence quote when the
  finding's evidence is a body string rather than a URL.
  (6) **Workspace consistency.** Right-rail "Challenge with LLM"
  button now opens the same prompt-preview modal as the detail
  page (replaces the old runChallengeAsideLLM inline flow);
  `loadFinding()` re-wires probe buttons after each panel swap.
- **2026-05-02** — **Enhanced-AI fidelity hardening: dead-host echo
  detection + G3 enforcement + Challenge with LLM.** Concrete fixes
  in response to a real false-positive cluster on a Cloudhub-broken
  vhost where every path returned the same 502 + 11,755-byte body
  yet a Nikto signature still fired and the BFLA prompt escalated
  it to `high`. Five paired changes:
  (1) `app/spa_fallback.py` no longer hard-pins to status 200; it now
  fingerprints any host whose junk-path probes agree on (status, body)
  — covers the SPA-200 case AND the gateway-502 case (MuleSoft
  Cloudhub, AWS API Gateway with dead origin, CloudFront with
  unconfigured backend). The cached signature carries the canonical
  status so `is_fallback()` matches both axes.
  (2) `app/enhanced_ai.py` URL-only renderers (`_render_endpoints_by_methods`,
  `_render_oauth_endpoints`, `_render_url_processing`) now drop
  echo-tagged URLs entirely instead of inlining the `[SPA-FALLBACK ECHO]`
  tag — defense in depth, the model cannot speculate off paths it
  literally cannot see. Body-bearing renderers
  (`_render_response_samples`) keep their entries because the body
  is itself useful telemetry.
  (3) New mechanical post-processor `_g3_downgrade_if_scanner_only`
  enforces HEADER rule G3: a finding whose only `evidence` is a
  scanner URL/line claim (regex-matched) and whose severity is
  `high`/`critical` is auto-downgraded to `low` and prefixed with
  "REQUIRES MANUAL VERIFICATION:" in the title. Audit trail (original
  severity, matched pattern, reason) lands in `raw_data` so a
  reviewer can see the row was auto-touched.
  (4) New `Challenge with LLM` button in the workspace right rail and
  on the finding detail page, replacing the disabled `Challenge`
  affordance for `enhanced_ai_testing` rows (toolkit probes don't
  match those). Wired to `POST /finding/<id>/challenge_llm` →
  `enhanced_ai.run_single_finding_fidelity()`, which runs the
  configured fidelity prompt as a one-element batch and returns the
  verdict (validated / false_positive / inconclusive + confidence +
  suggested severity + reasoning) for inline rendering. Bypasses the
  bulk-pass exclusion of LLM-emitted rows so an analyst can
  re-evaluate any finding on demand.
  (5) Finding `description` and `remediation` now render as markdown
  via a new Jinja `md` filter — fenced code blocks (```bash …```)
  show as proper monospace blocks with a left accent stripe instead
  of literal triple-backticks. Markdown library added to the
  Dockerfile pip install (markdown==3.7); `app/static/style.css`
  gains a `.markdown-body` rule set scoped to the analyst-facing
  detail page.
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

- **Single sign-on (SAML 2.0) + per-user TOTP + Okta-aware setup UX.**
  Three layered authentication options ship together so an operator
  can mix-and-match per install:
  - **Local password (existing) + opt-in TOTP.** New `/security`
    page lets any signed-in user enrol an authenticator app
    (Google Authenticator, Authy, 1Password, etc.). Enrolment
    generates a 160-bit base32 secret, renders a QR via the new
    `app/totp.py` module (RFC 6238, ±1 step skew window), and
    persists the secret + `totp_enrolled_at` only after the user
    types a matching code. Subsequent logins go through a
    second-step page that gates the session-cookie issue on a valid
    6-digit code. Disable from the same page.
  - **SAML 2.0 SP via `python3-saml`.** New `app/saml.py`
    wraps OneLogin's spec-correct toolkit (libxmlsec1 signature
    verification). New routes `/saml/login` (SP-initiated),
    `/saml/acs` (assertion consumer), `/saml/sls` (single
    logout), and `/saml/metadata` (SP XML for one-shot Okta
    import). First successful SSO login JIT-creates a local user
    row with role `readonly` and `auth_source='saml'`; admins
    promote from /admin/users like any other account. SLO is
    wired so logging out of nextgen-dast also signs the user out
    of Okta when the IdP SLO URL is configured.
  - **`/admin/sso` config page with "Use Okta" relabelling.** A
    single radio toggle swaps every IdP-field label and
    placeholder into Okta's nomenclature (Identity Provider Issuer
    → IdP Entity ID, etc.) with realistic Okta-shaped examples
    (`http://www.okta.com/exk1abcd1234EFGH5678`,
    `https://example.okta.com/app/example_app/exk.../sso/saml`).
    Inline help text on every field tells the operator which
    Okta panel it maps to. SP URLs auto-derive from the install's
    request host so Okta-side config is copy/paste rather than
    hand-typed. Wire protocol is standard SAML 2.0 either way.
  - **Force-SAML toggle with file-flag escape hatch.** A second
    checkbox on /admin/sso requires SSO and disables the local
    `/login` form. Critical: existence of `/data/.saml_bypass` on
    the host re-enables `/login` regardless of the toggle, so a
    broken IdP / expired cert / Okta outage never locks the
    operator out. The bypass file lives in the data volume so it
    survives container recreate; the login page renders a yellow
    banner whenever the file is present so anyone who ends up
    there knows they are on the broken-glass path.
  - **Schema additions (idempotent).** Three columns on `users`
    (`totp_secret`, `totp_enrolled_at`, `auth_source`) and one new
    `saml_config` table with IdP / SP / mode fields. Auto-healed
    by the existing `verify_schema.py` + `schema.sql` startup
    pass; existing 2.1.1 DBs pick the columns up on first boot of
    the new image with no manual step.
  - **Image deltas.** Adds `python3-saml==1.16.0` and
    `segno==1.6.1` Python deps (the latter is a pure-Python QR
    renderer — no Pillow). Adds `libxmlsec1-dev`,
    `libxmlsec1-openssl`, `libxml2-dev`, `pkg-config`, `gcc`,
    `g++`, `make` apt packages (libxmlsec1-openssl is the runtime
    crypto backend python3-saml uses to verify IdP signatures;
    the rest are build-time).
  - **Encrypted-assertion support is deliberately deferred** —
    the SP would need its own private-key/cert pair and a key-
    rotation surface, which is the wrong shape for v1. Standard
    Okta deployments don't need it (assertions are signed and
    over TLS).

- **PDF download URL — cache-busting query string.** The
  per-assessment "Download PDF" link on the assessment detail page now
  appends `?v=<mtime>` to the report URL. The on-disk filename is
  deterministic (`<fqdn>_<finished_date>_report.pdf`), so when an
  operator re-uploaded a PDF logo or changed the PDF theme and then
  hit "Regenerate PDF", the browser would serve the previously-cached
  copy and the operator would think the new theme had not been
  applied. The new query string is the file mtime (already exposed by
  `reports.list_reports()` as `created_at`), so each regeneration
  produces a unique URL and the browser revalidates. Same pattern as
  the `/branding/logo/<kind>?v=<mtime>` URLs we already use in
  `base.html` and the branding admin pages. Template-only change in
  `app/templates/assessment_detail.html`; no Python or schema impact.

- **Branding — "Show company name" toggles per surface.** The web
  app branding page and the PDF branding page each grew a Show /
  Don't show radio control for the company name. When OFF on the
  web side, the sidebar brand text, the login splash heading, and
  the browser tab title drop the name (the logo, if uploaded, still
  identifies the install). When OFF on the PDF side, the cover-page
  H1, the running header on every page, the document `<title>`, and
  the Prepared-by row all drop the name — so a report titled
  `HackRange — Penetration Test Report` becomes simply
  `Penetration Test Report`. Stored as two independent TINYINT(1)
  columns (`web_show_company_name`, `pdf_show_company_name`) on the
  `branding` row, defaulting to 1 so existing installs keep their
  current behavior on upgrade. The Prepared-by cell continues to
  surface the contact email when the company name is hidden, so the
  row still identifies a point of contact.
- **Bulk Challenge re-evaluates `validated` findings.** Previously
  the bulk runner skipped any finding whose `validation_status` was
  `validated` OR `false_positive`, on the theory that a confident
  verdict shouldn't be re-tested. That made stale verdicts immortal:
  when a probe was updated to fix a false positive (as just happened
  with `csrf_validation`), already-validated findings stayed stuck on
  the old verdict and the user had to flip each one by hand. Bulk
  now skips only `false_positive` (intentional triage, either by the
  probe or by the analyst) and re-runs `validated` so probe updates
  propagate. A no-downgrade guard on the write path preserves a
  previously-validated verdict when the re-run returns
  `inconclusive` or `errored` (transient network blip on a confident
  finding shouldn't wipe out the verdict).
- **`csrf_validation` probe — auth-wall + SameSite refutes wapiti
  CSRF.** When the probe's anonymous GET lands on a login page
  (URL path contains `/login`/`/signin`/`/auth`, or any form on
  the page has a password input) AND the response sets
  `SameSite=Lax/Strict` on a cookie, the probe now returns
  `validated=False` with confidence 0.85 instead of bailing as
  inconclusive. Rationale: the textbook cross-site CSRF vector
  wapiti's csrf module checks for is already defeated by (a) the
  auth wall (an unauthenticated attacker can't reach the
  endpoint) and (b) SameSite enforcement (a cross-site forged
  POST can't carry the victim's session cookie). 0.85 is above
  the dispatcher's 0.8 threshold for `false_positive`, so the
  finding flips correctly. This was the verdict that finding 625
  on assessment 15 should have produced after the multi-form
  selector fix kept it from misfiring on the wrong form.
- **`csrf_validation` probe — multi-form page selection.** Real-world
  pages routinely render multiple forms (a header logout/login form
  alongside the actual state-changing form). The earlier scraper
  grabbed only the first `<form>` it encountered, so on a page like
  `/vendor-srs-details.php` -- where the header renders a logout
  form whose action is `/login.php` -- the probe wound up testing
  the LOGIN form's CSRF behavior and emitting a verdict for the
  wrong endpoint. On finding 625 (assessment 15) that produced a
  `validated=true` from a "no token field" smoking-gun fired against
  the login form. The scraper now collects every form on the page
  and selects the one whose resolved action path matches the wapiti
  target URL's path. When no form matches, the probe bails with
  `validated=None` and an explicit "could not locate the target form
  on this page" message instead of silently testing the wrong form.
- **`csrf_validation` probe — auth-wall detection.** Mirrors the
  exact scenario that produces the wapiti CSRF false positive on
  endpoints behind authentication. When the probe is pointed at a
  state-changing endpoint (e.g. `/admin/transfer`) without a valid
  session, the auth middleware short-circuits every POST with a
  redirect to the login page; with redirect-following enabled, the
  probe sees a 200 + login HTML for the baseline AND every tampering
  test. The login body has no CSRF / auth keywords, so the older
  classifier called all of them `processed`, populated
  `smoking_guns`, and rubber-stamped wapiti's bypass claim. The
  probe now records each POST's final URL and, when every test
  (baseline + tampering) lands at the login page while the POST
  endpoint differs, returns `validated=None` with a clear "endpoint
  is auth-gated; re-run from an authenticated session" message
  instead of a false `validated=True`.
- Tier-3 advanced LLM consolidation pass (per-flow deep analysis hook
  is wired in `consolidation.run` but not yet enabled).
