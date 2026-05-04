-- Author: Tim Rice <tim.j.rice@hackrange.com>
-- Part of nextgen-dast. See README.md for license and overall architecture.
-- nextgen-dast schema. Idempotent (CREATE IF NOT EXISTS).
-- Applied automatically by mariadb on first init via /docker-entrypoint-initdb.d.
-- Re-applied programmatically by scripts/reset.py for upgrades / repairs.
--
-- File layout (read top to bottom):
--   §1  CREATE TABLEs in dependency order. A fresh DB only needs §1 to be
--       fully functional — every column the application reads at runtime is
--       declared inside the CREATE.
--   §2  ALTER TABLEs. Idempotent (`ADD COLUMN IF NOT EXISTS`,
--       `ADD INDEX IF NOT EXISTS`, `MODIFY COLUMN` for ENUM widening). On a
--       fresh DB these are all no-ops because §1 already declared the
--       canonical column shape; on an existing DB they bring an older schema
--       up to date.
--   §3  Seed data (`INSERT IGNORE`). Safe to re-run.
--
-- WHY THE ORDER MATTERS: an earlier revision of this file ran the findings
-- ALTERs ahead of the findings CREATE TABLE, which silently broke fresh
-- installs (ALTER on a non-existent table aborts and leaves the DB partly
-- migrated). The strict CREATE → ALTER → SEED order in this file is the
-- guarantee that "fresh install" and "upgrade" always converge to the same
-- shape.

-- ===========================================================================
-- §1  CREATE TABLEs (canonical shape)
-- ===========================================================================

-- Branding: single-row table that drives both the live UI chrome and the
-- generated PDF report. The default `company_name` is intentionally the
-- product codename ("nextgen-dast") so a freshly-installed instance has a
-- coherent brand before an admin opens /admin/branding.
CREATE TABLE IF NOT EXISTS branding (
  id INT PRIMARY KEY DEFAULT 1,
  company_name VARCHAR(255) NOT NULL DEFAULT 'nextgen-dast',
  tagline VARCHAR(255),
  primary_color VARCHAR(16) NOT NULL DEFAULT '#5fb3d7',
  accent_color VARCHAR(16) NOT NULL DEFAULT '#7bc47f',
  -- Classification banner is optional. The column-level DEFAULT seeds a
  -- sensible value on a fresh install, but the column is NULL-able so an
  -- admin can clear the banner from /admin/branding without tripping a
  -- NOT NULL violation. base.html only renders the banner when this value
  -- is truthy, so NULL/empty correctly hides it.
  classification VARCHAR(64) DEFAULT 'CONFIDENTIAL',
  classification_color VARCHAR(16) DEFAULT '#e67373',
  header_text VARCHAR(255),
  footer_text VARCHAR(255),
  disclaimer TEXT,
  contact_email VARCHAR(255),
  header_logo_filename VARCHAR(255),
  footer_logo_filename VARCHAR(255),
  -- Web (live UI) branding overrides. Independent of PDF so an admin can keep
  -- a dark dashboard while the report uses light corporate colors.
  web_mode ENUM('dark','custom') NOT NULL DEFAULT 'dark',
  web_primary_color VARCHAR(16),
  web_accent_color VARCHAR(16),
  web_font_family VARCHAR(255),
  web_sev_critical VARCHAR(16),
  web_sev_high VARCHAR(16),
  web_sev_medium VARCHAR(16),
  web_sev_low VARCHAR(16),
  web_sev_info VARCHAR(16),
  -- Web logos. Two slots so an admin can upload a logo tuned for the
  -- dark sidebar and another tuned for the light one; base.html picks
  -- the right file based on the viewer's theme. On a single-logo
  -- deployment whichever slot is set wins for both themes.
  web_header_logo_filename VARCHAR(255),
  web_header_logo_dark_filename VARCHAR(255),
  -- PDF report branding overrides.
  pdf_font_family VARCHAR(255),
  pdf_sev_critical VARCHAR(16),
  pdf_sev_high VARCHAR(16),
  pdf_sev_medium VARCHAR(16),
  pdf_sev_low VARCHAR(16),
  pdf_sev_info VARCHAR(16),
  pdf_cover_text_color VARCHAR(16),
  pdf_header_color VARCHAR(16),
  pdf_body_color VARCHAR(16),
  -- Hyperlink color for the rendered PDF. Independent of primary color (which
  -- doubles as cover-page background) so admins can keep a pale brand primary
  -- without making linked text unreadable.
  pdf_link_color VARCHAR(16),
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  -- Three-tier authorization. 'superadmin' can do everything 'admin' can plus
  -- edit AI prompts, the system-default Enhanced-AI budget, per-user
  -- max_spend caps, and other tenant-wide knobs that affect cost and risk
  -- posture. 'admin' can read/write assessments and the /admin/* settings
  -- area but cannot change spend limits or AI prompts. 'readonly' can
  -- browse assessments but cannot mutate. The legacy is_admin column is
  -- retained for backward-compat; new code uses `role`.
  role ENUM('superadmin','admin','readonly') NOT NULL DEFAULT 'readonly',
  is_admin TINYINT(1) NOT NULL DEFAULT 0,
  -- Per-user hard cap on the Enhanced-AI per-scan budget the user is allowed
  -- to set. NULL = no per-user cap (system default applies). Enforced at
  -- assessment-submit time: server clamps the submitted budget to
  -- min(system_default, user.max_spend_usd). Editable only by superadmin.
  max_spend_usd DECIMAL(8,2) NULL,
  -- Per-user UI theme preference. 'dark' is the application default and
  -- the only theme prior to 2026-05; 'light' was added in the 2026-05
  -- dashboard pass. Stored on the user row so a saved choice follows
  -- the analyst across browsers without a client-side cookie. Read by
  -- the base template at every page render to set the body class that
  -- swaps the CSS variable palette.
  theme ENUM('dark','light') NOT NULL DEFAULT 'dark',
  disabled TINYINT(1) NOT NULL DEFAULT 0,
  last_login DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Generic key/value store. Used by the SCA / scanner-update background task
-- to persist last-run timestamps across container restarts and by anything
-- else that needs a tiny, schema-less knob without a dedicated table.
CREATE TABLE IF NOT EXISTS config (
  `key` VARCHAR(128) PRIMARY KEY,
  value TEXT,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- LLM provider endpoints. Each row is a callable backend (Anthropic native or
-- OpenAI-compatible) that the consolidation / enrichment pipelines can use.
-- `is_default=1` picks the row consulted when an assessment doesn't pin an
-- endpoint id; the application enforces single-default semantics in code.
CREATE TABLE IF NOT EXISTS llm_endpoints (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) UNIQUE NOT NULL,
  backend ENUM('anthropic','openai_compat') NOT NULL,
  base_url VARCHAR(512),
  api_key TEXT,
  model VARCHAR(128) NOT NULL,
  is_default TINYINT(1) NOT NULL DEFAULT 0,
  extra_headers TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- User-Agent strings sent by every HTTP scanner. Pre-seeded with a curated
-- list (see §3); admins can add custom entries from /user-agents.
CREATE TABLE IF NOT EXISTS user_agents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  label VARCHAR(128) UNIQUE NOT NULL,
  user_agent VARCHAR(512) NOT NULL,
  is_default TINYINT(1) NOT NULL DEFAULT 0,
  is_seeded TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per scan run. The orchestrator owns this row's lifecycle:
-- queued → running → consolidating → done/error/cancelled. The 'deleting'
-- status is set by the user-initiated delete path; the lifespan sweeper in
-- app/server.py finishes the teardown asynchronously so the HTTP request
-- returns instantly.
CREATE TABLE IF NOT EXISTS assessments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  fqdn VARCHAR(255) NOT NULL,
  scan_http TINYINT(1) NOT NULL DEFAULT 1,
  scan_https TINYINT(1) NOT NULL DEFAULT 1,
  profile ENUM('quick','standard','thorough','premium') NOT NULL DEFAULT 'standard',
  llm_tier ENUM('none','basic','advanced') NOT NULL DEFAULT 'basic',
  llm_endpoint_id INT,
  user_agent_id INT,
  creds_username VARCHAR(255),
  creds_password VARCHAR(255),
  login_url VARCHAR(512),
  status ENUM('queued','running','consolidating','done','error','cancelled','deleting')
    NOT NULL DEFAULT 'queued',
  current_step VARCHAR(255),
  scan_ids TEXT,
  total_findings INT DEFAULT 0,
  risk_score INT,
  exec_summary LONGTEXT,
  llm_cost_usd DECIMAL(10,4),
  llm_in_tokens INT,
  llm_out_tokens INT,
  error_text TEXT,
  worker_pid INT,
  -- Per-assessment toggle: when set, info-severity findings are filtered out
  -- of the findings table on the assessment page AND out of the generated
  -- PDF report. Defaults to 0 so existing assessments are unchanged on read.
  filter_info TINYINT(1) NOT NULL DEFAULT 0,
  -- Free-form caller-supplied identifier. Lets the API caller tag this
  -- assessment against their internal CMDB / Service Now / app catalog ID.
  -- Indexed so the assessments list page can filter by it cheaply.
  application_id VARCHAR(128),
  -- If this assessment was materialized by a scan_schedules row, schedule_id
  -- points back at it. NULL for one-off scans started via the /assess form
  -- or POST /api/v1/assessments.
  schedule_id INT,
  -- When 1, the orchestrator's finalize step deletes every OTHER same-fqdn
  -- assessment in (done, error, cancelled) so only the most recent run
  -- survives. Ignored while the scan is in flight.
  keep_only_latest TINYINT(1) NOT NULL DEFAULT 0,
  -- When 1, every LLM call made for this assessment (enrichment,
  -- consolidation, enhanced_ai_testing) writes its full prompt + response
  -- into llm_analyses, and a "View LLM Debug Log" button is rendered on
  -- the assessment detail page (superadmin only). Defaults to 0 because
  -- prompts and responses can contain captured cookies / tokens / PII.
  llm_debug TINYINT(1) NOT NULL DEFAULT 0,
  -- Per-scan hard cap on Enhanced-AI-Testing spend (USD). Only relevant
  -- when llm_tier='advanced'. NULL = system default applies. Server
  -- clamps to min(system_default, user.max_spend_usd) at submit. The
  -- enhanced_ai pass tracks accumulated cost via app/llm.py:cost() and
  -- short-circuits the remaining work when this cap is reached, keeping
  -- partial findings produced so far.
  enhanced_ai_budget_usd DECIMAL(8,2) NULL,
  -- Role-aware Enhanced-AI-Testing opt-in. The orchestrator only runs
  -- the enhanced_ai pass when ALL three of: profile='premium',
  -- llm_tier='advanced', enhanced_ai_testing=1. The two TEXT columns
  -- below carry the operator's description of the authenticated user's
  -- authorized scope and what that user must NOT be able to do, so the
  -- weakness-discovery and fidelity passes can suppress findings that
  -- merely demonstrate authorized capabilities (auto-tagged as
  -- 'expected_behavior' info-severity) while preserving real privilege
  -- escalations beyond scope at their original severity.
  enhanced_ai_testing TINYINT(1) NOT NULL DEFAULT 0,
  role_scope_description TEXT NULL,
  role_restrictions TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME,
  finished_at DATETIME,
  KEY idx_fqdn (fqdn),
  KEY idx_status (status),
  KEY idx_application_id (application_id),
  KEY idx_schedule_id (schedule_id),
  CONSTRAINT fk_assess_endpoint FOREIGN KEY (llm_endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- REST API tokens
--
-- Token format presented to the client is OUI-style: 12 hex octets separated
-- by colons (e.g. 4E:47:44:A1:B2:C3:D4:E5:F6:07:18:29). The first three
-- octets are the fixed NGD vendor prefix (4E:47:44 = "NGD"); the remaining
-- nine octets carry 72 bits of random secret. We store ONLY the SHA-256 hash
-- of the canonical (uppercase, colon-separated) token so a DB read does not
-- yield usable credentials. The `prefix` column stores the first six octets
-- (vendor OUI + first 3 random) so the UI can display "4E:47:44:A1:B2:C3:…"
-- next to the token row without revealing the secret half.
--
-- `allowed_ips` is a comma-separated list of IPs / CIDR ranges. An empty
-- list means *no source can use this token* (fail-closed) — the issuer
-- must explicitly whitelist a caller. The API code parses it on every
-- request and rejects 403 if the source IP doesn't match any entry.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  label VARCHAR(128) NOT NULL,
  prefix VARCHAR(32) NOT NULL,
  token_hash CHAR(64) NOT NULL,
  allowed_ips TEXT NOT NULL,
  disabled TINYINT(1) NOT NULL DEFAULT 0,
  last_used_at DATETIME,
  last_used_ip VARCHAR(64),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by_user_id INT NULL,
  notes TEXT,
  KEY idx_token_hash (token_hash),
  CONSTRAINT fk_apitoken_user FOREIGN KEY (created_by_user_id)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per finding across every assessment. The orchestrator inserts
-- normalized rows during consolidation; the analyst-facing pages let users
-- triage status (open / confirmed / false_positive / accepted_risk / fixed)
-- and the toolkit pages drive the validation_* columns when a probe is run.
CREATE TABLE IF NOT EXISTS findings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  assessment_id INT NOT NULL,
  source_tool VARCHAR(64) NOT NULL,
  source_scan_id VARCHAR(128),
  severity ENUM('critical','high','medium','low','info')
    NOT NULL DEFAULT 'info',
  owasp_category VARCHAR(64),
  cwe VARCHAR(32),
  cvss VARCHAR(16),
  title VARCHAR(512) NOT NULL,
  description TEXT,
  evidence_url VARCHAR(1024),
  evidence_method VARCHAR(16),
  evidence_request_path VARCHAR(512),
  evidence_response_path VARCHAR(512),
  remediation TEXT,
  status ENUM('open','confirmed','false_positive','accepted_risk','fixed')
    NOT NULL DEFAULT 'open',
  raw_data LONGTEXT,
  -- Number of times this same finding signature was observed in the same
  -- assessment. Lets the report renderer collapse duplicates without losing
  -- visibility into how often a flaw fires.
  seen_count INT NOT NULL DEFAULT 1,
  -- Validation pipeline (toolkit probes). 'unvalidated' is the default when
  -- a finding is freshly imported; the toolkit pages flip this to validated /
  -- false_positive / inconclusive / errored as probes run.
  validation_status ENUM('unvalidated','validated','false_positive','inconclusive','errored')
    NOT NULL DEFAULT 'unvalidated',
  validation_probe VARCHAR(64),
  validation_run_at DATETIME,
  validation_evidence LONGTEXT,
  -- Pointer into finding_enrichment for cached LLM remediation guidance.
  -- NULL until the enrichment pipeline runs for this finding's signature.
  enrichment_id INT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_assessment (assessment_id),
  KEY idx_severity (severity),
  KEY idx_tool (source_tool),
  KEY idx_enrichment (enrichment_id),
  CONSTRAINT fk_finding_assessment FOREIGN KEY (assessment_id)
    REFERENCES assessments(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Cache of remediation guidance per finding *type* (signature), not per
-- finding row. Same nuclei template / nikto line / wapiti category across
-- many assessments shares one row here. LLM only runs on the first miss.
-- Manual edits set source='manual' and is_locked=1 to prevent automatic
-- overwrite on the next assessment.
CREATE TABLE IF NOT EXISTS finding_enrichment (
  id INT AUTO_INCREMENT PRIMARY KEY,
  signature_hash CHAR(64) UNIQUE NOT NULL,
  source_tool VARCHAR(64) NOT NULL,
  title_norm VARCHAR(512) NOT NULL,
  cwe VARCHAR(32),
  owasp_category VARCHAR(64),
  source ENUM('static','llm','manual') NOT NULL DEFAULT 'static',
  is_locked TINYINT(1) NOT NULL DEFAULT 0,
  description_long TEXT,
  impact TEXT,
  remediation_long TEXT,
  remediation_steps TEXT,
  code_example TEXT,
  references_json TEXT,
  user_story TEXT,
  bug_report_md TEXT,
  jira_summary VARCHAR(255),
  suggested_priority ENUM('p0','p1','p2','p3','p4'),
  llm_endpoint_id INT NULL,
  llm_model VARCHAR(128),
  llm_in_tokens INT,
  llm_out_tokens INT,
  edited_by_user_id INT NULL,
  notes TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_tool (source_tool),
  KEY idx_owasp (owasp_category),
  CONSTRAINT fk_enrich_endpoint FOREIGN KEY (llm_endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL,
  CONSTRAINT fk_enrich_user FOREIGN KEY (edited_by_user_id)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Software Composition Analysis (SCA)
--
-- Three tables make up the SCA layer:
--
--   sca_packages            — every (ecosystem, name, version) tuple we have
--                             ever observed in any assessment, with first /
--                             last seen timestamps. Lets the admin SCA page
--                             list "what libraries are out there in our
--                             customer base, and how stale are they."
--
--   sca_vulnerabilities     — the cached vulnerability database. One row
--                             per (ecosystem, package, vulnerable_range,
--                             cve_id). Populated from multiple feeds:
--                               - 'osv'    OSV.dev offline DB
--                               - 'retire' retire.js jsrepository.json
--                               - 'nuclei' nuclei-templates CVE coverage
--                               - 'llm'    on-demand LLM gap-fill for
--                                          packages with no feed coverage
--                               - 'manual' admin override (is_locked=1
--                                          prevents automatic refresh)
--                             SCA findings consult this table FIRST and only
--                             escalate to a paid LLM call when no row exists.
--
--   sca_assessment_packages — per-assessment audit trail of which packages
--                             were observed where, so the report renderer
--                             can show "jQuery 3.4.1 was loaded from
--                             /static/js/jquery.min.js on this scan."
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sca_packages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ecosystem VARCHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(128) NOT NULL,
  latest_version VARCHAR(128),
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_eco_name_ver (ecosystem, name, version),
  KEY idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sca_vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ecosystem VARCHAR(32) NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  -- Free-form version range string in OSV / npm-semver / retire.js notation
  -- (e.g. ">=1.0.3 <3.5.0", "<3.5.0", "= 1.12.4"). Resolved client-side by
  -- app/sca.py before declaring a hit.
  vulnerable_range VARCHAR(255) NOT NULL,
  cve_id VARCHAR(64),
  ghsa_id VARCHAR(64),
  severity ENUM('critical','high','medium','low','info','unknown')
    NOT NULL DEFAULT 'unknown',
  cvss VARCHAR(16),
  summary VARCHAR(512),
  description TEXT,
  fixed_version VARCHAR(128),
  references_json TEXT,
  source ENUM('osv','retire','nuclei','llm','manual') NOT NULL,
  is_locked TINYINT(1) NOT NULL DEFAULT 0,
  llm_endpoint_id INT NULL,
  llm_model VARCHAR(128),
  fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  notes TEXT,
  -- A cve_id can apply to multiple version ranges of the same package
  -- (e.g. fixed in 3.5 vs 4.0 backports). Allow duplicates per range.
  UNIQUE KEY uk_eco_pkg_range_cve (ecosystem, package_name, vulnerable_range, cve_id),
  KEY idx_pkg (ecosystem, package_name),
  KEY idx_cve (cve_id),
  KEY idx_severity (severity),
  CONSTRAINT fk_sca_vuln_endpoint FOREIGN KEY (llm_endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sca_assessment_packages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  assessment_id INT NOT NULL,
  ecosystem VARCHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(128) NOT NULL,
  -- Where on the target the package was observed: a JS URL, a manifest
  -- path (/package.json), a HTML script tag, etc. Free-form for the
  -- report renderer to display verbatim.
  source_url VARCHAR(1024),
  -- How we identified this package:
  --   'retire'         retire.js fingerprint match
  --   'manifest'       direct read of an exposed package manifest
  --   'lockfile'       parsed from an exposed lockfile
  --   'sourcemap'      reconstructed from an exposed *.map file
  --   'html_script'    versioned URL in a <script src=...> tag
  detection_method VARCHAR(32) NOT NULL,
  -- JSON list of CVE ids matched against sca_vulnerabilities at scan time.
  -- Cached on the row so the report doesn't re-query the vuln cache to
  -- render the package's status months later.
  matched_cves_json TEXT,
  observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_assessment (assessment_id),
  KEY idx_pkg (ecosystem, name, version),
  CONSTRAINT fk_sca_apkg_assess FOREIGN KEY (assessment_id)
    REFERENCES assessments(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- LLM analysis log. One row per (target_type, target_id) call, capturing
-- the model invoked, tokens, raw response, and any extracted findings.
-- Used by the LLM admin page and the per-assessment cost rollups.
CREATE TABLE IF NOT EXISTS llm_analyses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  -- target_type names which pipeline produced this row. 'scan' is the
  -- consolidation roll-up; 'flow' is reserved for per-flow advanced
  -- analyses; 'enrichment' is per-finding catalog enrichment;
  -- 'enhanced_ai_weakness' is one weakness-discovery scenario emitted
  -- by the enhanced_ai pass; 'enhanced_ai_fidelity' is a fidelity batch.
  target_type ENUM('flow','scan','enrichment','enhanced_ai_weakness','enhanced_ai_fidelity')
    NOT NULL,
  target_id VARCHAR(128) NOT NULL,
  -- Direct foreign key to the owning assessment so the LLM debug log page
  -- can stream every call for an assessment in chronological order with
  -- one indexed query — without parsing the polymorphic target_id. NULL
  -- only for orphan / pre-migration rows.
  assessment_id INT NULL,
  endpoint_id INT,
  endpoint_name VARCHAR(128),
  model VARCHAR(128),
  status ENUM('running','done','error') NOT NULL,
  request_tokens INT,
  response_tokens INT,
  -- Full request prompt sent to the LLM. Only populated when the owning
  -- assessment had llm_debug=1 at the time of the call. NULL otherwise so
  -- the debug-log storage cost is opt-in. Captures the rendered user
  -- template; the system prompt is reconstructible from ai_prompts at
  -- view time, so we only store the user-facing portion to halve storage.
  request_prompt LONGTEXT,
  raw_response LONGTEXT,
  findings_json LONGTEXT,
  error_text TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME,
  KEY idx_target (target_type, target_id),
  KEY idx_assessment (assessment_id, created_at),
  CONSTRAINT fk_endpoint FOREIGN KEY (endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL,
  CONSTRAINT fk_llm_assess FOREIGN KEY (assessment_id)
    REFERENCES assessments(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Editable LLM prompts used by the Enhanced-AI-Testing pass.
--
-- Each row is one prompt scenario in a named slot. A slot is the runtime hook
-- the orchestrator dispatches to:
--   advanced_ai_testing.weakness_discovery — one LLM call per active row,
--       each call sees the full scan telemetry and emits a JSON array of
--       findings. Multiple rows let the operator stack scenario angles
--       (Business Logic, BOLA, SSRF, Race Conditions, …) without code
--       changes; the orchestrator iterates rows ordered by sort_order.
--   advanced_ai_testing.fidelity — per-finding fidelity evaluator; one row
--       expected (the default), but multiple are supported for A/B work.
--
-- The 21 default rows ship pre-seeded by app/enhanced_ai_prompts.py (20
-- weakness-discovery scenarios + 1 fidelity evaluator). is_seeded
-- marks "shipped with the product" so the AI-Prompts admin page can render a
-- "Restore to default" button for those slots — restore reads the in-code
-- defaults, not a DB row, so a deleted seeded prompt can always be brought
-- back. fire_when is a small expression evaluated against a per-assessment
-- telemetry summary (e.g. "has_creds AND findings_count >= 3"); a row whose
-- expression evaluates false is silently skipped, so no LLM cost is incurred
-- when a scenario has no input data.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_prompts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slot VARCHAR(96) NOT NULL,
  name VARCHAR(128) NOT NULL,
  description TEXT,
  -- Full system prompt. Cacheable via Anthropic prompt caching when the
  -- backend is anthropic; the per-scenario user prompt varies so only the
  -- system block is cached.
  system_prompt LONGTEXT NOT NULL,
  -- Per-scenario user-prompt template. Substitutable {placeholder} names
  -- are validated against a per-slot allowlist defined in code. Unknown
  -- placeholders render as the literal string `{placeholder=??unknown??}`
  -- so a typo never crashes the run.
  user_template LONGTEXT NOT NULL,
  -- Finding category emitted by this scenario (only used by weakness-
  -- discovery slots; ignored by fidelity). Drives the `category` field of
  -- the findings the LLM emits — kept on the row so the operator can
  -- relabel without changing the prompt body.
  category VARCHAR(64),
  -- Boolean expression evaluated against the per-assessment telemetry
  -- summary at runtime. Empty string / NULL means "always fire". Allowed
  -- terms are documented in app/enhanced_ai.py:_eval_fire_when.
  fire_when VARCHAR(255),
  -- Display + execution order within a slot. Lower runs first.
  sort_order INT NOT NULL DEFAULT 100,
  -- Optional batch size for fidelity-style scenarios that group multiple
  -- findings into one LLM call. Ignored for weakness-discovery scenarios
  -- (which always send the full telemetry once per call).
  batch_size INT NULL,
  -- 0 disables the row without deleting it. Useful for temporarily
  -- pausing a costly scenario without losing its prompt text.
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  -- 1 marks rows seeded from in-code defaults (mirrors user_agents
  -- pattern). Restore-to-default re-seeds these from the in-code defaults
  -- in app/enhanced_ai_prompts.py.
  is_seeded TINYINT(1) NOT NULL DEFAULT 0,
  -- Bumped on every save so the audit log can reference a specific
  -- iteration of the prompt.
  version INT NOT NULL DEFAULT 1,
  created_by_user_id INT NULL,
  updated_by_user_id INT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_slot_name (slot, name),
  KEY idx_slot_order (slot, is_active, sort_order),
  CONSTRAINT fk_prompt_creator FOREIGN KEY (created_by_user_id)
    REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_prompt_updater FOREIGN KEY (updated_by_user_id)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Scheduled scans
--
-- A scan_schedules row is a recipe (target + profile + creds + LLM tier)
-- plus a cron expression. The lifespan sweeper in app/server.py calls
-- app.schedules.tick() once per minute; due rows are materialized into a
-- normal `assessments` row (with schedule_id pointing back here) and the
-- existing orchestrator subprocess is spawned exactly as for a manual scan.
--
-- Cron expressions are standard 5-field syntax (croniter), interpreted as
-- UTC. `next_run_at` is recomputed by the tick after every fire and is the
-- only column the sweeper reads to decide what's due.
--
-- `keep_only_latest` carries through to every materialized assessment so
-- the dedupe sweep happens automatically when each scheduled scan finishes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_schedules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  fqdn VARCHAR(255) NOT NULL,
  scan_http TINYINT(1) NOT NULL DEFAULT 1,
  scan_https TINYINT(1) NOT NULL DEFAULT 1,
  profile ENUM('quick','standard','thorough','premium') NOT NULL DEFAULT 'standard',
  llm_tier ENUM('none','basic','advanced') NOT NULL DEFAULT 'none',
  llm_endpoint_id INT NULL,
  user_agent_id INT NULL,
  creds_username VARCHAR(255) NULL,
  creds_password VARCHAR(255) NULL,
  login_url VARCHAR(512) NULL,
  application_id VARCHAR(128) NULL,
  -- Standard 5-field cron expression in UTC. Validated by croniter on insert.
  cron_expr VARCHAR(64) NOT NULL,
  -- Optional time-window controls. start_after suppresses fires before this
  -- moment (useful for pre-creating a schedule that should activate later);
  -- end_before disables the schedule once the wall clock passes it.
  start_after DATETIME NULL,
  end_before DATETIME NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  -- When 1, a tick that finds a same-fqdn assessment already in flight
  -- (queued/running/consolidating) skips firing this round. Prevents the
  -- daily-on-premium scenario where a 12-hour scan stacks on top of itself.
  skip_if_running TINYINT(1) NOT NULL DEFAULT 1,
  -- Copied into every materialized assessment. The dedupe sweep then runs
  -- automatically when the assessment finishes.
  keep_only_latest TINYINT(1) NOT NULL DEFAULT 0,
  -- Copied into every materialized assessment so scheduled scans can inherit
  -- the same Enhanced-AI debug + budget settings as a one-off scan would.
  -- See assessments.llm_debug / assessments.enhanced_ai_budget_usd for
  -- semantics. Only meaningful when llm_tier='advanced'; ignored otherwise.
  llm_debug TINYINT(1) NOT NULL DEFAULT 0,
  enhanced_ai_budget_usd DECIMAL(8,2) NULL,
  -- Carried into every materialized assessment. See assessments table
  -- for the semantics of these three columns.
  enhanced_ai_testing TINYINT(1) NOT NULL DEFAULT 0,
  role_scope_description TEXT NULL,
  role_restrictions TEXT NULL,
  next_run_at DATETIME NULL,
  last_run_at DATETIME NULL,
  last_assessment_id INT NULL,
  created_by INT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_due (enabled, next_run_at),
  CONSTRAINT fk_sched_endpoint FOREIGN KEY (llm_endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL,
  CONSTRAINT fk_sched_user FOREIGN KEY (created_by)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Boot-time data-migration bookkeeping. Each row records that one
-- migration in app/migrations.py:MIGRATIONS has been applied to this
-- database. Pending migrations run on every container start; rows with
-- status='success' are skipped. A failed migration writes status='failed'
-- with the exception text in `notes` so an operator can diagnose, fix,
-- and retry on the next boot. See app/migrations.py for the runner.
CREATE TABLE IF NOT EXISTS schema_migrations (
  id VARCHAR(64) PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      ON UPDATE CURRENT_TIMESTAMP,
  status ENUM('success','failed') NOT NULL DEFAULT 'success',
  notes TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ===========================================================================
-- §2  ALTER TABLEs (migrations for existing DBs)
--
-- Every statement in this section is idempotent: ADD COLUMN IF NOT EXISTS,
-- ADD INDEX IF NOT EXISTS, and MODIFY COLUMN for ENUM widening. On a fresh
-- DB they are no-ops because §1 already declared the canonical shape. On
-- an existing DB they bring the schema forward without dropping data.
-- ===========================================================================

-- Older DBs may have an assessments row that pre-dates user_agent_id, the
-- info-filter toggle, the 'premium' profile value, the 'deleting' status,
-- the application_id column, or the new schedule_id / keep_only_latest
-- columns. All of these are no-ops on a fresh install.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS user_agent_id INT;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS filter_info TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE assessments MODIFY COLUMN profile
  ENUM('quick','standard','thorough','premium') NOT NULL DEFAULT 'standard';
ALTER TABLE assessments MODIFY COLUMN status
  ENUM('queued','running','consolidating','done','error','cancelled','deleting')
  NOT NULL DEFAULT 'queued';
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS application_id VARCHAR(128);
ALTER TABLE assessments ADD INDEX IF NOT EXISTS idx_application_id (application_id);
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS schedule_id INT NULL;
ALTER TABLE assessments ADD INDEX IF NOT EXISTS idx_schedule_id (schedule_id);
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS keep_only_latest TINYINT(1) NOT NULL DEFAULT 0;

-- Older findings rows pre-date the seen_count rollup, the validation
-- pipeline, and the enrichment pointer.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS seen_count INT NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_status
  ENUM('unvalidated','validated','false_positive','inconclusive','errored')
  NOT NULL DEFAULT 'unvalidated';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_probe VARCHAR(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_run_at DATETIME;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_evidence LONGTEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_id INT NULL;
ALTER TABLE findings ADD INDEX IF NOT EXISTS idx_enrichment (enrichment_id);

-- Granular branding migrations: split web vs PDF, per-severity colors, font.
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_mode ENUM('dark','custom') NOT NULL DEFAULT 'dark';
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_primary_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_accent_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_font_family VARCHAR(255);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_sev_critical VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_sev_high VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_sev_medium VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_sev_low VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_sev_info VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_header_logo_filename VARCHAR(255);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS web_header_logo_dark_filename VARCHAR(255);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_font_family VARCHAR(255);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_critical VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_high VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_medium VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_low VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_info VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_cover_text_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_header_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_body_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_link_color VARCHAR(16);

-- Make the classification banner optional on existing DBs. Earlier installs
-- created these columns NOT NULL, which made it impossible to clear the
-- banner via /admin/branding (the form handler converts an empty string to
-- NULL and the UPDATE then 500s). The MODIFY below relaxes the constraint;
-- existing CONFIDENTIAL values are preserved.
ALTER TABLE branding MODIFY COLUMN classification VARCHAR(64) DEFAULT 'CONFIDENTIAL';
ALTER TABLE branding MODIFY COLUMN classification_color VARCHAR(16) DEFAULT '#e67373';

-- Older users rows pre-date the role / disabled / last_login columns. The
-- UPDATE below migrates legacy is_admin=1 accounts to the new role column.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role ENUM('admin','readonly') NOT NULL DEFAULT 'readonly';
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login DATETIME;
UPDATE users SET role='admin' WHERE is_admin = 1 AND role = 'readonly';

-- Enhanced-AI-Testing additions. Widen the role enum so existing 2.1.1 DBs
-- pick up the new 'superadmin' tier without losing data; MODIFY is idempotent
-- when the target definition is identical, so re-applying on every boot is
-- harmless. The one-shot bump of existing role='admin' rows to 'superadmin'
-- lives in app/migrations.py so it runs exactly once per database (a plain
-- UPDATE here would re-promote anyone a superadmin had intentionally
-- demoted on subsequent boots).
ALTER TABLE users MODIFY COLUMN role
  ENUM('superadmin','admin','readonly') NOT NULL DEFAULT 'readonly';
ALTER TABLE users ADD COLUMN IF NOT EXISTS max_spend_usd DECIMAL(8,2) NULL;
-- 2026-05-02: per-user UI theme preference. Default 'dark' matches the
-- pre-existing visual identity of the app; the light palette was added
-- alongside the dashboard overhaul. Existing users keep dark until they
-- flip the toggle. Idempotent on reapply.
ALTER TABLE users ADD COLUMN IF NOT EXISTS theme
  ENUM('dark','light') NOT NULL DEFAULT 'dark';

ALTER TABLE assessments ADD COLUMN IF NOT EXISTS llm_debug
  TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS enhanced_ai_budget_usd
  DECIMAL(8,2) NULL;

ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS llm_debug
  TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS enhanced_ai_budget_usd
  DECIMAL(8,2) NULL;

-- Role-aware Enhanced-AI-Testing additions (2026-05-03). The new
-- enhanced_ai_testing flag is the third gate (alongside profile=premium
-- and llm_tier=advanced) that the orchestrator checks before running
-- the enhanced_ai pass. The two TEXT columns carry the authenticated
-- user's authorized scope and explicit out-of-scope restrictions, fed
-- into both the weakness-discovery and fidelity prompt passes so the
-- model can suppress findings that merely demonstrate authorized
-- behavior (auto-tagged as 'expected_behavior' info-severity).
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS enhanced_ai_testing
  TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS role_scope_description
  TEXT NULL;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS role_restrictions
  TEXT NULL;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS enhanced_ai_testing
  TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS role_scope_description
  TEXT NULL;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS role_restrictions
  TEXT NULL;

-- llm_analyses additions. Widen target_type so the new pipelines
-- (enrichment, enhanced_ai_weakness, enhanced_ai_fidelity) can write to
-- the same table; add request_prompt for debug-mode capture; add
-- assessment_id so the LLM Debug Log page is one indexed query.
ALTER TABLE llm_analyses MODIFY COLUMN target_type
  ENUM('flow','scan','enrichment','enhanced_ai_weakness','enhanced_ai_fidelity')
  NOT NULL;
ALTER TABLE llm_analyses ADD COLUMN IF NOT EXISTS request_prompt LONGTEXT;
ALTER TABLE llm_analyses ADD COLUMN IF NOT EXISTS assessment_id INT NULL;
ALTER TABLE llm_analyses ADD INDEX IF NOT EXISTS idx_assessment
  (assessment_id, created_at);
-- Note: the FK from llm_analyses.assessment_id to assessments.id only
-- exists on databases created from this schema fresh; existing 2.1.1 DBs
-- that get the column ADDed don't pick it up, since MariaDB's ADD
-- CONSTRAINT is not idempotent. The app-level assessment-delete path
-- in app/cleanup.py:cleanup_assessment explicitly deletes dependent
-- llm_analyses rows so cascade behaviour is identical regardless.

-- ===========================================================================
-- §3  Seed data (INSERT IGNORE — safe on every boot)
-- ===========================================================================

-- Single-row branding table: ensure a default row always exists.
INSERT IGNORE INTO branding (id) VALUES (1);

-- Curated User-Agent string set, seeded on first boot. is_seeded=1 marks
-- these as "shipped with the product" so admins can distinguish them from
-- custom entries they add later.
INSERT IGNORE INTO user_agents (label, user_agent, is_default, is_seeded) VALUES
  ('Chrome on Windows',   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 1, 1),
  ('Firefox on Windows',  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0', 0, 1),
  ('Edge on Windows',     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0', 0, 1),
  ('Chrome on macOS',     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 0, 1),
  ('Safari on macOS',     'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Safari/605.1.15', 0, 1),
  ('Chrome on Android',   'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36', 0, 1),
  ('Safari on iPhone',    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1', 0, 1),
  ('Googlebot',           'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 0, 1),
  ('Bingbot',             'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 0, 1),
  ('curl',                'curl/8.5.0', 0, 1),
  ('nextgen-dast',        'nextgen-dast/1.0 (authorized DAST scanner)', 0, 1);

-- Single-row config keys consulted by the SCA / scanner-update background
-- task. Showing them up on a fresh DB lets the admin SCA page render with
-- defaults rather than blanks.
INSERT IGNORE INTO config (`key`, value) VALUES
  ('sca_update_interval_hours', '24'),
  ('sca_signature_max_age_days', '7'),
  ('sca_last_updated_at', ''),
  ('sca_last_update_log', ''),
  -- System-wide default for the per-scan Enhanced-AI-Testing budget (USD).
  -- Editable on /admin/llm by superadmin only. Per-user max_spend_usd
  -- (users.max_spend_usd) clamps below this when set, so a user without
  -- a personal cap inherits the system default at submit time.
  ('advanced_ai_budget_default_usd', '25'),
  -- System-wide default UI theme (one of: 'dark', 'light'). Drives the
  -- pre-login experience (login page palette + which web-logo slot is
  -- chosen on the login screen) and also serves as the fallback for any
  -- signed-in user who has not picked a personal theme. Each user can
  -- still override their own preference via /theme; this row only sets
  -- the default that new visitors and unauthenticated views see.
  ('default_theme', 'dark');
