-- Author: Tim Rice <tim.j.rice@hackrange.com>
-- Part of nextgen-dast. See README.md for license and overall architecture.
-- nextgen-dast schema. Idempotent (CREATE IF NOT EXISTS).
-- Applied automatically by mariadb on first init via /docker-entrypoint-initdb.d.
-- Re-applied programmatically by scripts/reset.py for upgrades / repairs.

CREATE TABLE IF NOT EXISTS branding (
  id INT PRIMARY KEY DEFAULT 1,
  company_name VARCHAR(255) NOT NULL DEFAULT 'Pentest Proxy',
  tagline VARCHAR(255),
  primary_color VARCHAR(16) NOT NULL DEFAULT '#5fb3d7',
  accent_color VARCHAR(16) NOT NULL DEFAULT '#7bc47f',
  classification VARCHAR(64) NOT NULL DEFAULT 'CONFIDENTIAL',
  classification_color VARCHAR(16) NOT NULL DEFAULT '#e67373',
  header_text VARCHAR(255),
  footer_text VARCHAR(255),
  disclaimer TEXT,
  contact_email VARCHAR(255),
  header_logo_filename VARCHAR(255),
  footer_logo_filename VARCHAR(255),
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Single-row table: ensure a default row always exists
INSERT IGNORE INTO branding (id) VALUES (1);

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','readonly') NOT NULL DEFAULT 'readonly',
  is_admin TINYINT(1) NOT NULL DEFAULT 0,
  disabled TINYINT(1) NOT NULL DEFAULT 0,
  last_login DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS config (
  `key` VARCHAR(128) PRIMARY KEY,
  value TEXT,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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

CREATE TABLE IF NOT EXISTS user_agents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  label VARCHAR(128) UNIQUE NOT NULL,
  user_agent VARCHAR(512) NOT NULL,
  is_default TINYINT(1) NOT NULL DEFAULT 0,
  is_seeded TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME,
  finished_at DATETIME,
  KEY idx_fqdn (fqdn),
  KEY idx_status (status),
  CONSTRAINT fk_assess_endpoint FOREIGN KEY (llm_endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE assessments ADD COLUMN IF NOT EXISTS user_agent_id INT;
-- Per-assessment toggle: when set, info-severity findings are filtered
-- out of the findings table on the assessment page AND out of the
-- generated PDF report. Defaults to 0 so existing assessments are
-- unchanged on the next read.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS filter_info TINYINT(1) NOT NULL DEFAULT 0;
-- Premium profile: thorough + enhanced_testing probe pass. Existing
-- profile column was the 3-value ENUM; widen it. ALTER MODIFY is
-- idempotent for ENUM additions in MariaDB / MySQL.
ALTER TABLE assessments MODIFY COLUMN profile
  ENUM('quick','standard','thorough','premium') NOT NULL DEFAULT 'standard';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS seen_count INT NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_status
  ENUM('unvalidated','validated','false_positive','inconclusive','errored')
  NOT NULL DEFAULT 'unvalidated';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_probe VARCHAR(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_run_at DATETIME;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_evidence LONGTEXT;
-- Granular branding: split web vs PDF, per-severity colors, font choice
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
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_font_family VARCHAR(255);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_critical VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_high VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_medium VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_low VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_sev_info VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_cover_text_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_header_color VARCHAR(16);
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_body_color VARCHAR(16);
-- Hyperlink color for the rendered PDF report. Independent of primary
-- color (which doubles as cover-page background) so admins can keep a
-- pale brand primary without making linked text unreadable.
ALTER TABLE branding ADD COLUMN IF NOT EXISTS pdf_link_color VARCHAR(16);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role ENUM('admin','readonly') NOT NULL DEFAULT 'readonly';
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login DATETIME;
-- Migrate existing is_admin=1 accounts to the new role column
UPDATE users SET role='admin' WHERE is_admin = 1 AND role = 'readonly';
-- Add 'deleting' to the assessments status enum for the async sweeper
ALTER TABLE assessments MODIFY COLUMN status
  ENUM('queued','running','consolidating','done','error','cancelled','deleting')
  NOT NULL DEFAULT 'queued';
-- Optional caller-supplied application identifier. Free-form so it can carry
-- the customer's CMDB / Service Now / internal app catalog ID without us
-- having to model their taxonomy. Indexed so the assessments list page can
-- filter by it cheaply.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS application_id VARCHAR(128);
ALTER TABLE assessments ADD INDEX IF NOT EXISTS idx_application_id (application_id);

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
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_assessment (assessment_id),
  KEY idx_severity (severity),
  KEY idx_tool (source_tool),
  CONSTRAINT fk_finding_assessment FOREIGN KEY (assessment_id)
    REFERENCES assessments(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_id INT NULL;
ALTER TABLE findings ADD INDEX IF NOT EXISTS idx_enrichment (enrichment_id);

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

CREATE TABLE IF NOT EXISTS llm_analyses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('flow','scan') NOT NULL,
  target_id VARCHAR(128) NOT NULL,
  endpoint_id INT,
  endpoint_name VARCHAR(128),
  model VARCHAR(128),
  status ENUM('running','done','error') NOT NULL,
  request_tokens INT,
  response_tokens INT,
  raw_response LONGTEXT,
  findings_json LONGTEXT,
  error_text TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME,
  KEY idx_target (target_type, target_id),
  CONSTRAINT fk_endpoint FOREIGN KEY (endpoint_id)
    REFERENCES llm_endpoints(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
