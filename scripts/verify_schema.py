"""
Author: Tim Rice <tim.j.rice@hackrange.com>
Part of nextgen-dast. See README.md for license and overall architecture.

Schema drift detector. Run on container start (or manually) to confirm the
live MariaDB has every table and every column the application expects to
read at runtime.

This guards against the failure mode that broke fresh installs in earlier
revisions: an out-of-order ALTER TABLE silently fails and leaves the DB
"mostly there" but missing a few columns. The application then runs but
crashes on the first row read that touches a missing column.

Usage:
    python -m scripts.verify_schema           # exits 0 if clean, 1 with a
                                              # human-readable diff otherwise.

The expected shape lives in EXPECTED_TABLES below — kept in lock-step with
db/schema.sql §1 (CREATE TABLE blocks). Add a column there when you add it
to the schema; the next deploy will catch any DB that didn't pick it up.
"""
from __future__ import annotations

import sys
from typing import Dict, Set


# ---------------------------------------------------------------------------
# Expected canonical shape. Mirror of db/schema.sql §1. Add a column here
# whenever you add one to the CREATE TABLE — that's how we catch any host
# that was last migrated against an older schema.
# ---------------------------------------------------------------------------
EXPECTED_TABLES: Dict[str, Set[str]] = {
    "branding": {
        "id", "company_name", "tagline", "primary_color", "accent_color",
        "classification", "classification_color", "header_text",
        "footer_text", "disclaimer", "contact_email",
        "header_logo_filename", "footer_logo_filename",
        "web_mode", "web_primary_color", "web_accent_color",
        "web_font_family", "web_sev_critical", "web_sev_high",
        "web_sev_medium", "web_sev_low", "web_sev_info",
        "web_header_logo_filename",
        "pdf_font_family", "pdf_sev_critical", "pdf_sev_high",
        "pdf_sev_medium", "pdf_sev_low", "pdf_sev_info",
        "pdf_cover_text_color", "pdf_header_color", "pdf_body_color",
        "pdf_link_color",
        "updated_at",
    },
    "users": {
        "id", "username", "password_hash", "role", "is_admin",
        "disabled", "last_login", "created_at", "updated_at",
    },
    "config": {"key", "value", "updated_at"},
    "llm_endpoints": {
        "id", "name", "backend", "base_url", "api_key", "model",
        "is_default", "extra_headers", "created_at", "updated_at",
    },
    "user_agents": {
        "id", "label", "user_agent", "is_default", "is_seeded",
        "created_at",
    },
    "assessments": {
        "id", "fqdn", "scan_http", "scan_https", "profile", "llm_tier",
        "llm_endpoint_id", "user_agent_id", "creds_username",
        "creds_password", "login_url", "status", "current_step",
        "scan_ids", "total_findings", "risk_score", "exec_summary",
        "llm_cost_usd", "llm_in_tokens", "llm_out_tokens", "error_text",
        "worker_pid", "filter_info", "application_id",
        "schedule_id", "keep_only_latest",
        "created_at", "started_at", "finished_at",
    },
    "api_tokens": {
        "id", "label", "prefix", "token_hash", "allowed_ips", "disabled",
        "last_used_at", "last_used_ip", "created_at",
        "created_by_user_id", "notes",
    },
    "findings": {
        "id", "assessment_id", "source_tool", "source_scan_id", "severity",
        "owasp_category", "cwe", "cvss", "title", "description",
        "evidence_url", "evidence_method", "evidence_request_path",
        "evidence_response_path", "remediation", "status", "raw_data",
        "seen_count", "validation_status", "validation_probe",
        "validation_run_at", "validation_evidence", "enrichment_id",
        "created_at",
    },
    "finding_enrichment": {
        "id", "signature_hash", "source_tool", "title_norm", "cwe",
        "owasp_category", "source", "is_locked", "description_long",
        "impact", "remediation_long", "remediation_steps", "code_example",
        "references_json", "user_story", "bug_report_md", "jira_summary",
        "suggested_priority", "llm_endpoint_id", "llm_model",
        "llm_in_tokens", "llm_out_tokens", "edited_by_user_id", "notes",
        "created_at", "updated_at",
    },
    "sca_packages": {
        "id", "ecosystem", "name", "version", "latest_version",
        "first_seen", "last_seen",
    },
    "sca_vulnerabilities": {
        "id", "ecosystem", "package_name", "vulnerable_range", "cve_id",
        "ghsa_id", "severity", "cvss", "summary", "description",
        "fixed_version", "references_json", "source", "is_locked",
        "llm_endpoint_id", "llm_model", "fetched_at", "updated_at",
        "notes",
    },
    "sca_assessment_packages": {
        "id", "assessment_id", "ecosystem", "name", "version",
        "source_url", "detection_method", "matched_cves_json",
        "observed_at",
    },
    "llm_analyses": {
        "id", "target_type", "target_id", "endpoint_id", "endpoint_name",
        "model", "status", "request_tokens", "response_tokens",
        "raw_response", "findings_json", "error_text", "created_at",
        "finished_at",
    },
    "scan_schedules": {
        "id", "name", "fqdn", "scan_http", "scan_https", "profile",
        "llm_tier", "llm_endpoint_id", "user_agent_id", "creds_username",
        "creds_password", "login_url", "application_id", "cron_expr",
        "start_after", "end_before", "enabled", "skip_if_running",
        "keep_only_latest", "next_run_at", "last_run_at",
        "last_assessment_id", "created_by", "created_at", "updated_at",
    },
}


def check(db) -> list[str]:
    """Return a list of human-readable drift complaints. Empty list = clean.

    `db` is the application's app.db module (already configured to talk to
    the live MariaDB). We look up actual columns via INFORMATION_SCHEMA
    rather than DESCRIBE so the query batches in one round-trip.
    """
    issues: list[str] = []

    # Pull the entire information_schema.columns view for the active schema
    # in one query. The DB connection helper already knows which database
    # name to use, so DATABASE() returns the right scope.
    rows = db.query(
        "SELECT TABLE_NAME, COLUMN_NAME "
        "FROM information_schema.columns "
        "WHERE TABLE_SCHEMA = DATABASE()"
    )

    actual: Dict[str, Set[str]] = {}
    for r in rows:
        t = r["TABLE_NAME"]
        c = r["COLUMN_NAME"]
        actual.setdefault(t, set()).add(c)

    for table, expected_cols in EXPECTED_TABLES.items():
        if table not in actual:
            issues.append(f"missing table: {table}")
            continue
        missing = expected_cols - actual[table]
        if missing:
            cols = ", ".join(sorted(missing))
            issues.append(f"{table}: missing column(s): {cols}")

    return issues


def main() -> int:
    # Local import so this module is cheap to import in code paths that
    # don't actually need to talk to the DB. The app/ directory is on
    # sys.path inside the container (uvicorn launches with cwd=/app), so
    # `import db` resolves to app/db.py — no package prefix needed.
    import sys
    sys.path.insert(0, "/app")
    import db as appdb

    if not appdb.healthy():
        print("verify_schema: database is not reachable; cannot verify",
              file=sys.stderr)
        return 2

    issues = check(appdb)
    if not issues:
        print("verify_schema: OK ({} tables, all expected columns present)"
              .format(len(EXPECTED_TABLES)))
        return 0

    print("verify_schema: drift detected", file=sys.stderr)
    for line in issues:
        print(f"  - {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
