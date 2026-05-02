# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Boot-time schema migration runner.

Why a hand-rolled framework instead of Alembic / Django migrations: the
project intentionally has zero ORM and one DB engine. A 90-line runner
gives us idempotent boot-time fixups without dragging in a 50k-line
dependency. Each migration is a callable that returns a one-line summary
on success or raises on failure.

Migrations run once per database. The `schema_migrations` table records
which ids have been applied; pending ids are applied in registration
order on every container start. If a migration fails, the row is marked
`status='failed'` with the exception text and the runner re-raises so
the boot stops — better than silently coming up half-migrated.

Adding a new migration:
  1. Write a function `def my_migration() -> str` that performs the
     work and returns a short human-readable summary (stored in
     schema_migrations.notes).
  2. Append `(id, fn)` to MIGRATIONS below using a date-prefixed id.
  3. Ship. Every container that pulls the new image will apply the
     migration on first start; reruns on already-migrated DBs are
     no-ops.

What does NOT belong in here:
  * DDL changes — those are still expressed in db/schema.sql, applied
    on boot by the schema-drift auto-healer in server.py.
  * Per-assessment ad-hoc fixups — those go in scripts/ as standalone
    CLI tools.
This module is for one-shot DATA migrations that must run exactly once
per upgrade, fleet-wide, without operator action.
"""
from __future__ import annotations

import json
import logging
from typing import Callable

import db

log = logging.getLogger("nextgen-dast.migrations")

# MariaDB advisory lock name. If two boots race (multi-worker uvicorn,
# or a compose `up -d` while a sibling worker is still finishing),
# only one acquires the lock and runs the migration loop; the others
# observe `applied_ids` already includes everything and exit cleanly.
_LOCK_NAME = "nextgen_dast_schema_migrations"
_LOCK_TIMEOUT_SEC = 60


# ---- bookkeeping helpers ---------------------------------------------------

def _ensure_table() -> None:
    """Create the `schema_migrations` table if it does not yet exist.

    The DDL is also in db/schema.sql so a fresh `pentest.sh bootstrap`
    creates it alongside everything else; this CREATE-IF-NOT-EXISTS
    keeps already-running 2.1.1 databases self-bootstrapping when they
    pull the first image that ships migrations."""
    db.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
              id VARCHAR(64) PRIMARY KEY,
              applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                  ON UPDATE CURRENT_TIMESTAMP,
              status ENUM('success','failed') NOT NULL DEFAULT 'success',
              notes TEXT
           ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")


def _applied_ids() -> set:
    """Set of migration ids that previously ran to completion. Failed
    rows are NOT included — they will be retried on the next boot, which
    is usually what an operator wants after fixing the underlying issue."""
    rows = db.query_all(
        "SELECT id FROM schema_migrations WHERE status = 'success'")
    return {r["id"] for r in rows}


def _record(id: str, status: str, notes: str) -> None:
    """Upsert into schema_migrations. ON DUPLICATE handles the retry-after-
    fix case (a failed row gets its status flipped to 'success' on rerun)."""
    db.execute(
        """INSERT INTO schema_migrations (id, status, notes)
           VALUES (%s, %s, %s)
           ON DUPLICATE KEY UPDATE status = VALUES(status),
                                   notes = VALUES(notes),
                                   applied_at = CURRENT_TIMESTAMP""",
        (id, status, (notes or "")[:65000]))


# ---- migration definitions -------------------------------------------------

def m_2026_05_01_reset_stale_traversal_validations() -> str:
    """Clear validation_status for findings whose verdict was written by
    path_traversal_ftp_download or path_traversal_extension_bypass before
    the probe rewrites shipped on 2026-05-01.

    Why: both probes used to walk redirects silently and matched
    response bodies with loose patterns (`[A-Za-z0-9+/=]{6,}`,
    single-key JSON detection). On any host that 303s /ftp/* to /login,
    the login HTML page hit the regex via `doctype` and the probe
    returned validated=True, severity-uplifting the finding to high.
    The rewrite added per-file shape validators (KDBX magic bytes,
    BOTH dependencies+version for package.json, multi-line base64,
    multi-bullet YAML), `follow_redirects=False`, and a centralized
    `_response_disqualified` guard. Findings probed before the
    rewrite landed in the running image are not re-validated until
    something prompts a re-run.

    What this migration does: for any finding whose
    validation_probe is one of the rewritten probes AND whose
    validation_run_at predates the rewrite cutoff, set
    validation_status back to 'unvalidated' so the next bulk
    Challenge (manual or auto) re-runs it under the corrected probe.
    Other probes' verdicts are not touched."""
    # The cutoff is the moment the first 2.1.1 image with the rewritten
    # probes was pushed to the registry. Anything validated before this
    # may have used the loose-regex code path. Hardcoded rather than
    # parameterised because there is exactly one rewrite event we are
    # backfilling for.
    cutoff = "2026-05-01 11:46:00"
    rewritten = ("path_traversal_ftp_download",
                 "path_traversal_extension_bypass")

    rows = db.query_all(
        """SELECT id FROM findings
            WHERE validation_probe IN %s
              AND validation_run_at IS NOT NULL
              AND validation_run_at < %s
              AND validation_status IN ('validated','false_positive')""",
        (rewritten, cutoff))
    if not rows:
        return f"no stale validations to reset (cutoff {cutoff})"

    ids = [r["id"] for r in rows]
    placeholders = ",".join(["%s"] * len(ids))
    db.execute(
        f"""UPDATE findings
              SET validation_status = 'unvalidated',
                  validation_probe = NULL,
                  validation_run_at = NULL,
                  validation_evidence = NULL
            WHERE id IN ({placeholders})""",
        tuple(ids))
    return (f"reset {len(ids)} finding(s) probed by rewritten "
            f"path-traversal probes before {cutoff}")


def m_2026_05_01_enrichment_orphan_cleanup() -> str:
    """Re-point findings whose enrichment_id is keyed under the pre-2.1.1
    broad signature hash. Locked manual rows are preserved untouched.

    Same logic as scripts/enrichment_orphan_cleanup.py — that script
    remains as a manual fallback (with --assessment / --commit flags)
    for ad-hoc runs. The migration is "all assessments, always commit"
    and runs exactly once per database."""
    import enrichment as enrichment_mod

    rows = db.query_all(
        """SELECT f.id, f.source_tool, f.title, f.cwe, f.owasp_category,
                  f.evidence_url, f.raw_data,
                  e.signature_hash AS linked_sig,
                  e.is_locked       AS linked_locked
             FROM findings f
             JOIN finding_enrichment e ON e.id = f.enrichment_id
            WHERE f.enrichment_id IS NOT NULL""")

    aligned = 0
    locked_kept = 0
    cleared = 0
    for row in rows:
        # Reconstruct just enough of the canonical finding-shape dict for
        # signature() to read its discriminator fields. raw_data is JSON
        # in the DB; pre-parse so the helper sees the structured form.
        raw = row.get("raw_data")
        parsed: dict = {}
        if isinstance(raw, str) and raw:
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {}
        elif isinstance(raw, dict):
            parsed = raw
        finding = {
            "source_tool": row.get("source_tool") or "",
            "title": row.get("title") or "",
            "cwe": row.get("cwe") or "",
            "owasp_category": row.get("owasp_category") or "",
            "evidence_url": row.get("evidence_url") or "",
            "raw_data": parsed,
        }
        new_sig = enrichment_mod.signature(finding)
        if row["linked_sig"] == new_sig:
            aligned += 1
            continue
        if row["linked_locked"]:
            # Preserve admin-curated guidance even if the hash drifted.
            # We never silently strip a locked manual entry.
            locked_kept += 1
            continue
        cleared += 1
        db.execute(
            "UPDATE findings SET enrichment_id = NULL WHERE id = %s",
            (row["id"],))
    return (f"scanned {len(rows)} findings: aligned={aligned}, "
            f"locked_kept={locked_kept}, cleared={cleared}")


def m_2026_05_01_promote_existing_admins_to_superadmin() -> str:
    """Bump every existing role='admin' user to role='superadmin' on the
    database where the Enhanced-AI-Testing release first lands.

    Why a one-shot migration rather than a schema.sql UPDATE: the schema
    file is re-applied on every drift-heal pass, so a plain `UPDATE users
    SET role='superadmin' WHERE role='admin'` would re-promote anyone a
    superadmin had intentionally demoted. The migration framework
    guarantees exactly-once-per-database execution, which is what
    "preserve existing privilege on first deploy, then leave humans to
    manage the role as they see fit" requires.

    On fresh databases this migration is a no-op — the schema seeds no
    role='admin' rows, so there's nothing to promote. The legacy
    is_admin=1 rows get bumped from 'readonly' to 'admin' by
    schema.sql's existing UPDATE, then this migration moves them on to
    'superadmin'. New users created by the admin UI default to
    'readonly' as before."""
    rows = db.query_all(
        "SELECT id, username FROM users WHERE role = 'admin'")
    if not rows:
        return "no role='admin' users to promote"
    db.execute("UPDATE users SET role = 'superadmin' WHERE role = 'admin'")
    return (f"promoted {len(rows)} user(s) to superadmin: "
            + ", ".join(r["username"] for r in rows))


# Append-only registration list. Ids are date-prefixed (YYYY_MM_DD_) so
# alphabetical ordering matches chronological ordering. Ids never change
# once shipped — renaming would re-run the migration on databases that
# already applied the original.
def m_2026_05_02_remap_ai_findings_to_owasp_top10() -> str:
    """Backfill `owasp_category` for existing enhanced_ai_testing
    findings so they land in the right OWASP Top 10 bucket for the
    PDF cover scorecard, the heat map, and the per-category demerit
    math. Earlier enhanced_ai builds wrote the scenario name
    ('bola_idor', 'rate_limit_evasion', etc.) directly into
    `owasp_category`; new code writes the OWASP code at insert time
    (see enhanced_ai._scenario_to_owasp), but historical rows still
    carry the scenario label and won't be re-scanned.

    The scenario label is preserved in `raw_data.llm_category` so we
    can read it back even when `owasp_category` already got
    overwritten (it shouldn't have, but the redundancy makes this
    migration idempotent without a separate "did we run yet" guard).

    Skips rows that already carry an OWASP code (starts with 'A0' or
    'A10') so re-running the migration is a no-op even if the DB has
    already been touched by a partial backfill. New databases with
    no enhanced_ai findings see this migration run as a no-op.
    """
    import enhanced_ai as ea_mod  # local import: avoid cycles at module load

    rows = db.query_all(
        "SELECT id, owasp_category, raw_data FROM findings "
        "WHERE source_tool = 'enhanced_ai_testing'")
    if not rows:
        return "no enhanced_ai_testing findings to remap"

    remapped = 0
    skipped_already_ok = 0
    skipped_unknown = 0
    for row in rows:
        current = (row.get("owasp_category") or "").strip()
        # Already an OWASP Top 10 code (A01..A10 prefix). Leave alone.
        if current.startswith("A0") or current.startswith("A10"):
            skipped_already_ok += 1
            continue

        # Recover the scenario label. Prefer raw_data.llm_category (the
        # canonical record); fall back to whatever's in owasp_category
        # on databases where llm_category wasn't yet recorded.
        scenario = current
        rd = row.get("raw_data")
        if isinstance(rd, str) and rd:
            try:
                rd_obj = json.loads(rd)
                lc = rd_obj.get("llm_category") if isinstance(rd_obj, dict) else None
                if isinstance(lc, str) and lc.strip():
                    scenario = lc.strip()
            except Exception:
                pass

        owasp_code = ea_mod._scenario_to_owasp(scenario)
        if not owasp_code:
            skipped_unknown += 1
            continue
        db.execute(
            "UPDATE findings SET owasp_category = %s WHERE id = %s",
            (owasp_code[:64], row["id"]))
        remapped += 1

    return (f"remapped {remapped} enhanced_ai finding(s); "
            f"skipped {skipped_already_ok} already-OWASP-coded, "
            f"{skipped_unknown} unrecognized scenario(s)")


MIGRATIONS: list = [
    ("2026_05_01_enrichment_orphan_cleanup",
     m_2026_05_01_enrichment_orphan_cleanup),
    ("2026_05_01_reset_stale_traversal_validations",
     m_2026_05_01_reset_stale_traversal_validations),
    ("2026_05_01_promote_existing_admins_to_superadmin",
     m_2026_05_01_promote_existing_admins_to_superadmin),
    ("2026_05_02_remap_ai_findings_to_owasp_top10",
     m_2026_05_02_remap_ai_findings_to_owasp_top10),
]


# ---- public entry point ----------------------------------------------------

def run_pending() -> None:
    """Apply every migration that has not yet succeeded against this DB.

    Idempotent: callable on every container boot. Already-applied
    migrations are skipped via the schema_migrations bookkeeping table.
    Concurrent boots are serialized via a MariaDB advisory lock; if the
    lock cannot be acquired in _LOCK_TIMEOUT_SEC, the runner logs a
    warning and returns (the lock-holder will run the migrations).

    Raises whatever the failing migration raises, so the FastAPI
    lifespan in server.py can surface the failure to the operator
    instead of letting a half-migrated container come up healthy."""
    _ensure_table()
    lock = db.query_one(
        "SELECT GET_LOCK(%s, %s) AS got",
        (_LOCK_NAME, _LOCK_TIMEOUT_SEC))
    if not lock or not lock.get("got"):
        log.warning(
            "schema migrations: another worker holds the lock — skipping "
            "(it will run them).")
        return
    try:
        applied = _applied_ids()
        for migration_id, fn in MIGRATIONS:
            if migration_id in applied:
                continue
            log.info("running migration %s", migration_id)
            try:
                summary = fn() or ""
                _record(migration_id, "success", summary)
                log.info("migration %s OK: %s", migration_id, summary)
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"
                log.exception("migration %s FAILED: %s", migration_id, msg)
                _record(migration_id, "failed", msg)
                raise
    finally:
        # RELEASE_LOCK is safe to call even if GET_LOCK already timed out.
        db.execute("SELECT RELEASE_LOCK(%s)", (_LOCK_NAME,))
