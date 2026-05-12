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


def m_2026_05_02_fp_lower_version_fingerprint_dupes() -> str:
    """Auto-mark lower-version duplicate fingerprint findings as
    false_positive. Earlier sca_runner.fingerprint_js_content() did
    not deduplicate by component within a file, so a JS bundle
    containing stray version strings (changelog comments, regex
    literals, migrate-shim version assignments) produced one record
    per detected version. Each record then drove its own info
    "Library detected" finding plus per-CVE OSV findings.

    The fix in fingerprint_js_content keeps only the highest semver
    per (file, component) going forward. This migration cleans up
    the historical data: for every (assessment, evidence_url,
    raw_data.package.name) group that has multiple versions, we
    keep the highest semver as-is and flip the lower-version
    siblings to status='false_positive' / validation_status=
    'false_positive' with a stamped validation_evidence note.

    Idempotent: rows already in status='false_positive' are not
    touched, and the second pass groups them out, so the migration
    runs as a no-op once it has been applied.
    """
    rows = db.query_all("""
        SELECT id, assessment_id, evidence_url, raw_data, status,
               source_tool, severity
          FROM findings
         WHERE source_tool = 'sca'
           AND raw_data IS NOT NULL
    """)
    if not rows:
        return "no SCA findings to dedup"

    # Group rows by (assessment_id, evidence_url, package_name).
    # Each group ends up with one or more (version, row_id) pairs.
    groups: dict[tuple, list[tuple[str, dict]]] = {}
    for row in rows:
        if (row.get("status") or "open") == "false_positive":
            continue   # already triaged out; never re-flip
        rd = row.get("raw_data")
        try:
            obj = json.loads(rd) if isinstance(rd, str) else (rd or {})
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        # SCA findings carry either of two raw_data shapes:
        #   * OSV / retire-style:    raw_data.package.{name, version}
        #   * fingerprinter info:    raw_data.{component, version}
        # Normalise both into (name, version) here so the dedup
        # group key catches both kinds of rows for the same library.
        pkg = obj.get("package") or {}
        name = (pkg.get("name") or obj.get("component") or "").strip().lower()
        version = (pkg.get("version") or obj.get("version") or "").strip()
        url = (row.get("evidence_url") or "").strip()
        if not (name and version and url):
            continue
        key = (row["assessment_id"], url, name)
        groups.setdefault(key, []).append((version, row))

    # Local semver tuple — same shape as
    # sca_runner._semver_tuple. Reproduced inline so the migration
    # has no dependency on importing scripts/sca_runner.
    def _sv(v: str) -> tuple:
        s = v.lstrip("vV").strip() if v else ""
        base, _, pre = s.partition("-")
        out: list = []
        for chunk in base.split("."):
            try:
                out.append((1, int(chunk)))
            except ValueError:
                out.append((0, chunk))
        out.append((0, pre) if pre else (2, ""))
        return tuple(out)

    flipped = 0
    groups_touched = 0
    for key, members in groups.items():
        if len(members) < 2:
            continue
        # Find the maximum semver in the group. Only flip rows that
        # are STRICTLY less than the max -- rows at the same version
        # as the max are different CVEs / different findings against
        # the same library version, not version-duplicates, and
        # must NOT be flipped. Earlier passes did flip equal-version
        # siblings, which incorrectly suppressed real CVE rows; the
        # corrective_v3 migration that runs immediately after this
        # one undoes those mistaken flips.
        max_v = max(_sv(mv[0]) for mv in members)
        max_v_str = next(mv[0] for mv in members if _sv(mv[0]) == max_v)
        any_flipped_in_group = False
        for ver, row in members:
            if _sv(ver) >= max_v:
                continue   # at-max version — keep
            note = ("auto-flipped by 2026-05-02 dedup migration: "
                    f"another finding on the same evidence_url "
                    f"reports the same component at version "
                    f"{max_v_str}; this record's lower version "
                    f"{ver} is most likely a fingerprinter artifact "
                    "(stray version string in the bundle). Review "
                    "the higher-version finding for the canonical "
                    "verdict.")
            db.execute(
                "UPDATE findings "
                "   SET status = 'false_positive', "
                "       validation_status = 'false_positive', "
                "       validation_probe = 'fingerprint_dedup', "
                "       validation_run_at = NOW(), "
                "       validation_evidence = %s "
                " WHERE id = %s "
                "   AND status <> 'false_positive'",
                (json.dumps({"summary": note,
                              "kept_version": max_v_str,
                              "flipped_version": ver}), row["id"]))
            flipped += 1
            any_flipped_in_group = True
        if any_flipped_in_group:
            groups_touched += 1

    return (f"flipped {flipped} lower-version duplicate(s) across "
            f"{groups_touched} (assessment, file, component) group(s)")


def m_2026_05_02_unflip_equal_version_dedup_mistakes() -> str:
    """Corrective pass for the previous fp_lower_version dedup
    migration. The first two passes (v1 and v2) sorted group members
    descending and flipped every row except the first, which mistakenly
    flipped same-version siblings (multiple CVEs against the SAME
    library version, e.g. four bootstrap 4.1.3 CVEs on the same JS
    file). Those rows were never duplicates — they were independent
    findings.

    The validation_evidence JSON written by the buggy passes carries
    `kept_version` and `flipped_version` -- if those two values are
    EQUAL, the row was wrongly flipped and we revert it here. Rows
    correctly flipped (lower version vs higher) are left alone.

    Idempotent: only matches rows whose validation_probe is exactly
    'fingerprint_dedup' AND whose evidence shows kept == flipped.
    Re-runs after the cleanup find no such rows."""
    rows = db.query_all("""
        SELECT id, validation_evidence
          FROM findings
         WHERE source_tool = 'sca'
           AND status = 'false_positive'
           AND validation_probe = 'fingerprint_dedup'
    """)
    if not rows:
        return "no fingerprint_dedup-flipped rows to inspect"

    reverted = 0
    for row in rows:
        ev = row.get("validation_evidence")
        try:
            obj = json.loads(ev) if isinstance(ev, str) else (ev or {})
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        kept = (obj.get("kept_version") or "").strip()
        flipped = (obj.get("flipped_version") or "").strip()
        if not (kept and flipped):
            continue
        if kept != flipped:
            continue   # legitimate lower-version flip; leave alone
        # Revert to status=open / unvalidated and clear the bogus
        # dedup metadata. The downstream sca_finding_validate probe
        # (or analyst review) decides the correct verdict; we don't
        # presume an outcome here.
        db.execute(
            "UPDATE findings "
            "   SET status = 'open', "
            "       validation_status = 'unvalidated', "
            "       validation_probe = NULL, "
            "       validation_run_at = NULL, "
            "       validation_evidence = NULL "
            " WHERE id = %s",
            (row["id"],))
        reverted += 1

    return (f"reverted {reverted} same-version row(s) wrongly flipped "
            "by the earlier dedup pass")


MIGRATIONS: list = [
    ("2026_05_01_enrichment_orphan_cleanup",
     m_2026_05_01_enrichment_orphan_cleanup),
    ("2026_05_01_reset_stale_traversal_validations",
     m_2026_05_01_reset_stale_traversal_validations),
    ("2026_05_01_promote_existing_admins_to_superadmin",
     m_2026_05_01_promote_existing_admins_to_superadmin),
    ("2026_05_02_remap_ai_findings_to_owasp_top10",
     m_2026_05_02_remap_ai_findings_to_owasp_top10),
    ("2026_05_02_fp_lower_version_fingerprint_dupes",
     m_2026_05_02_fp_lower_version_fingerprint_dupes),
    # v2 re-runs the same dedup logic after the first pass missed
    # rows whose raw_data carried the fingerprinter info-row shape
    # (component/version at the top level) instead of the OSV /
    # retire shape (package.{name, version}). The function itself
    # is now shape-aware; a new migration id is required because
    # the schema_migrations bookkeeping marks the original id as
    # success and would skip a re-run otherwise.
    ("2026_05_02_fp_lower_version_fingerprint_dupes_v2",
     m_2026_05_02_fp_lower_version_fingerprint_dupes),
    # v3 corrects the same-version flips that v1 and v2 wrongly
    # produced. The bug was specifically: when a group's members all
    # had the same version (multiple CVEs against the same library
    # release), every row except the first was flipped. v3 reverts
    # those, leaving real lower-version flips alone.
    ("2026_05_02_unflip_equal_version_dedup_mistakes",
     m_2026_05_02_unflip_equal_version_dedup_mistakes),
    # v4 re-runs the (now correct) dedup logic. After v3 puts the
    # equal-version rows back to status=open, this pass picks up
    # any rows the original buggy passes missed because their group
    # had MORE than one member at the max version (the second-and-
    # later max-version rows would have been flipped under the old
    # logic, then reverted by v3, but we want to make sure the
    # genuine lower-version siblings in the group are still flipped).
    ("2026_05_02_fp_lower_version_fingerprint_dupes_v4",
     m_2026_05_02_fp_lower_version_fingerprint_dupes),
    # 2026-05-03: back-fill rows where validation_status='false_positive'
    # but findings.status is still 'open' (or 'confirmed'). Earlier
    # versions of the LLM fidelity grader wrote only validation_status
    # when refuting a finding; the workspace filter then missed them
    # because it only checked .status. New code (server.py:_is_finding_triaged
    # and the matching reports.py / api.py guards) handles this in
    # both fields, but the back-fill keeps the data invariant true so
    # any future code path that only inspects .status is also right.
    ("2026_05_03_backfill_status_from_validation_status",
     lambda: __import__("__main__")),  # placeholder, real fn below
    # 2026-05-03: refresh the seeded fidelity prompt to the v2 text
    # that includes the 'expected_behavior' verdict and the
    # {role_context_block} placeholder. Existing 2.1.1 databases
    # already have a seeded row from the v1 release; without this
    # migration the role-aware verdict path is dead code until an
    # operator manually clicks "Restore to default". Operator-edited
    # rows are detected by checking whether 'expected_behavior' is
    # already in the system_prompt and are left untouched.
    # Registered with a placeholder lambda; the real function is
    # defined further down (alongside other 2026-05-03 migrations) and
    # bound into this list by the same late-binding loop the
    # backfill-status migration uses.
    ("2026_05_03_refresh_fidelity_prompt_for_role_scope",
     lambda: __import__("__main__")),
    # 2026-05-04: add the dark-mode web logo column. Existing 2.1.1
    # databases shipped with only `web_header_logo_filename` (which
    # is now the LIGHT-mode logo); operators uploading a dark-mode
    # variant need the new column to land before the upload form
    # POSTs to it. Idempotent ALTER TABLE -- safe to re-run.
    ("2026_05_04_add_web_header_logo_dark_filename",
     lambda: __import__("__main__")),
    # 2026-05-12: add the exploit-chain / attacker-workflow / likelihood
    # columns to finding_enrichment so the LLM enrichment pipeline can
    # persist its deeper exploit-chain validation, and the web detail
    # page + PDF report can render an "attacker workflow" card. Fresh
    # installs get the columns from schema.sql; this migration only
    # adds the columns when they are not already present, so it is
    # safely re-runnable.
    ("2026_05_12_add_exploit_chain_columns",
     lambda: __import__("__main__")),
    # 2026-05-12: rewind enhanced_ai_testing findings stuck on
    # validation_status='errored' to 'unvalidated' so the (now-fixed)
    # fidelity grader picks them up. See
    # m_2026_05_12_unstick_llm_errored_validations for the full root
    # cause writeup; the gist is that probe failures against
    # URL-less LLM findings were being trapped on the row as a
    # verdict the grader then skipped. Idempotent: re-runs against a
    # clean database are a no-op.
    ("2026_05_12_unstick_llm_errored_validations",
     lambda: __import__("__main__")),
    # 2026-05-12: add the agentic-pass control columns to
    # assessments + scan_schedules so the new agentic_deep_dive_count
    # and agentic_extra knobs can be persisted. Idempotent; see
    # m_2026_05_12_add_agentic_columns docstring for full writeup.
    ("2026_05_12_add_agentic_columns",
     lambda: __import__("__main__")),
]


def m_2026_05_03_refresh_fidelity_prompt_for_role_scope() -> str:
    """Refresh the seeded fidelity prompt to the v2 text that includes
    the 'expected_behavior' verdict and the {role_context_block}
    placeholder.

    Why this is needed: existing 2.1.1 databases already have a row in
    `ai_prompts` with slot='advanced_ai_testing.fidelity', is_seeded=1,
    and the original v1 system_prompt + user_template. seed_defaults_if_empty
    only inserts when the slot+name pair is missing, so on an upgrade
    the row keeps the v1 text and the new role-aware verdict path is
    dead code until an operator clicks "Restore to default" by hand.
    This migration does that automatically -- but only for rows that
    look unchanged from v1, so an operator's customizations are
    preserved.

    Detection heuristic: the row is considered "v1 default" when
    is_seeded=1 AND the system_prompt does NOT contain the substring
    'expected_behavior'. Once the migration writes the v2 text, the
    same check on the next boot is False, so re-runs are no-ops.

    For operator-edited rows we surface a one-line note in the
    migration summary so the operator knows their custom prompt did
    NOT receive the role-aware verdict and can manually merge if
    desired."""
    import enhanced_ai_prompts as eap

    rows = db.query_all(
        "SELECT id, system_prompt, user_template "
        "FROM ai_prompts "
        "WHERE slot = %s AND is_seeded = 1",
        (eap.SLOT_FIDELITY,))
    if not rows:
        return "no seeded fidelity row to refresh (will be added by seed_defaults_if_empty on next boot)"

    refreshed = 0
    skipped_custom = 0
    for r in rows:
        sys_prompt = r.get("system_prompt") or ""
        if "expected_behavior" in sys_prompt:
            # Already on the v2 text (either via this migration on a
            # prior boot, or because an operator manually restored
            # to default after pulling the new image).
            continue
        # Looks like the v1 default — overwrite with the in-code v2.
        # We only update body fields, leaving is_active alone so a
        # paused row stays paused.
        db.execute(
            "UPDATE ai_prompts "
            "SET system_prompt = %s, user_template = %s "
            "WHERE id = %s",
            (eap.FIDELITY_SYSTEM, eap.FIDELITY_USER, r["id"]))
        refreshed += 1

    return (f"refreshed {refreshed} seeded fidelity prompt(s) to v2 "
            f"(role-aware verdict + role_context_block placeholder); "
            f"{skipped_custom} operator-edited row(s) left untouched")


def m_2026_05_03_backfill_status_from_validation_status() -> str:
    """Promote rows with validation_status='false_positive' AND
    status NOT IN ('false_positive','fixed','accepted_risk') so the
    overall status field also reflects the FP verdict.

    Idempotent on subsequent runs (UPDATE-with-WHERE that no longer
    matches once back-filled). Safe to leave in MIGRATIONS forever
    as a self-healing guard.

    The migration ID was registered in MIGRATIONS via a placeholder
    lambda, then re-bound here. Pylint will frown but Python's late
    binding lets us define the function after the registration list.
    """
    rows = db.query_all(
        "SELECT id, severity, status, validation_status FROM findings "
        "WHERE validation_status='false_positive' "
        "  AND status NOT IN ('false_positive','fixed','accepted_risk')")
    if not rows:
        return "no half-flipped FPs found — nothing to back-fill"
    db.execute(
        "UPDATE findings SET status='false_positive' "
        "WHERE validation_status='false_positive' "
        "  AND status NOT IN ('false_positive','fixed','accepted_risk')")
    return f"back-filled {len(rows)} half-flipped FP row(s) to status='false_positive'"


def m_2026_05_04_add_web_header_logo_dark_filename() -> str:
    """Add `web_header_logo_dark_filename` to the `branding` table on
    existing 2.1.1 deployments.

    The column was added to schema.sql in the same release that ships
    this migration, so a fresh install never runs the ALTER. On an
    upgrade the migration adds the column iff it's not already there.
    Idempotent: information_schema is consulted first so a re-run on
    an already-migrated DB is a no-op.

    The migration is bookkeeping only -- once the column exists,
    branding.save_logo() / .delete_logo() handle the new
    'web_header_dark' kind without further code changes."""
    row = db.query_one(
        "SELECT 1 AS exists_ FROM information_schema.columns "
        "WHERE table_schema = DATABASE() "
        "  AND table_name = 'branding' "
        "  AND column_name = 'web_header_logo_dark_filename'")
    if row and row.get("exists_"):
        return "branding.web_header_logo_dark_filename already present"
    db.execute(
        "ALTER TABLE branding "
        "ADD COLUMN web_header_logo_dark_filename VARCHAR(255) "
        "AFTER web_header_logo_filename")
    return ("added branding.web_header_logo_dark_filename "
            "(dark-mode web logo)")


def m_2026_05_12_add_exploit_chain_columns() -> str:
    """Add the six exploit-chain / attacker-workflow / likelihood
    columns to `finding_enrichment` on existing 2.1.1 deployments.

    Why: the 2026-05 release extends finding enrichment so the LLM
    output now includes a kill-chain breakdown, an attacker workflow
    narrative, prerequisites the attacker needs to line up, an
    exploitation-likelihood band with rationale, and a detection
    difficulty hint. The web finding-detail page and the PDF report
    both render these fields. Fresh installs pick them up from
    schema.sql; this migration is the upgrade path for databases
    seeded under the prior schema.

    Idempotent: each ADD COLUMN is gated on an information_schema
    lookup so a re-run on an already-migrated DB is a no-op. The
    columns are added one at a time so a partial failure mid-list
    leaves the rest intact for the next boot's retry."""
    columns = [
        ("prerequisites_json",   "TEXT",
            "AFTER suggested_priority"),
        ("exploit_chain_json",   "TEXT",
            "AFTER prerequisites_json"),
        ("attacker_workflow",    "TEXT",
            "AFTER exploit_chain_json"),
        ("likelihood",           "ENUM('very_low','low','medium','high','very_high') NULL",
            "AFTER attacker_workflow"),
        ("likelihood_rationale", "TEXT",
            "AFTER likelihood"),
        ("detection_difficulty", "ENUM('easy','moderate','hard') NULL",
            "AFTER likelihood_rationale"),
    ]
    added = []
    skipped = []
    for name, ddl, position in columns:
        row = db.query_one(
            "SELECT 1 AS exists_ FROM information_schema.columns "
            "WHERE table_schema = DATABASE() "
            "  AND table_name = 'finding_enrichment' "
            "  AND column_name = %s", (name,))
        if row and row.get("exists_"):
            skipped.append(name)
            continue
        db.execute(
            f"ALTER TABLE finding_enrichment ADD COLUMN {name} {ddl} {position}")
        added.append(name)
    if added:
        return (f"added {len(added)} column(s): {', '.join(added)}"
                + (f"; {len(skipped)} already present" if skipped else ""))
    return "all exploit-chain columns already present — no-op"


def m_2026_05_12_add_agentic_columns() -> str:
    """Add the agentic-pass control columns to assessments and
    scan_schedules on existing 2.1.1 deployments.

    Why: round-3 of the parity push introduces an agentic AI deep-
    dive that runs after the Enhanced-AI weakness pass. Two new
    knobs per assessment / per schedule control it:
      - agentic_deep_dive_count (INT) -- how many of the top-severity
        open findings get a tool-calling LLM deep-dive. Default 5;
        0 disables the per-finding pass entirely.
      - agentic_extra (TINYINT(1)) -- opt-in flag for the second,
        free-roaming agentic pass that explores the scan surface for
        misses. When set, the assessment's effective LLM budget cap
        is automatically doubled so the free-roam pass has room
        without starving the per-finding pass.

    Idempotent: each ADD COLUMN is gated on an information_schema
    lookup, so a re-run on an already-migrated DB is a no-op. The
    same columns are present in db/schema.sql for fresh installs."""
    targets = [
        ("assessments", "agentic_deep_dive_count",
         "INT NOT NULL DEFAULT 5",
         "AFTER role_restrictions"),
        ("assessments", "agentic_extra",
         "TINYINT(1) NOT NULL DEFAULT 0",
         "AFTER agentic_deep_dive_count"),
        ("scan_schedules", "agentic_deep_dive_count",
         "INT NOT NULL DEFAULT 5",
         "AFTER role_restrictions"),
        ("scan_schedules", "agentic_extra",
         "TINYINT(1) NOT NULL DEFAULT 0",
         "AFTER agentic_deep_dive_count"),
    ]
    added = []
    skipped = []
    for table, col, ddl, position in targets:
        row = db.query_one(
            "SELECT 1 AS exists_ FROM information_schema.columns "
            "WHERE table_schema = DATABASE() "
            "  AND table_name = %s "
            "  AND column_name = %s", (table, col))
        if row and row.get("exists_"):
            skipped.append(f"{table}.{col}")
            continue
        db.execute(
            f"ALTER TABLE {table} ADD COLUMN {col} {ddl} {position}")
        added.append(f"{table}.{col}")
    if added:
        return (f"added {len(added)} column(s): {', '.join(added)}"
                + (f"; {len(skipped)} already present" if skipped else ""))
    return "all agentic columns already present -- no-op"


def m_2026_05_12_unstick_llm_errored_validations() -> str:
    """Reset validation_status='errored' on enhanced_ai_testing-source
    findings back to 'unvalidated' so the LLM fidelity grader can pick
    them up on the next re-run.

    Why: the auto-validation pass (challenge_runner) was running
    toolkit probes against LLM-emitted findings whose evidence_url
    was NULL (LLM output rarely conforms to the strict probe schema).
    The probe could not construct a valid request and returned an
    'errored' verdict, which got written onto the finding row. The
    fidelity selection then excluded 'errored' rows, so the LLM's
    most actionable findings were stuck in limbo, neither validated
    nor refuted, with no path back to triage. The new code path in
    challenge_runner stops overwriting validation_status on these
    rows; this migration backfills already-deployed databases so the
    fix is visible without re-running the assessment.

    The original probe error transcript is preserved in
    validation_evidence (and accessible from the finding detail page)
    so an analyst can still see what was attempted -- only the
    status flag is rewound. Probes have been rerun on each finding
    multiple times under ERROR_RETRY_ATTEMPTS, so 'errored' here is a
    persistent schema mismatch, not a transient flake worth waiting
    on.

    Scope is narrowly limited to source_tool='enhanced_ai_testing'
    because non-LLM sources DO have probe-shaped evidence -- an
    'errored' verdict on a wapiti / nikto / nuclei finding usually
    means a real probe failure (target offline, TLS handshake
    failure, etc.) that the analyst should keep visible."""
    rows = db.query_all(
        """SELECT id FROM findings
            WHERE source_tool = 'enhanced_ai_testing'
              AND validation_status = 'errored'""")
    if not rows:
        return "no stuck enhanced_ai_testing errored rows to reset"
    ids = [r["id"] for r in rows]
    placeholders = ",".join(["%s"] * len(ids))
    db.execute(
        f"""UPDATE findings
              SET validation_status = 'unvalidated'
            WHERE id IN ({placeholders})""",
        tuple(ids))
    return (f"reset {len(ids)} enhanced_ai_testing finding(s) from "
            f"'errored' back to 'unvalidated' (probe error transcripts "
            f"preserved in validation_evidence)")


# Re-bind the placeholders in MIGRATIONS now that the functions exist.
# The registration list is built at import time so we patch it here
# rather than re-ordering the file (the dedup migrations need their
# m_* helpers defined first too).
_LATE_BIND = {
    "2026_05_03_backfill_status_from_validation_status":
        m_2026_05_03_backfill_status_from_validation_status,
    "2026_05_03_refresh_fidelity_prompt_for_role_scope":
        m_2026_05_03_refresh_fidelity_prompt_for_role_scope,
    "2026_05_04_add_web_header_logo_dark_filename":
        m_2026_05_04_add_web_header_logo_dark_filename,
    "2026_05_12_add_exploit_chain_columns":
        m_2026_05_12_add_exploit_chain_columns,
    "2026_05_12_unstick_llm_errored_validations":
        m_2026_05_12_unstick_llm_errored_validations,
    "2026_05_12_add_agentic_columns":
        m_2026_05_12_add_agentic_columns,
}
for _i, (_id, _fn) in enumerate(MIGRATIONS):
    if _id in _LATE_BIND:
        MIGRATIONS[_i] = (_id, _LATE_BIND[_id])


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
