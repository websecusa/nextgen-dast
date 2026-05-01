# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Safe deletion of assessment artifacts.

This module is the ONLY place that should ever rm files belonging to an
assessment. Defenses, layered:

1. Strict regex on every path component sourced from user input.
2. Path.resolve() then prefix-check — refuse anything that escapes
   /data/scans, /data/logs, or /root/.wapiti/scans.
3. Whitelist of artifact names — never blindly rmtree anything we don't
   recognize as an output of one of our tools.
4. Refuse to delete the parent directories themselves.
5. No shell — only Path.unlink()/shutil.rmtree() in pure Python.
6. All actions audited to /data/logs/deletions.jsonl.
"""
from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import db

SCANS_ROOT = Path("/data/scans").resolve()
LOGS_ROOT = Path("/data/logs").resolve()
REPORTS_ROOT = Path("/data/reports").resolve()
WAPITI_ROOT = Path("/root/.wapiti/scans").resolve()
DELETION_LOG = Path("/data/logs/deletions.jsonl")

SCAN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
FQDN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,253}[a-z0-9]$")

# Only these names (and subpaths thereof) get removed inside a scan dir.
# Anything not on this list is left alone, AND its presence prevents the
# scan dir itself from being rmdir'd at the end of the sweep — so missing
# entries here cause silent storage leaks. Add new entries whenever a
# scanner / probe writes a new top-level filename inside a scan dir.
SCAN_ARTIFACT_NAMES = {
    "meta.json", "output.log", "flows.jsonl", "proxy.log",
    "report", "report.html", "report.json", "report.jsonl",
    # nikto's --output writer appends its own extension when the supplied
    # filename ends in .html; the resulting file is .html.htm.
    "report.html.htm",
    "flows", "sqlmap", "auth_cookies.txt",
    # enhanced_testing (premium profile) writes a per-probe verdicts/
    # directory plus a roll-up summary.json next to it.
    "verdicts", "summary.json",
}


def _audit(action: str, **fields) -> None:
    rec = {"timestamp": datetime.now(timezone.utc).isoformat(),
           "action": action, **fields}
    try:
        DELETION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(DELETION_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass


def _safe_resolve(base: Path, candidate: Path) -> Path | None:
    """Resolve `candidate` and return it ONLY if it's strictly inside `base`
    and not equal to `base` itself."""
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    base = base.resolve()
    if resolved == base:
        return None
    try:
        resolved.relative_to(base)
    except ValueError:
        return None
    return resolved


def _delete_scan_dir(scan_id: str, *, dry_run: bool = False) -> dict:
    """Remove all artifacts under /data/scans/<scan_id> using a name
    whitelist. Returns a summary of what was/would be removed."""
    if not SCAN_ID_RE.match(scan_id):
        return {"ok": False, "error": f"invalid scan_id format: {scan_id!r}"}
    scan_dir = _safe_resolve(SCANS_ROOT, SCANS_ROOT / scan_id)
    if scan_dir is None or not scan_dir.is_dir():
        return {"ok": True, "removed": [], "note": "no such scan dir"}

    removed = []
    skipped = []
    for entry in scan_dir.iterdir():
        if entry.name not in SCAN_ARTIFACT_NAMES:
            skipped.append(entry.name)
            continue
        # second guard — ensure entry's resolved path is still inside scan_dir
        target = _safe_resolve(scan_dir, entry)
        if target is None:
            skipped.append(f"{entry.name} (failed safety check)")
            continue
        if dry_run:
            removed.append(entry.name)
            continue
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
            removed.append(entry.name)
        except Exception as e:
            skipped.append(f"{entry.name} (error: {e})")

    if not dry_run and not any(scan_dir.iterdir()):
        try:
            scan_dir.rmdir()
        except OSError:
            pass

    return {"ok": True, "scan_id": scan_id, "removed": removed,
            "skipped": skipped}


def _delete_wapiti_session(fqdn: str, *, dry_run: bool = False) -> dict:
    """Remove /root/.wapiti/scans/<fqdn>_*.{db,pkl} for matching FQDN."""
    if not FQDN_RE.match(fqdn):
        return {"ok": False, "error": f"invalid fqdn format: {fqdn!r}"}
    if not WAPITI_ROOT.exists():
        return {"ok": True, "removed": [], "note": "no wapiti session dir"}
    removed = []
    for entry in WAPITI_ROOT.iterdir():
        if not entry.name.startswith(fqdn + "_"):
            continue
        if not entry.name.endswith((".db", ".pkl")):
            continue
        target = _safe_resolve(WAPITI_ROOT, entry)
        if target is None:
            continue
        if dry_run:
            removed.append(entry.name)
            continue
        try:
            target.unlink(missing_ok=True)
            removed.append(entry.name)
        except Exception:
            pass
    return {"ok": True, "fqdn": fqdn, "removed": removed}


def _delete_orchestrator_log(aid: int) -> dict:
    target = _safe_resolve(LOGS_ROOT, LOGS_ROOT / f"orchestrator_{int(aid)}.log")
    if target is None or not target.exists():
        return {"ok": True, "removed": False}
    try:
        target.unlink()
        return {"ok": True, "removed": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _delete_challenge_log(aid: int) -> dict:
    """Remove /data/logs/challenge_all_<aid>.log if present. Written by
    POST /assessment/{aid}/challenge_all when an analyst kicks off a
    bulk validation pass."""
    target = _safe_resolve(LOGS_ROOT, LOGS_ROOT / f"challenge_all_{int(aid)}.log")
    if target is None or not target.exists():
        return {"ok": True, "removed": False}
    try:
        target.unlink()
        return {"ok": True, "removed": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _delete_reports_dir(aid: int) -> dict:
    """Remove the per-assessment generated-PDF directory at
    /data/reports/<aid>/ along with every .pdf inside it.

    Defenses (same shape as _delete_scan_dir): the candidate path must
    resolve to something strictly inside REPORTS_ROOT, and we only
    remove files matching the canonical PDF filename pattern enforced
    by the report generator. After removing the files, we rmdir the
    per-assessment directory if it became empty.

    A non-empty directory after the sweep means someone dropped a
    non-PDF file there manually — we leave it (and the directory)
    alone rather than blindly deleting unknown content.
    """
    aid_str = str(int(aid))
    rdir = _safe_resolve(REPORTS_ROOT, REPORTS_ROOT / aid_str)
    if rdir is None or not rdir.is_dir():
        return {"ok": True, "removed": [], "note": "no reports dir"}
    # Same regex used by reports.REPORT_FILENAME_RE — kept as a literal
    # here so the cleanup module doesn't import the reports module
    # (avoids dragging weasyprint into the deletion sweeper).
    PDF_RE = re.compile(r"^[A-Za-z0-9.-]+_\d{4}-\d{2}-\d{2}_report\.pdf$")
    removed: list[str] = []
    skipped: list[str] = []
    for entry in rdir.iterdir():
        if not PDF_RE.match(entry.name):
            skipped.append(entry.name)
            continue
        target = _safe_resolve(rdir, entry)
        if target is None or not target.is_file():
            skipped.append(f"{entry.name} (failed safety check)")
            continue
        try:
            target.unlink(missing_ok=True)
            removed.append(entry.name)
        except Exception as e:
            skipped.append(f"{entry.name} (error: {e})")
    if not skipped:
        try:
            rdir.rmdir()
        except OSError:
            pass
    return {"ok": True, "assessment_id": int(aid),
            "removed": removed, "skipped": skipped}


def cleanup_assessment(assessment_id: int) -> dict:
    """Remove all on-disk artifacts of an assessment AND its DB rows.

    Per-assessment storage we touch:
      * /data/scans/<sid>/             every scan dir referenced by
                                       assessments.scan_ids
      * /data/reports/<aid>/           generated PDF reports
      * /data/logs/orchestrator_<aid>.log
      * /data/logs/challenge_all_<aid>.log
      * /root/.wapiti/scans/<fqdn>_*   wapiti's per-host session db

    Order matters: filesystem first, then DB. If filesystem cleanup
    fails midway, the assessment row stays and the periodic sweeper
    re-tries on its next pass."""
    a = db.query_one("SELECT id, fqdn, scan_ids FROM assessments WHERE id = %s",
                     (int(assessment_id),))
    if not a:
        return {"ok": True, "note": "no such assessment"}

    summary = {"assessment_id": a["id"], "fqdn": a["fqdn"], "scans": []}
    sids = [s for s in (a.get("scan_ids") or "").split(",") if s.strip()]
    for sid in sids:
        summary["scans"].append(_delete_scan_dir(sid))

    summary["wapiti"] = _delete_wapiti_session(a["fqdn"])
    summary["orchestrator_log"] = _delete_orchestrator_log(a["id"])
    summary["challenge_log"] = _delete_challenge_log(a["id"])
    summary["reports"] = _delete_reports_dir(a["id"])

    # Now DB. Findings cascade via FK. llm_analyses for this assessment's
    # flows have no FK so we do them by hand via the scan_ids match.
    db.execute(
        "DELETE FROM llm_analyses WHERE target_type='flow' AND "
        "target_id IN (SELECT id FROM (SELECT %s AS id) t WHERE 1=0) ",
        ("",))  # placeholder — we don't track scan-flow→llm linkage strongly enough yet
    db.execute("DELETE FROM assessments WHERE id = %s", (a["id"],))
    summary["db"] = "deleted"

    _audit("assessment_deleted", **summary)
    return summary


def sweep_orphans() -> dict:
    """Remove on-disk artifacts whose owning assessment row no longer
    exists. Catches three failure modes:

      * Bug fixes (like the missing reports/challenge-log cleanup) that
        left storage from older deletions on disk.
      * Manual DB row deletions (someone DELETEd from the assessments
        table without going through the UI).
      * Crash mid-cleanup leaving partial state.

    Safe to run repeatedly: each artifact has the same regex + path-
    safety guard as the per-assessment sweep, and we only touch
    files/dirs whose name matches the per-assessment ID pattern.
    """
    if not db.healthy():
        return {"ok": False, "error": "db unhealthy; refusing to sweep"}

    live_ids = {int(r["id"]) for r in db.query("SELECT id FROM assessments")}
    summary: dict = {"live_assessments": len(live_ids),
                     "reports_removed": [], "logs_removed": [],
                     "scans_removed": []}

    # Orphaned per-assessment report directories.
    if REPORTS_ROOT.exists():
        for entry in REPORTS_ROOT.iterdir():
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            if int(entry.name) in live_ids:
                continue
            res = _delete_reports_dir(int(entry.name))
            summary["reports_removed"].append(res)

    # Orphaned per-assessment log files (orchestrator + challenge_all).
    if LOGS_ROOT.exists():
        log_re = re.compile(r"^(orchestrator|challenge_all)_(\d+)\.log$")
        for entry in LOGS_ROOT.iterdir():
            m = log_re.match(entry.name)
            if not m:
                continue
            if int(m.group(2)) in live_ids:
                continue
            target = _safe_resolve(LOGS_ROOT, entry)
            if target is None:
                continue
            try:
                target.unlink(missing_ok=True)
                summary["logs_removed"].append(entry.name)
            except Exception:
                pass

    # Orphaned scan directories. A scan dir is "owned" iff its id
    # appears in some assessments.scan_ids list.
    owned_scan_ids: set[str] = set()
    for r in db.query("SELECT scan_ids FROM assessments WHERE scan_ids IS NOT NULL"):
        for sid in (r.get("scan_ids") or "").split(","):
            sid = sid.strip()
            if sid:
                owned_scan_ids.add(sid)
    if SCANS_ROOT.exists():
        for entry in SCANS_ROOT.iterdir():
            if not entry.is_dir():
                continue
            if not SCAN_ID_RE.match(entry.name):
                continue
            if entry.name in owned_scan_ids:
                continue
            res = _delete_scan_dir(entry.name)
            summary["scans_removed"].append(res)

    if (summary["reports_removed"] or summary["logs_removed"]
            or summary["scans_removed"]):
        _audit("orphan_sweep", **summary)
    return summary


def find_pending() -> list[int]:
    """Return ids of assessments marked status='deleting' for the sweeper."""
    return [r["id"] for r in db.query(
        "SELECT id FROM assessments WHERE status = 'deleting' ORDER BY id")]


def delete_scan(scan_id: str) -> dict:
    """Public, safe delete of a single scan dir from /data/scans. Same
    guards as the assessment sweeper: regex, path-resolve, name whitelist.
    Does NOT touch the assessments table — caller decides whether to
    detach the scan_id from any owning assessment.

    Returns the same shape as `_delete_scan_dir`: {ok, scan_id, removed[],
    skipped[]} or {ok: False, error: ...}."""
    result = _delete_scan_dir(scan_id)
    if result.get("ok"):
        _audit("scan_deleted", scan_id=scan_id, **result)
    return result


def dedupe_for_fqdn(aid: int) -> int:
    """If assessment <aid> has keep_only_latest=1, mark every OTHER same-fqdn
    assessment in (done, error, cancelled) as 'deleting' so the lifespan
    sweeper tears them down asynchronously.

    Returns the number of rows marked. Safe to call on any assessment id
    (no-ops cleanly if the row is missing or keep_only_latest=0).

    Important properties:
      - In-flight scans (queued, running, consolidating, deleting) are
        NEVER touched. We won't race a running orchestrator.
      - Only OTHER rows are marked — the just-finished assessment <aid>
        itself is excluded so the user keeps the latest run.
      - Idempotent: marking an already-'deleting' row is harmless because
        of the status filter.

    Called from scripts/orchestrator.py at the very end of the run, after
    the row's terminal status has been written.
    """
    row = db.query_one(
        "SELECT fqdn, keep_only_latest FROM assessments WHERE id=%s",
        (aid,),
    )
    if not row:
        return 0
    if not int(row.get("keep_only_latest") or 0):
        return 0

    fqdn = row["fqdn"]
    victims = db.query(
        """SELECT id FROM assessments
            WHERE fqdn = %s
              AND id <> %s
              AND status IN ('done','error','cancelled')""",
        (fqdn, aid),
    )
    if not victims:
        return 0

    ids = [v["id"] for v in victims]
    placeholders = ",".join(["%s"] * len(ids))
    db.execute(
        f"UPDATE assessments SET status='deleting' "
        f"WHERE id IN ({placeholders})",
        ids,
    )
    _audit("dedupe_marked", trigger_assessment_id=aid, fqdn=fqdn,
           marked_assessment_ids=ids, count=len(ids))
    return len(ids)
