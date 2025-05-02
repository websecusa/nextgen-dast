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
WAPITI_ROOT = Path("/root/.wapiti/scans").resolve()
DELETION_LOG = Path("/data/logs/deletions.jsonl")

SCAN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
FQDN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,253}[a-z0-9]$")

# Only these names (and subpaths thereof) get removed inside a scan dir.
SCAN_ARTIFACT_NAMES = {
    "meta.json", "output.log", "flows.jsonl", "proxy.log",
    "report", "report.html", "report.json", "report.jsonl",
    "flows", "sqlmap", "auth_cookies.txt",
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


def cleanup_assessment(assessment_id: int) -> dict:
    """Remove all on-disk artifacts of an assessment AND its DB rows.

    Order matters: filesystem first, then DB. If filesystem cleanup fails
    midway, the assessment row stays and we can retry."""
    a = db.query_one("SELECT id, fqdn, scan_ids FROM assessments WHERE id = %s",
                     (int(assessment_id),))
    if not a:
        return {"ok": True, "note": "no such assessment"}

    summary = {"assessment_id": a["id"], "fqdn": a["fqdn"], "scans": []}
    sids = [s for s in (a.get("scan_ids") or "").split(",") if s.strip()]
    for sid in sids:
        summary["scans"].append(_delete_scan_dir(sid))

    summary["wapiti"] = _delete_wapiti_session(a["fqdn"])
    summary["log"] = _delete_orchestrator_log(a["id"])

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
