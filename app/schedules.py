# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Scheduled-scan engine.

Two surfaces:
  - REST/HTML callers (server.py, api.py) use create / update / delete /
    list / fetch / spawn_one_off to manage rows in `scan_schedules`.
  - The lifespan sweeper (server.py) calls tick() once per minute. tick()
    looks up due rows, atomically advances next_run_at, and spawns the
    detached orchestrator subprocess for each due schedule via the same
    code path the manual /assess form uses.

Cron expressions are standard 5-field syntax (croniter), interpreted as
UTC. The application stores everything in UTC (matching the rest of the
schema) and templates render UTC; the browser-side JS in the schedules
template optionally re-displays "next 3 fires" in local time.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from croniter import croniter

import db


# Subprocess log dir matches what server.py / api.py already use so the
# detached orchestrator's stdout lands in the conventional spot.
LOGS_DIR = Path("/data/logs")


# ---------------------------------------------------------------------------
# Cron helpers
# ---------------------------------------------------------------------------

def validate_cron(expr: str) -> Optional[str]:
    """Return None if `expr` parses as a 5-field cron expression, else a
    short human-readable error string suitable for displaying back to the
    user (form validation / API 400 body)."""
    if not expr or not expr.strip():
        return "cron expression is required"
    try:
        if not croniter.is_valid(expr):
            return "invalid cron expression"
    except Exception as e:  # croniter raises various ValueErrors
        return f"invalid cron expression: {e}"
    return None


def compute_next_run(cron_expr: str,
                     after: Optional[datetime] = None) -> Optional[datetime]:
    """Return the next firing instant of `cron_expr` strictly after
    `after` (defaults to "now" in UTC). Returns None if the cron expression
    is invalid — callers should validate up front, but this guards against
    a row whose cron_expr was hand-edited in the DB."""
    if validate_cron(cron_expr) is not None:
        return None
    base = after if after is not None else datetime.now(timezone.utc)
    # Strip tzinfo for croniter (it works on naive datetimes; we treat all
    # of them as UTC to match the schema's naive DATETIME columns).
    if base.tzinfo is not None:
        base = base.replace(tzinfo=None)
    return croniter(cron_expr, base).get_next(datetime)


def preview_runs(cron_expr: str, count: int = 3) -> list[datetime]:
    """Return the next `count` fires for display in the UI. Empty list if
    the expression is invalid."""
    if validate_cron(cron_expr) is not None:
        return []
    it = croniter(cron_expr, datetime.utcnow())
    return [it.get_next(datetime) for _ in range(count)]


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

# Columns exposed to the create / update API. Whitelisted explicitly so a
# caller can never set internal bookkeeping like next_run_at or last_run_at.
_WRITABLE_FIELDS = (
    "name", "fqdn", "scan_http", "scan_https", "profile", "llm_tier",
    "llm_endpoint_id", "user_agent_id", "creds_username", "creds_password",
    "login_url", "application_id", "cron_expr", "start_after", "end_before",
    "enabled", "skip_if_running", "keep_only_latest",
)


def _normalize(payload: dict) -> dict:
    """Coerce form/API field types into the shape the DB expects.

    Booleans-as-strings become 0/1; empty strings become NULL for nullable
    columns; the FQDN is lower-cased and stripped of any scheme/path the
    user pasted in. Mirrors the normalization /assess does for one-off
    scans so a schedule run has identical inputs to a manual one.
    """
    out = {k: payload.get(k) for k in _WRITABLE_FIELDS if k in payload}

    # FQDN: same scheme-strip / lower-case as server.py /assess.
    if "fqdn" in out and out["fqdn"]:
        v = out["fqdn"].strip().lower()
        # Drop any scheme:// and any path the user pasted in.
        for prefix in ("http://", "https://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        out["fqdn"] = v.split("/", 1)[0]

    # Booleans (forms send "on" / "1" / missing).
    for k in ("scan_http", "scan_https", "enabled",
              "skip_if_running", "keep_only_latest"):
        if k in out:
            out[k] = 1 if out[k] in (1, "1", True, "on", "true") else 0

    # Empty strings → NULL for the nullable text columns.
    for k in ("creds_username", "creds_password", "login_url",
              "application_id", "start_after", "end_before",
              "llm_endpoint_id", "user_agent_id"):
        if k in out and (out[k] is None or out[k] == ""):
            out[k] = None

    # Cap application_id to its column width to match /assess.
    if out.get("application_id"):
        out["application_id"] = str(out["application_id"]).strip()[:128] or None

    return out


def create(payload: dict, created_by: Optional[int] = None) -> int:
    """Insert a new schedule. Returns the new row id.

    Raises ValueError on validation failure with a message safe to surface
    to the caller (form re-render / API 400 body).
    """
    data = _normalize(payload)
    if not data.get("name"):
        raise ValueError("name is required")
    if not data.get("fqdn"):
        raise ValueError("fqdn is required")
    if not data.get("cron_expr"):
        raise ValueError("cron_expr is required")
    err = validate_cron(data["cron_expr"])
    if err:
        raise ValueError(err)
    if data.get("profile") and data["profile"] not in (
            "quick", "standard", "thorough", "premium"):
        raise ValueError("invalid profile")
    if data.get("llm_tier") and data["llm_tier"] not in (
            "none", "basic", "advanced"):
        raise ValueError("invalid llm_tier")

    # Compute the initial next_run_at relative to start_after (if any) so a
    # schedule "starting next Monday" doesn't fire today.
    base = data.get("start_after") or datetime.utcnow()
    if isinstance(base, str):
        base = datetime.fromisoformat(base)
    nxt = compute_next_run(data["cron_expr"], base)

    cols = list(data.keys()) + ["next_run_at", "created_by"]
    placeholders = ", ".join(["%s"] * len(cols))
    col_sql = ", ".join(cols)
    values = [data[k] for k in data] + [nxt, created_by]
    return db.execute(
        f"INSERT INTO scan_schedules ({col_sql}) VALUES ({placeholders})",
        values,
    )


def update(sid: int, payload: dict) -> None:
    """Apply a partial update. Recomputes next_run_at if the cron expression
    or start window changed. Silently ignores unknown fields (caller may
    pass form data with extras like the CSRF token)."""
    data = _normalize(payload)
    if not data:
        return
    if "cron_expr" in data:
        err = validate_cron(data["cron_expr"])
        if err:
            raise ValueError(err)

    sets = ", ".join([f"{k}=%s" for k in data])
    values = [data[k] for k in data] + [sid]
    db.execute(
        f"UPDATE scan_schedules SET {sets} WHERE id=%s",
        values,
    )

    # Recompute next_run_at if the firing pattern moved. Reread the row so
    # we use the post-update cron / start_after values.
    if "cron_expr" in data or "start_after" in data:
        row = get(sid)
        if row:
            base = row.get("start_after") or datetime.utcnow()
            if isinstance(base, str):
                base = datetime.fromisoformat(base)
            nxt = compute_next_run(row["cron_expr"], base)
            db.execute(
                "UPDATE scan_schedules SET next_run_at=%s WHERE id=%s",
                (nxt, sid),
            )


def delete(sid: int) -> None:
    """Hard-delete a schedule row. Historical assessments that came from it
    keep their `schedule_id` value; the application code tolerates a stale
    reference (renders "(deleted schedule)")."""
    db.execute("DELETE FROM scan_schedules WHERE id=%s", (sid,))


def list_all() -> list[dict]:
    """Newest first. Used by /schedules and GET /api/v1/schedules."""
    return db.query(
        "SELECT * FROM scan_schedules ORDER BY id DESC"
    )


def get(sid: int) -> Optional[dict]:
    return db.query_one(
        "SELECT * FROM scan_schedules WHERE id=%s", (sid,)
    )


def set_enabled(sid: int, enabled: bool) -> None:
    """Toggle the enabled flag without disturbing the cron expression."""
    db.execute(
        "UPDATE scan_schedules SET enabled=%s WHERE id=%s",
        (1 if enabled else 0, sid),
    )


# ---------------------------------------------------------------------------
# Materialization (runs a schedule by inserting an assessments row)
# ---------------------------------------------------------------------------

def _materialize(sched: dict) -> int:
    """Insert an assessments row from a schedule and spawn its orchestrator.
    Returns the new assessment id. Caller is responsible for updating the
    schedule's last_run_at / last_assessment_id."""
    aid = db.execute(
        """INSERT INTO assessments
              (fqdn, scan_http, scan_https, profile, llm_tier,
               llm_endpoint_id, user_agent_id,
               creds_username, creds_password, login_url,
               application_id, schedule_id, keep_only_latest, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                   'queued')""",
        (
            sched["fqdn"],
            int(sched.get("scan_http") or 0),
            int(sched.get("scan_https") or 0),
            sched.get("profile") or "standard",
            sched.get("llm_tier") or "none",
            sched.get("llm_endpoint_id"),
            sched.get("user_agent_id"),
            sched.get("creds_username"),
            sched.get("creds_password"),
            sched.get("login_url"),
            sched.get("application_id"),
            sched["id"],
            int(sched.get("keep_only_latest") or 0),
        ),
    )

    # Detached orchestrator subprocess — same shape as server.py /assess
    # and api.py _spawn_orchestrator. Logs to /data/logs/orchestrator_<aid>.log.
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / f"orchestrator_{aid}.log"
    log_fh = open(log_path, "ab", buffering=0)
    subprocess.Popen(
        ["python", "-m", "scripts.orchestrator", str(aid)],
        stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/app",
    )
    return aid


def spawn_one_off(sid: int) -> Optional[int]:
    """Manual "Run now" button on the schedule UI / API. Materializes the
    schedule into an assessment without touching next_run_at — so the
    regular cron cadence is undisturbed. Returns the new assessment id, or
    None if the schedule is missing."""
    sched = get(sid)
    if not sched:
        return None
    aid = _materialize(sched)
    db.execute(
        """UPDATE scan_schedules
              SET last_run_at = UTC_TIMESTAMP(),
                  last_assessment_id = %s
            WHERE id = %s""",
        (aid, sid),
    )
    return aid


# ---------------------------------------------------------------------------
# Periodic tick (called by the lifespan sweeper)
# ---------------------------------------------------------------------------

def _has_inflight(fqdn: str) -> bool:
    """True if any assessment for this FQDN is queued/running/consolidating.
    Used by skip_if_running to avoid stacking long scans on themselves."""
    row = db.query_one(
        """SELECT 1 FROM assessments
            WHERE fqdn=%s
              AND status IN ('queued','running','consolidating')
            LIMIT 1""",
        (fqdn,),
    )
    return row is not None


def tick() -> int:
    """Materialize every due schedule. Returns the number fired this tick.

    Two safety properties:
      1. Race-safe advancement. We compute the new next_run_at and update
         it with a WHERE clause that pins the *current* next_run_at value,
         so two concurrent ticks (multiple workers, future sharding, etc.)
         won't double-fire the same schedule. Only the worker whose UPDATE
         actually mutates a row spawns an orchestrator.
      2. Always advance. Even if skip_if_running causes us to NOT spawn an
         assessment this round, we still bump next_run_at — otherwise a
         long-running scan would cause the schedule to fire as soon as it
         finishes, immediately stacking a new run on top.
    """
    now = datetime.utcnow()
    fired = 0

    rows = db.query(
        """SELECT * FROM scan_schedules
            WHERE enabled = 1
              AND next_run_at IS NOT NULL
              AND next_run_at <= %s
              AND (start_after IS NULL OR start_after <= %s)
              AND (end_before  IS NULL OR end_before   > %s)
            ORDER BY next_run_at ASC""",
        (now, now, now),
    )

    for sched in rows:
        sid = sched["id"]
        cur_nxt = sched["next_run_at"]
        new_nxt = compute_next_run(sched["cron_expr"], now)
        if new_nxt is None:
            # Invalid cron — disable the row so we don't keep retrying it
            # every minute. Operator gets to fix it via the UI.
            db.execute(
                "UPDATE scan_schedules SET enabled=0 WHERE id=%s",
                (sid,),
            )
            continue

        # Race-safe bump. If another worker already advanced this row, the
        # rowcount will be 0 and we skip materialization here.
        with db.get_db() as conn, conn.cursor() as cur:
            n = cur.execute(
                """UPDATE scan_schedules
                      SET next_run_at = %s
                    WHERE id = %s AND next_run_at = %s""",
                (new_nxt, sid, cur_nxt),
            )
        if n == 0:
            continue

        # Skip-if-running: schedule is due, but a prior run hasn't finished.
        # Don't fire — but next_run_at is already advanced so the next tick
        # works off the new cadence.
        if int(sched.get("skip_if_running") or 0) and \
                _has_inflight(sched["fqdn"]):
            continue

        try:
            aid = _materialize(sched)
        except Exception as e:
            # Don't let one bad schedule kill the whole tick. Log to stderr
            # so the failure shows up in container logs alongside the
            # sweeper's other output.
            print(f"[schedule tick] sid={sid} materialize failed: {e!r}",
                  flush=True)
            continue

        db.execute(
            """UPDATE scan_schedules
                  SET last_run_at = %s,
                      last_assessment_id = %s
                WHERE id = %s""",
            (now, aid, sid),
        )
        fired += 1

    return fired
