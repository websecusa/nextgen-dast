# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Authentication / account audit log.

Appends one JSON object per line to /data/logs/auth_events.jsonl. We use
a flat JSONL file rather than a DB table so the log survives DB resets
and is easy to grep / ship to a SIEM. Every mutation to the users table
that goes through the web UI flows through here.

Schema for each line:
  ts      ISO-8601 UTC timestamp
  action  short verb (login_success, login_failure, password_set, ...)
  ok      bool — whether the action succeeded
  actor   {id, username} of the logged-in user performing the action,
          or None for unauthenticated paths (login attempts).
  target  {id, username} of the user being acted on, when relevant.
  ip      client IP, taken from X-Forwarded-For if present (the app sits
          behind nginx) else the direct peer address.
  extra   freeform dict of additional context (reason, role, etc.).

Failures here are non-fatal: the audit log is best-effort. A disk-full
or permission error must not break login or admin actions.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

LOG_PATH = Path(os.environ.get("AUTH_AUDIT_LOG", "/data/logs/auth_events.jsonl"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_event(
    action: str,
    *,
    ok: bool = True,
    actor: Optional[dict] = None,
    target: Optional[dict] = None,
    ip: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """Append one event line. Best-effort: any IO error is swallowed and
    a single warning is printed to stderr so the operator can see it in
    the container log without breaking the request."""
    record = {
        "ts": _now_iso(),
        "action": action,
        "ok": bool(ok),
        "actor": actor,
        "target": target,
        "ip": ip,
        "extra": extra or {},
    }
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Open in append mode with line buffering so concurrent writes
        # from multiple workers each land as a complete line. JSONL has
        # no header so this is safe to interleave.
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError as exc:
        print(f"[audit] WARN: could not write {LOG_PATH}: {exc}",
              file=sys.stderr, flush=True)


def actor_from_user(user: Optional[dict]) -> Optional[dict]:
    """Project a sessions.verify() payload (or a users row) down to the
    {id, username} pair we want in the audit record."""
    if not user:
        return None
    return {
        "id": user.get("id"),
        "username": user.get("username"),
    }
