# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Database backup & restore.

The Settings → Database page lets an administrator dump the live MariaDB
to a gzipped .sql file (downloaded by the browser) and restore from a
previously-downloaded archive.

Why we shell out to mysqldump / mariadb-dump and the mysql client rather
than serialising row-by-row through pymysql:

  * mysqldump is the canonical tool. Triggers, views, AUTO_INCREMENT
    seeds, charset metadata, foreign-key reordering — it gets all of
    that right. Re-implementing it in pymysql would be ~500 lines of
    edge cases and the inevitable bug would silently produce a backup
    that won't restore.
  * It can stream — stdout is a pipe — so we can pipe through gzip and
    into a StreamingResponse without ever materialising the whole dump
    in memory. That matters once the findings table grows to gigabytes.

Large-import safety notes:

  * `--max-allowed-packet=1G` matches the server-side max_allowed_packet
    we set in docker-compose. mysqldump will otherwise refuse to emit a
    single multi-row INSERT bigger than its default (1MB).
  * `--single-transaction` snapshots InnoDB without locking; the dump is
    point-in-time consistent for the assessments / scans / findings
    tables (all InnoDB).
  * The restore path streams the upload through gunzip → mysql client.
    Memory stays bounded regardless of dump size.
"""
from __future__ import annotations

import gzip
import os
import re
import shutil
import subprocess
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional


# Where we keep dumps that the user creates via the UI. Mounted from
# the host (./data is bind-mounted into /data) so a host snapshot
# captures the dumps too.
BACKUPS_DIR = Path("/data/backups")
BACKUPS_DIR.mkdir(parents=True, exist_ok=True)


# Filename pattern for backups. Includes a UTC timestamp so files sort
# chronologically and a numeric suffix for the rare case of two
# backups taken in the same second. The pattern doubles as a
# whitelist for downloads / deletes — see _safe_filename().
BACKUP_FILENAME_RE = re.compile(
    r"^pentest-backup-\d{8}-\d{6}(?:-\d+)?\.sql\.gz$"
)


# Cap the upload size hard. 4 GiB is well above any realistic
# dump for this product (assessments + findings + scans) and well
# below the 5 GiB default for a memory-mapped file. Refuse anything
# bigger so a malformed multipart upload can't OOM the orchestrator.
MAX_RESTORE_BYTES = 4 * 1024 * 1024 * 1024


def _db_env() -> dict:
    """Connection details from the same env vars db.py reads. We re-read
    them on each invocation so a runtime change to DB_PASSWORD (e.g.
    after a rotation) takes effect immediately."""
    return {
        "host":     os.environ.get("DB_HOST", "127.0.0.1"),
        "port":     os.environ.get("DB_PORT", "13306"),
        "user":     os.environ.get("DB_USER", "pentest"),
        "password": os.environ.get("DB_PASSWORD", ""),
        "database": os.environ.get("DB_NAME", "pentest"),
    }


def _have_dump_tool() -> Optional[str]:
    """mysqldump is shipped as `mariadb-dump` on recent Debian (the
    mariadb-client package symlinks both names) but some bases only
    ship one. Find whichever is present so the call never tries to
    spawn a missing binary."""
    for name in ("mariadb-dump", "mysqldump"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _have_client_tool() -> Optional[str]:
    """Same idea for the mysql / mariadb client used during restore."""
    for name in ("mariadb", "mysql"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _safe_filename(name: str) -> Optional[str]:
    """Validate a filename against the canonical pattern. Refuses path
    separators and anything not matching BACKUP_FILENAME_RE. Returns the
    sanitised name or None when the input is unsafe."""
    name = (name or "").strip()
    if "/" in name or "\\" in name or name.startswith("."):
        return None
    return name if BACKUP_FILENAME_RE.match(name) else None


def list_backups() -> list[dict]:
    """Return one entry per .sql.gz file in BACKUPS_DIR, newest first.
    Used by the Settings page to render the table of available dumps."""
    out = []
    if not BACKUPS_DIR.exists():
        return out
    for p in sorted(BACKUPS_DIR.glob("pentest-backup-*.sql.gz"), reverse=True):
        try:
            st = p.stat()
        except OSError:
            continue
        if not BACKUP_FILENAME_RE.match(p.name):
            continue
        out.append({
            "filename": p.name,
            "size_bytes": st.st_size,
            "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc),
        })
    return out


def make_backup_filename() -> str:
    """Allocate a fresh BACKUPS_DIR/<filename> path that doesn't collide
    with anything already on disk. Adds a `-N` suffix when the wall-clock
    timestamp alone wouldn't be unique."""
    base = "pentest-backup-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = BACKUPS_DIR / f"{base}.sql.gz"
    n = 1
    while candidate.exists():
        candidate = BACKUPS_DIR / f"{base}-{n}.sql.gz"
        n += 1
    return candidate.name


def write_backup(target_filename: str) -> dict:
    """Run mysqldump → gzip → file. Returns {ok, path|error, size_bytes}.

    We launch mysqldump with `--result-file` set to /dev/stdout, then
    gzip the stream into the target file. The whole thing is bounded by
    pipe buffers so memory usage is constant regardless of how big the
    DB is — important once findings / raw_data are several GB."""
    tool = _have_dump_tool()
    if not tool:
        return {"ok": False,
                "error": "mariadb-dump / mysqldump is not installed in this image"}
    safe = _safe_filename(target_filename)
    if not safe:
        return {"ok": False,
                "error": "refusing unsafe backup filename"}
    out_path = BACKUPS_DIR / safe
    env = _db_env()
    # mysqldump reads --password from the env to keep it off the
    # process arg list (visible in `ps`). The `MYSQL_PWD` /
    # `MARIADB_PASSWORD` env names are both supported by the client.
    sub_env = os.environ.copy()
    sub_env["MYSQL_PWD"] = env["password"]
    sub_env["MARIADB_PASSWORD"] = env["password"]
    args = [
        tool,
        "--host=" + env["host"],
        "--port=" + str(env["port"]),
        "--user=" + env["user"],
        # InnoDB-only, so single-transaction is a non-locking
        # consistent-read snapshot. Without it, large dumps would lock
        # the assessments table for minutes at a time.
        "--single-transaction",
        # Don't try to lock MyISAM tables we don't have.
        "--skip-lock-tables",
        # Ship triggers / events / routines along with table data so the
        # restore is a faithful copy.
        "--triggers", "--events", "--routines",
        # Safe row defaults that survive across MariaDB minor versions.
        "--default-character-set=utf8mb4",
        # Big multi-row INSERT statements survive a 1 GB packet on the
        # restore side. Match this to the server-side max_allowed_packet
        # configured in docker-compose.
        "--max-allowed-packet=1G",
        # Quote identifiers + use the modern compat syntax.
        "--quote-names",
        env["database"],
    ]
    started = time.time()
    # gzip(1)'s default compression (-6) is the right balance between
    # CPU time and dump size for SQL — the format compresses well and
    # extra levels (-9) burn 30% more time for ~3% smaller output.
    try:
        with open(out_path, "wb") as raw_out:
            gz = gzip.GzipFile(fileobj=raw_out, mode="wb",
                               filename=safe.replace(".gz", ""),
                               compresslevel=6)
            try:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=sub_env)
                # 1 MB chunks — large enough that gzip overhead is not a
                # concern, small enough to be friendly with cgroup
                # memory limits on the host.
                while True:
                    chunk = proc.stdout.read(1024 * 1024)
                    if not chunk:
                        break
                    gz.write(chunk)
                proc.stdout.close()
                rc = proc.wait()
                err = proc.stderr.read().decode("utf-8", "replace")
                proc.stderr.close()
            finally:
                gz.close()
    except OSError as exc:
        return {"ok": False, "error": f"writing backup file failed: {exc}"}

    if rc != 0:
        # The dump failed mid-stream. Remove the partial file so the
        # listing only shows complete, restorable dumps.
        try:
            out_path.unlink()
        except OSError:
            pass
        # Trim noisy mysqldump warnings ("Using a password on the
        # command line interface can be insecure") so the message that
        # surfaces in the UI is the actually-useful one.
        msg = "; ".join(line.strip() for line in err.splitlines()
                        if line.strip()
                        and "Using a password" not in line)
        return {"ok": False,
                "error": f"mariadb-dump exited {rc}: {msg or 'unknown error'}"}

    return {
        "ok": True,
        "path": str(out_path),
        "filename": out_path.name,
        "size_bytes": out_path.stat().st_size,
        "elapsed_seconds": round(time.time() - started, 2),
    }


def delete_backup(filename: str) -> bool:
    """Remove a backup file. Returns True if a file was actually deleted.
    Validates the filename against the canonical pattern so this can't
    be coerced into a path traversal."""
    safe = _safe_filename(filename)
    if not safe:
        return False
    target = (BACKUPS_DIR / safe).resolve()
    backups_dir = BACKUPS_DIR.resolve()
    if not str(target).startswith(str(backups_dir)):
        return False
    if not target.exists():
        return False
    try:
        target.unlink()
    except OSError:
        return False
    return True


def restore_from_stream(stream: Iterator[bytes],
                        is_gzip: Optional[bool] = None) -> dict:
    """Apply a SQL dump from `stream` (an iterator of bytes chunks) onto
    the live database via the mysql/mariadb client.

    Auto-detects gzip on the wire by sniffing the first two bytes (0x1f
    0x8b). Callers can force the decision with is_gzip=True/False — used
    when the filename extension is the only hint.

    Returns {ok, message, total_bytes, elapsed_seconds}. On failure the
    message includes the client's stderr so the user can act on it
    (typical errors: max_allowed_packet too small, unknown database,
    duplicate primary key)."""
    tool = _have_client_tool()
    if not tool:
        return {"ok": False,
                "error": "mariadb / mysql client is not installed in this image"}
    env = _db_env()
    sub_env = os.environ.copy()
    sub_env["MYSQL_PWD"] = env["password"]
    sub_env["MARIADB_PASSWORD"] = env["password"]
    args = [
        tool,
        "--host=" + env["host"],
        "--port=" + str(env["port"]),
        "--user=" + env["user"],
        "--default-character-set=utf8mb4",
        # Match server-side max_allowed_packet so a row that the dump
        # tool produced under the same cap can fit through the client
        # write path during restore.
        "--max-allowed-packet=1G",
        # Don't bail on the first error — surface the one the user
        # cares about (likely the primary-key collision row, not a
        # downstream "table doesn't exist" cascade).
        "--force",
        env["database"],
    ]
    started = time.time()
    proc = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=sub_env)
    # zlib.decompressobj with `MAX_WBITS | 16` handles raw gzip streams,
    # incrementally — feed it chunks of arbitrary size and read out the
    # decompressed bytes as they're available. Cleaner than rebuilding a
    # GzipFile per chunk and retains state correctly across reads.
    decomp: Optional[zlib.decompressobj] = None
    total = 0
    sniff_buf = b""
    sniffed = (is_gzip is not None)
    if is_gzip is True:
        decomp = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        for chunk in stream:
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESTORE_BYTES:
                proc.stdin.close()
                proc.wait()
                return {"ok": False,
                        "error": (f"upload exceeded {MAX_RESTORE_BYTES} "
                                  "bytes — refusing to restore.")}
            if not sniffed:
                # Buffer until we have at least the first two bytes,
                # then decide whether the stream is gzipped.
                sniff_buf += chunk
                if len(sniff_buf) < 2:
                    continue
                is_gzip = sniff_buf[:2] == b"\x1f\x8b"
                if is_gzip:
                    decomp = zlib.decompressobj(zlib.MAX_WBITS | 16)
                chunk = sniff_buf
                sniff_buf = b""
                sniffed = True
            if decomp is not None:
                data = decomp.decompress(chunk)
            else:
                data = chunk
            if data:
                proc.stdin.write(data)
        # Flush any tail bytes the decompressor was holding back.
        if decomp is not None:
            tail = decomp.flush()
            if tail:
                proc.stdin.write(tail)
        proc.stdin.close()
    except BrokenPipeError:
        # Client died early (e.g. malformed SQL on first row). Fall
        # through to wait() and surface its stderr.
        pass
    except (OSError, zlib.error) as exc:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.kill()
        return {"ok": False, "error": f"restore stream IO failed: {exc}"}

    rc = proc.wait()
    err = proc.stderr.read().decode("utf-8", "replace")
    out = proc.stdout.read().decode("utf-8", "replace")
    proc.stderr.close()
    proc.stdout.close()
    elapsed = round(time.time() - started, 2)
    if rc != 0:
        # mysql/--force will run to completion and then exit non-zero
        # if any single statement failed. Surface a trimmed message.
        msg = "; ".join(line.strip() for line in err.splitlines()
                        if line.strip()
                        and "Using a password" not in line)
        return {"ok": False,
                "error": f"client exited {rc}: {msg or 'unknown error'}",
                "total_bytes": total,
                "elapsed_seconds": elapsed}
    return {
        "ok": True,
        "message": (out.strip() or
                    f"Restore complete — {total} byte(s) imported."),
        "total_bytes": total,
        "elapsed_seconds": elapsed,
    }
