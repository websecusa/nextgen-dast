# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Pentest proxy + scanner UI.

- Manages a mitmdump subprocess in reverse-proxy mode for intercept logging.
- Launches wapiti / nikto scans against configurable targets.
- Serves a small Jinja2 web UI on 127.0.0.1:8888.
"""
import hmac
import json
import os
import re
from contextlib import asynccontextmanager
import shlex
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import psutil
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import api as api_mod
import audit as audit_mod
import auth as auth_mod
import branding as branding_mod
import cleanup as cleanup_mod
import db
import dbops as dbops_mod
import enrichment as enrichment_mod
import llm as llm_mod
import reports as reports_mod
import schedules as schedules_mod
import sessions
import toolkit as toolkit_mod
import useragent as ua_mod
import users as users_mod

ROOT_PATH = os.environ.get("UI_ROOT_PATH", "").rstrip("/")

DATA = Path("/data")
FLOWS_DIR = DATA / "flows"
LOGS_DIR = DATA / "logs"
SCANS_DIR = DATA / "scans"
STATE_FILE = DATA / "state.json"
FLOW_LOG = LOGS_DIR / "flows.jsonl"
PROXY_PID_FILE = DATA / "proxy.pid"
PROXY_LOG = LOGS_DIR / "proxy.log"

for d in (FLOWS_DIR, LOGS_DIR, SCANS_DIR):
    d.mkdir(parents=True, exist_ok=True)

DEFAULT_STATE = {
    "proxy": {
        "running": False,
        "listen_host": "127.0.0.1",
        "listen_port": 9443,
        "mode": "reverse",
        "upstream": "https://127.0.0.1:443",
        "upstream_host_header": "fairtprm.com",
        "ssl_insecure": True,
    }
}


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return json.loads(json.dumps(DEFAULT_STATE))


def save_state(s: dict) -> None:
    STATE_FILE.write_text(json.dumps(s, indent=2))


# ---- mitmdump process management ---------------------------------------------

def proxy_pid() -> Optional[int]:
    if not PROXY_PID_FILE.exists():
        return None
    try:
        pid = int(PROXY_PID_FILE.read_text().strip())
    except ValueError:
        return None
    if not psutil.pid_exists(pid):
        return None
    try:
        p = psutil.Process(pid)
        if "mitmdump" not in " ".join(p.cmdline()):
            return None
    except psutil.NoSuchProcess:
        return None
    return pid


def stop_proxy() -> None:
    pid = proxy_pid()
    if pid is None:
        if PROXY_PID_FILE.exists():
            PROXY_PID_FILE.unlink()
        return
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not psutil.pid_exists(pid):
                break
            time.sleep(0.1)
        if psutil.pid_exists(pid):
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if PROXY_PID_FILE.exists():
        PROXY_PID_FILE.unlink()


def start_proxy(cfg: dict) -> tuple[bool, str]:
    if proxy_pid() is not None:
        stop_proxy()

    listen_host = cfg["listen_host"]
    listen_port = int(cfg["listen_port"])
    upstream = cfg["upstream"].strip()
    host_header = (cfg.get("upstream_host_header") or "").strip()
    ssl_insecure = bool(cfg.get("ssl_insecure", True))

    if not re.match(r"^https?://", upstream):
        return False, f"upstream must start with http:// or https:// (got {upstream!r})"

    args = [
        "mitmdump",
        "--mode", f"reverse:{upstream}",
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "-s", "/app/proxy_addon.py",
        "--set", f"flow_log_path={FLOW_LOG}",
        "--set", "termlog_verbosity=info",
    ]
    if ssl_insecure:
        args += ["--set", "ssl_insecure=true"]
    if host_header:
        # mitmproxy modify_headers: /flow-filter/header-name/value
        args += ["--modify-headers", f"/~q/Host/{host_header}"]

    log_fh = open(PROXY_LOG, "ab", buffering=0)
    log_fh.write(f"\n--- start {datetime.now(timezone.utc).isoformat()} ---\n".encode())
    log_fh.write(("$ " + " ".join(shlex.quote(a) for a in args) + "\n").encode())
    proc = subprocess.Popen(
        args,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        cwd="/app",
        start_new_session=True,
    )
    PROXY_PID_FILE.write_text(str(proc.pid))
    # give it a moment to fail fast
    time.sleep(0.4)
    if proc.poll() is not None:
        if PROXY_PID_FILE.exists():
            PROXY_PID_FILE.unlink()
        tail = PROXY_LOG.read_bytes()[-2000:].decode("utf-8", "replace")
        return False, f"mitmdump exited immediately. tail:\n{tail}"
    return True, f"started pid {proc.pid}"


# ---- scan management ---------------------------------------------------------

def list_scans() -> list[dict]:
    scans = []
    for d in sorted(SCANS_DIR.iterdir(), reverse=True):
        meta = d / "meta.json"
        if not meta.exists():
            continue
        try:
            m = json.loads(meta.read_text())
        except Exception:
            continue
        # refresh status if process gone
        if m.get("status") == "running":
            pid = m.get("pid")
            if pid and not psutil.pid_exists(pid):
                m["status"] = "finished"
                m["finished_at"] = m.get("finished_at") or datetime.now(timezone.utc).isoformat()
                meta.write_text(json.dumps(m, indent=2))
        scans.append(m)
    return scans


def kill_scan(scan_id: str) -> None:
    meta = SCANS_DIR / scan_id / "meta.json"
    if not meta.exists():
        return
    m = json.loads(meta.read_text())
    pid = m.get("pid")
    if pid and psutil.pid_exists(pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    m["status"] = "killed"
    m["finished_at"] = datetime.now(timezone.utc).isoformat()
    meta.write_text(json.dumps(m, indent=2))


def _free_port(low: int = 19000, high: int = 19999) -> int:
    import socket
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            p = s.getsockname()[1]
        if low <= p <= high or True:  # any free ephemeral port is fine
            return p
    raise RuntimeError("no free port")


def start_scan(tool: str, target: str, extra: str = "",
               auth_profile: str = "",
               user_agent: Optional[str] = None) -> tuple[str, Optional[str]]:
    scan_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    sdir = SCANS_DIR / scan_id
    sdir.mkdir(parents=True, exist_ok=True)
    out = sdir / "output.log"
    extra_args = shlex.split(extra) if extra else []

    profile = auth_mod.get_profile(auth_profile) if auth_profile else None
    auth_args: list[str] = []
    auth_warning: Optional[str] = None
    if profile:
        if tool == "wapiti":
            auth_args = auth_mod.wapiti_args(profile, sdir, target)
        elif tool == "nikto":
            auth_args, auth_warning = auth_mod.nikto_args(profile)

    proxy_port = _free_port()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    # Some scanners need an explicit --proxy flag (HTTP_PROXY env isn't enough
    # for Perl/Python tools that use their own HTTP client). testssl.sh uses
    # raw TLS sockets so a HTTP proxy can't capture it — we skip the wrapper
    # for testssl and warn instead.

    if tool == "wapiti":
        report = sdir / "report"
        # Defensive — wapiti's html generator does create its output dir, but
        # other formats (json) write a file with plain open() and fail if the
        # parent is missing. Pre-creating here keeps both branches uniform and
        # immune to the "scan ran for an hour, then crashed on report write"
        # failure mode.
        report.mkdir(parents=True, exist_ok=True)
        cmd = ["wapiti", "-u", target, "-f", "html", "-o", str(report),
               "--flush-session", "--verbose", "1",
               "--proxy", proxy_url,
               # broaden the default attack surface — wapiti's default subset
               # routinely returns "0 vulnerabilities" on shallow targets.
               "-m", "all"]
        cmd += auth_args
        cmd += extra_args
    elif tool == "nikto":
        report = sdir / "report.html"
        cmd = ["nikto", "-h", target, "-output", str(report), "-Format", "htm",
               "-ask", "no", "-nointeractive",
               "-useproxy", proxy_url]
        cmd += auth_args
        cmd += extra_args
    elif tool == "nuclei":
        report = sdir / "report.jsonl"
        cmd = ["nuclei", "-target", target, "-jsonl-export", str(report),
               "-disable-update-check", "-no-color", "-silent",
               "-severity", "info,low,medium,high,critical",
               "-proxy", proxy_url]
        cmd += extra_args
    elif tool == "testssl":
        # raw TLS — no HTTP proxy capture. Flow files won't exist for this.
        report = sdir / "report.json"
        cmd = ["testssl.sh", "--jsonfile", str(report),
               "--quiet", "--color", "0", "--warnings", "off", target]
        cmd += extra_args
        proxy_port = 0  # signal: don't wrap with mitmdump
    elif tool == "sqlmap":
        report = sdir / "sqlmap"
        cmd = ["sqlmap", "-u", target, "--batch", "--output-dir", str(report),
               "--random-agent",
               "--proxy", proxy_url]
        cmd += extra_args
    elif tool == "dalfox":
        report = sdir / "report.json"
        cmd = ["dalfox", "url", target, "--format", "json",
               "--output", str(report), "--no-spinner", "--silence",
               "--proxy", proxy_url]
        cmd += extra_args
    else:
        raise ValueError(f"unknown tool: {tool}")

    # apply user-agent flags per scanner (skips testssl)
    ua_flags = ua_mod.flags_for(tool, user_agent)
    if ua_flags:
        cmd += ua_flags

    # wrap with run_scan.sh unless this scanner doesn't go over HTTP
    if proxy_port:
        cmd = ["/app/scripts/run_scan.sh", str(sdir), str(proxy_port), "--"] + cmd

    log_fh = open(out, "ab", buffering=0)
    log_fh.write(f"$ {' '.join(shlex.quote(c) for c in cmd)}\n".encode())
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    meta = {
        "id": scan_id,
        "tool": tool,
        "target": target,
        "extra": extra,
        "auth_profile": auth_profile or None,
        "auth_warning": auth_warning,
        "cmd": cmd,
        "pid": proc.pid,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2))
    return scan_id, auth_warning


# ---- flow log helpers --------------------------------------------------------

def read_flows(limit: int = 200) -> list[dict]:
    if not FLOW_LOG.exists():
        return []
    # read tail efficiently
    try:
        lines = FLOW_LOG.read_text(errors="replace").splitlines()
    except Exception:
        return []
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return list(reversed(out))


def read_flow(flow_id: str) -> Optional[dict]:
    if not FLOW_LOG.exists():
        return None
    for line in FLOW_LOG.read_text(errors="replace").splitlines():
        try:
            f = json.loads(line)
        except Exception:
            continue
        if f.get("id") == flow_id:
            return f
    return None


# ---- FastAPI app -------------------------------------------------------------

# Mask anything that looks like credentials in a displayed scanner command
# so screenshots / over-the-shoulder views don't leak the auditor1 password.
_CRED_MASK_FLAGS = (
    "--form-cred", "--auth-cred", "--auth-user", "--auth-password",
    "--form-user", "--form-password", "--cookie", "-C", "--header",
    "--api-key", "--token", "-id",
)


def mask_command(cmd: list) -> list:
    """Replace the value following any credential-bearing flag with '***'."""
    if not cmd:
        return []
    out = list(cmd)
    for i, tok in enumerate(out):
        if tok in _CRED_MASK_FLAGS and i + 1 < len(out):
            out[i + 1] = "***"
    return out


def reap_zombie_assessments(startup: bool = False) -> int:
    """Mark as 'error' any in-flight assessments whose worker process is gone.

    A row is considered a zombie when its `worker_pid` no longer exists in this
    container's PID namespace — typically because the nextgen-dast container
    was restarted (or OOM-killed) while a scan was mid-flight, leaving the
    assessment row stuck in 'running' / 'consolidating' forever.

    On startup we additionally reap 'queued' rows: their orchestrator was
    spawned by a previous instance of this container, so those PIDs are gone
    too. During steady-state sweeps we leave fresh 'queued' rows alone — the
    UI may have just inserted one and the orchestrator hasn't claimed its
    worker_pid yet.

    Returns the number of rows reaped.
    """
    if not db.healthy():
        return 0
    statuses = ("queued", "running", "consolidating") if startup \
        else ("running", "consolidating")
    placeholders = ",".join(["%s"] * len(statuses))
    rows = db.query(
        f"SELECT id, status, worker_pid FROM assessments "
        f"WHERE status IN ({placeholders})",
        statuses,
    )
    reaped = 0
    for r in rows:
        pid = r.get("worker_pid")
        # During steady-state sweeps, only reap rows that actually claimed
        # a pid. A NULL worker_pid on a 'running' row is unexpected but we
        # don't want to race the orchestrator's own status update.
        if pid is None and not startup:
            continue
        if pid is not None and psutil.pid_exists(pid):
            continue  # still alive — leave it
        msg = ("worker process gone (container restart or crash); "
               "scan was interrupted and must be re-run")
        db.execute(
            "UPDATE assessments SET status='error', error_text=%s, "
            "finished_at=NOW() WHERE id=%s AND status IN "
            f"({placeholders})",
            (msg, r["id"], *statuses),
        )
        reaped += 1
    return reaped


@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan — runs a one-shot zombie reap at startup, then
    a background sweeper that (a) drives 'deleting' cleanups and (b)
    periodically reaps any newly-orphaned in-flight assessments.

    The startup reap matters because detached orchestrator subprocesses are
    in this container's PID namespace; a container restart kills them but
    leaves the DB rows stuck in 'running'. The periodic reap catches the
    rarer case of a worker dying mid-scan while the app stays up.
    """
    import asyncio

    try:
        n = reap_zombie_assessments(startup=True)
        if n:
            print(f"[startup] reaped {n} zombie assessment(s) from prior run",
                  flush=True)
    except Exception as e:
        print(f"[startup] zombie reap failed: {e!r}", flush=True)

    # Schema drift check + auto-heal. If the live DB is missing any table
    # or column the application reads at runtime, apply db/schema.sql in
    # place so an admin who just `docker compose pull && up -d`'d into a
    # newer image gets the new tables/columns without a separate
    # `pentest.sh reset` step. schema.sql is idempotent (every CREATE has
    # IF NOT EXISTS, every ALTER uses IF NOT EXISTS / MODIFY, every INSERT
    # uses INSERT IGNORE), so re-applying it on a clean DB is a no-op
    # beyond the round-trips. We only run the heal when drift is detected
    # so steady-state restarts stay fast.
    try:
        from scripts.verify_schema import check as _schema_check
        issues = _schema_check(db)
        if issues:
            print("[startup] schema drift detected — auto-applying "
                  "db/schema.sql:", flush=True)
            for line in issues:
                print(f"[startup]   - {line}", flush=True)
            try:
                from scripts.reset import apply_schema as _apply_schema
                with db.get_db() as _conn:
                    _apply_schema(_conn, "/app/db/schema.sql")
                # Re-verify so the operator can see whether the heal
                # actually closed every gap. A residual drift after this
                # block indicates a hand-edited schema.sql or insufficient
                # DB privileges — both require human attention.
                residual = _schema_check(db)
                if residual:
                    print("[startup] SCHEMA DRIFT REMAINS after auto-heal "
                          "— investigate / re-run scripts/reset.py:",
                          flush=True)
                    for line in residual:
                        print(f"[startup]   - {line}", flush=True)
                else:
                    print("[startup] schema drift healed.", flush=True)
            except Exception as e:
                print(f"[startup] auto-heal failed: {e!r} — re-run "
                      f"scripts/reset.py manually", flush=True)
    except Exception as e:
        print(f"[startup] schema verify failed: {e!r}", flush=True)

    # Boot-time data migrations. Idempotent: each migration in
    # app/migrations.py:MIGRATIONS runs exactly once per database. The
    # bookkeeping table self-creates on first call. A failure raises so
    # the operator notices a half-applied state instead of getting a
    # silently-broken healthy container. We catch the exception here
    # only to surface it via the same [startup] log channel the rest of
    # the lifespan uses; the migration row is already marked 'failed' in
    # the DB, so the next boot will retry it.
    try:
        import migrations as _migrations_mod
        _migrations_mod.run_pending()
    except Exception as e:
        print(f"[startup] schema migration FAILED: {e!r} — see "
              f"schema_migrations table for the failed row; the next "
              f"boot will retry once the underlying issue is fixed",
              flush=True)

    # Seed Enhanced-AI default prompts on a fresh DB. Idempotent: each row
    # is matched by (slot, name) and only inserted if missing, so re-running
    # on every boot is safe. The schema-drift heal above creates the
    # ai_prompts table on existing 2.1.1 databases the first time the new
    # image boots; this block then populates it with the eleven default
    # scenarios. A failure does not block startup — the AI-Prompts admin
    # page can re-seed via "Restore to default".
    try:
        import enhanced_ai_prompts as _eap_mod
        n_seeded = _eap_mod.seed_defaults_if_empty(db)
        if n_seeded:
            print(f"[startup] seeded {n_seeded} default Enhanced-AI prompt(s)",
                  flush=True)
        # FOOTER schema bump (v2 split reproduction/remediation):
        # auto-restore seeded weakness rows whose system_prompt still
        # carries the old single-`recommendation` field. Operator-edited
        # rows (is_seeded=0) are NOT touched — those are someone's
        # custom work and should keep whatever schema they were
        # written with. Idempotent on subsequent boots once the in-DB
        # FOOTER includes the new "reproduction" string.
        try:
            stale = db.query_all(
                "SELECT id FROM ai_prompts "
                "WHERE slot=%s AND is_seeded=1 "
                "  AND system_prompt NOT LIKE '%%\"reproduction\"%%'",
                ("advanced_ai_testing.weakness_discovery",))
            if stale:
                result = _eap_mod.restore_defaults(
                    db, only_slot="advanced_ai_testing.weakness_discovery")
                print(f"[startup] FOOTER schema bumped — restored "
                      f"{len(result.get('restored') or [])} seeded "
                      f"weakness prompts to v2 (reproduction + remediation)",
                      flush=True)
        except Exception as e2:
            print(f"[startup] FOOTER schema restore failed: {e2!r} — "
                  f"existing prompts will keep emitting legacy schema",
                  flush=True)
    except Exception as e:
        print(f"[startup] enhanced_ai_prompts seed failed: {e!r} — "
              f"defaults can be reseeded from /admin/ai-prompts",
              flush=True)

    # One-shot orphan sweep at startup. Catches storage left behind by
    # pre-fix builds whose cleanup did not know about reports / challenge
    # logs, plus any scan dirs / logs whose owning assessment was deleted
    # while this container was down.
    try:
        s = cleanup_mod.sweep_orphans()
        n_r = len(s.get("reports_removed") or [])
        n_l = len(s.get("logs_removed") or [])
        n_s = len(s.get("scans_removed") or [])
        if n_r or n_l or n_s:
            print(f"[startup] orphan sweep: {n_r} report dir(s), "
                  f"{n_l} log file(s), {n_s} scan dir(s) cleaned up",
                  flush=True)
    except Exception as e:
        print(f"[startup] orphan sweep failed: {e!r}", flush=True)

    # Orphan sweep runs every Nth pass of the 60-second sweeper. Hourly
    # is plenty; the per-deletion path already cleans everything for a
    # normal /assessment/{id}/delete, so this only catches old leaks
    # (pre-fix) and manual-DELETE / crash-mid-cleanup cases.
    ORPHAN_SWEEP_EVERY = 60   # passes (= once an hour at 60s/pass)

    # SCA + scanner-update background refresh. Pulled into the same
    # sweeper to avoid a second long-lived task. The interval is
    # configurable via the `sca_update_interval_hours` config row so
    # an operator can throttle (or effectively disable, by setting it
    # very high) without rebuilding the image. The actual refresh runs
    # in a worker thread so the asyncio loop is not blocked while
    # network downloads stream in.
    import threading
    # Seed last-run timestamp from the config row written by the previous
    # container's last successful refresh — otherwise every restart kicks
    # off a brand-new update cycle even when the cache is still fresh.
    sca_state = {"last_run_at": 0.0, "in_flight": False}
    try:
        _row = db.query_one("SELECT value FROM config WHERE `key`=%s",
                            ("sca_last_updated_at",))
        if _row and (_row.get("value") or "").strip():
            sca_state["last_run_at"] = datetime.strptime(
                _row["value"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        pass

    def _sca_interval_hours() -> float:
        # Default 24 h. Out-of-band edits to the config row are picked
        # up on the next sweeper tick.
        try:
            row = db.query_one(
                "SELECT value FROM config WHERE `key`=%s",
                ("sca_update_interval_hours",))
            if row and (row.get("value") or "").strip():
                return max(1.0, float(row["value"]))
        except Exception:
            pass
        return 24.0

    def _sca_refresh_thread():
        # Imported lazily so the app can boot even if scripts/ is missing
        # (e.g. an air-gapped image stripped of the updater).
        try:
            from scripts import update_scanners as _upd
            _upd.run(scope="all",
                     log_path=Path("/data/logs/sca_update.log"))
        except Exception as e:
            print(f"[sca-update] refresh failed: {e!r}", flush=True)
        finally:
            sca_state["in_flight"] = False
            sca_state["last_run_at"] = time.time()

    async def sweeper():
        nonlocal_pass = {"n": 0}
        while True:
            try:
                ids = cleanup_mod.find_pending()
                for aid in ids:
                    try:
                        cleanup_mod.cleanup_assessment(aid)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                reap_zombie_assessments(startup=False)
            except Exception:
                pass
            nonlocal_pass["n"] += 1
            if nonlocal_pass["n"] % ORPHAN_SWEEP_EVERY == 0:
                try:
                    cleanup_mod.sweep_orphans()
                except Exception:
                    pass
            # Once per sweeper tick: check whether the SCA / scanner
            # update is due and (if so, and not already running) kick
            # off a background refresh thread.
            try:
                if not sca_state["in_flight"]:
                    age_h = (time.time() - sca_state["last_run_at"]) / 3600.0
                    if age_h >= _sca_interval_hours():
                        sca_state["in_flight"] = True
                        threading.Thread(
                            target=_sca_refresh_thread,
                            name="sca-update",
                            daemon=True,
                        ).start()
            except Exception:
                pass
            # Scheduled-scan tick. Materializes any due `scan_schedules`
            # row into a real assessment and spawns its orchestrator. Cron
            # resolution is to the minute, which matches the 60-second
            # cadence of this loop.
            try:
                schedules_mod.tick()
            except Exception as e:
                print(f"[schedule tick] failed: {e!r}", flush=True)
            await asyncio.sleep(60)

    task = asyncio.create_task(sweeper())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="nextgen-dast", root_path=ROOT_PATH, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="/app/static"), name="static")
templates = Jinja2Templates(directory="/app/templates")

# Markdown filter for finding description / remediation rendering.
# The Enhanced-AI-Testing weakness-discovery prompts emit markdown
# (fenced code blocks, headings, bullet lists) by design — the FOOTER
# explicitly tells the model to use fenced code blocks for any test
# payload, curl scaffold, or PoC snippet. Without a markdown pass the
# triple backticks render literally and the analyst sees a wall of
# pre-wrap text. The `safe` extensions list omits `attr_list` and
# `md_in_html` because the source text comes from an LLM and those
# extensions broaden the HTML attack surface; fenced_code + tables +
# nl2br + sane_lists is enough for the analyst-facing detail page.
import markdown as _markdown
from markupsafe import Markup as _Markup

_MD = _markdown.Markdown(
    extensions=["fenced_code", "tables", "nl2br", "sane_lists"],
    output_format="html5",
)


def _md_filter(text: str | None) -> _Markup:
    """Jinja filter: render an LLM-emitted markdown blob as safe HTML.
    Empty/None passes through as empty string. The Markdown instance is
    long-lived; we call .reset() each time to clear any per-render
    state (footnote counters, etc.) so the same instance can be reused
    across thousands of finding renders."""
    if not text:
        return _Markup("")
    _MD.reset()
    return _Markup(_MD.convert(str(text)))


templates.env.filters["md"] = _md_filter

# RESTful API (token-auth + IP whitelist). See app/api.py for the full
# surface description. Mounted at /api/v1; the auth middleware below
# whitelists /api/ so the router enforces its own token-based auth
# instead of the cookie-based session check used by the web UI.
app.include_router(api_mod.router)


# ---- auth middleware --------------------------------------------------------
# Public paths (no login required). Everything else requires a valid session.
# /api/v1 is also listed here because the API surface enforces its OWN token-
# based authentication (see app/api.py); the session cookie does not apply.
PUBLIC_PATHS = ("/login", "/health", "/static", "/branding/logo", "/api")
ADMIN_PATHS = ("/admin",)
# Routes a readonly user is allowed to POST to (otherwise POST/DELETE/PUT
# require admin role).
READONLY_WRITE_OK = ("/me/",)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # request.url.path includes the nginx /test prefix because we strip it at
    # the proxy layer rather than at uvicorn's --root-path. Normalize here so
    # PUBLIC_PATHS matches regardless of how it gets to us.
    if ROOT_PATH and path.startswith(ROOT_PATH):
        path = path[len(ROOT_PATH):] or "/"
    if any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS):
        return await call_next(request)

    cookie = request.cookies.get(sessions.COOKIE_NAME)
    user = sessions.verify(cookie) if cookie else None
    # Sessions issued before the CSRF rollout do not carry a `csrf` field.
    # Treat them as invalid so the user gets a fresh, CSRF-bound session
    # the next time they sign in. One-time inconvenience at upgrade.
    if user and not user.get("csrf"):
        user = None
    if not user:
        return RedirectResponse(
            f"{ROOT_PATH}/login?next={path}", status_code=303
        )

    request.state.user = user

    # Both 'admin' and 'superadmin' satisfy the coarse admin gate.
    # Per-route superadmin-only enforcement (AI Prompts editor, system-
    # default budget, per-user max_spend changes) lives in the individual
    # handlers via require_superadmin() so the middleware can stay
    # path-pattern-based and route changes can adjust gating without
    # touching the middleware.
    if (any(path.startswith(p) for p in ADMIN_PATHS)
            and user.get("role") not in ("admin", "superadmin")):
        return JSONResponse({"error": "admin only"}, status_code=403)

    if (request.method in ("POST", "PUT", "DELETE", "PATCH")
            and user.get("role") not in ("admin", "superadmin")
            and not any(path.startswith(p) for p in READONLY_WRITE_OK)):
        return JSONResponse(
            {"error": "read-only account — write actions require an admin"},
            status_code=403,
        )

    return await call_next(request)


def current_user(request: Request) -> Optional[dict]:
    return getattr(request.state, "user", None) if hasattr(request, "state") else None


# Account / auth surfaces that mutate state. CSRF is enforced by the
# individual handlers (see check_csrf below) so the middleware does not
# have to peek at request bodies. The list lives here so it is visible
# next to the auth middleware that classifies these routes.
CSRF_PROTECTED_PATHS = (
    "/me/password",
    "/admin/users",   # covers /admin/users, /admin/users/{uid}/...
    "/logout",
)


def check_csrf(request: Request, token: str) -> None:
    """Constant-time compare the form-supplied csrf_token against the
    token bound to the session. Raise 403 on any mismatch."""
    user = current_user(request) or {}
    expected = user.get("csrf", "")
    sent = (token or "").strip()
    if not expected or not sent or not hmac.compare_digest(expected, sent):
        raise HTTPException(status_code=403, detail="invalid CSRF token")


def require_superadmin(request: Request) -> dict:
    """Raise 403 unless the current session is a superadmin. Returns the
    user dict on success so callers can use it without a second
    current_user(request) round-trip. Use this on handlers that mutate
    AI prompts, the system-default Enhanced-AI budget, per-user
    max_spend caps, or role transitions involving 'superadmin' — these
    are the screens we deliberately gate above admin to prevent an
    admin compromise from raising costs or weakening AI guardrails."""
    user = current_user(request) or {}
    if user.get("role") != "superadmin":
        raise HTTPException(status_code=403,
                              detail="superadmin role required")
    return user


def _same_origin(request: Request) -> bool:
    """Return True when the request's Origin / Referer either match the
    request Host or are absent.

    Used by pre-auth state-changing endpoints (e.g. POST /login) where
    the standard CSRF token cannot apply because there is no session
    yet to bind a token to. Defense-in-depth on top of the SameSite=
    Strict session cookie: SameSite blocks the *post-login* cookie from
    being sent on cross-site navigation, but does not stop a malicious
    page from POSTing the login itself. Comparing Origin/Referer
    against Host catches that vector — a browser-driven cross-origin
    POST will always carry one of those headers set to the attacker's
    origin, so any mismatch is rejected.

    When neither Origin nor Referer is present (curl, server-to-server
    integrations, some legacy clients), there is no browser claim to
    validate and the request is allowed through. Browsers always send
    Origin on cross-site POSTs, so absence implies same-origin or non-
    browser traffic.
    """
    host = (request.headers.get("host") or "").strip().lower()
    if not host:
        # Nothing to compare against; do not block on a missing Host.
        return True
    claimed = (request.headers.get("origin")
               or request.headers.get("referer")
               or "").strip()
    if not claimed:
        return True
    try:
        parsed = urlparse(claimed)
    except Exception:
        return False
    claimed_host = (parsed.netloc or "").lower()
    if not claimed_host:
        return False
    # Strip default ports so https://x.com and https://x.com:443 match.
    for default_port in (":443", ":80"):
        if claimed_host.endswith(default_port):
            claimed_host = claimed_host[:-len(default_port)]
            break
    return claimed_host == host


def client_ip(request: Request) -> str:
    """Best-effort client IP for audit logging. Honors X-Forwarded-For
    (the app sits behind nginx → uvicorn over loopback), falling back
    to the direct peer address if the header is missing."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # First entry is the original client; the rest is the proxy
        # chain inserted by intermediate hops.
        return xff.split(",", 1)[0].strip()
    real = request.headers.get("x-real-ip", "")
    if real:
        return real.strip()
    if request.client:
        return request.client.host
    return ""


def redirect(path: str, code: int = 303) -> RedirectResponse:
    """Build a redirect that survives being served under a path prefix."""
    if path.startswith("/"):
        return RedirectResponse(f"{ROOT_PATH}{path}", status_code=code)
    return RedirectResponse(path, status_code=code)


def ctx(request: Request, **extra) -> dict:
    state = load_state()
    user = current_user(request)
    try:
        if db.healthy():
            brand = branding_mod.get()
            web_theme = branding_mod.get_web()
        else:
            brand, web_theme = {}, branding_mod.DARK_DEFAULTS
    except Exception:
        brand, web_theme = {}, branding_mod.DARK_DEFAULTS
    return {
        "request": request,
        "base": ROOT_PATH,
        "state": state,
        "proxy_running": proxy_pid() is not None,
        "user": user,
        # is_admin is the coarse "can mutate" gate consulted by every
        # admin-only screen. Both 'admin' and the new 'superadmin' tier
        # pass this check — superadmin is a strict superset of admin.
        # Template fragments that need superadmin-only behavior (AI
        # Prompts editor, system-default budget, max_spend column, the
        # editable per-scan budget input) should consult is_superadmin
        # below instead.
        "is_admin": ((user.get("role") in ("admin", "superadmin"))
                     if user else False),
        "is_superadmin": ((user.get("role") == "superadmin")
                          if user else False),
        # csrf_token is rendered into the hidden field of every form that
        # POSTs to a CSRF-protected endpoint. Empty string when the user
        # is not logged in (templates handle that case themselves).
        "csrf_token": (user or {}).get("csrf", ""),
        "brand": brand,
        "web": web_theme,
        # User-selected UI theme. 'dark' (default) or 'light'. Read fresh
        # from the users row on every render so a theme flip is visible
        # immediately without a session re-issue. Falls back to 'dark'
        # for unauthenticated visitors and any DB read error so the
        # login page never flashes a theme variant.
        "user_theme": _resolve_user_theme(user),
        **extra,
    }


def _resolve_user_theme(user: Optional[dict]) -> str:
    """Return 'dark' or 'light' for the supplied user. Reads the theme
    column off the users row; returns 'dark' on any failure (no user,
    DB error, missing column on a stale schema). Centralised so the
    dark fallback rule lives in exactly one place."""
    if not user:
        return "dark"
    try:
        row = db.query_one(
            "SELECT theme FROM users WHERE id=%s", (user.get("id"),))
    except Exception:
        return "dark"
    if not row:
        return "dark"
    val = (row.get("theme") or "dark").strip().lower()
    return val if val in ("dark", "light") else "dark"


def _dashboard_data(trend_filter: Optional[str] = None,
                    trend_days: int = 30) -> dict:
    """Aggregate the metrics shown on the / overview page.

    Returns a dict with severity counts, finished-assessment metrics, a
    findings-by-day series for the trend chart, the unresolved-by-age
    breakdown, the resolved-by-age breakdown, and a recent-activity
    list. All queries skip triaged findings (false-positive, fixed,
    accepted_risk) so the dashboard mirrors what's actually actionable.

    `trend_filter`, when set, restricts JUST the trend chart's series
    to assessments whose fqdn or application_id matches the substring.
    The filter intentionally does not propagate to the KPI strip /
    age matrices -- the typeahead is a per-card lens, not a global
    filter.

    `trend_days` controls the trend chart window (allowed: 7, 14, 21,
    30). Out-of-range values clamp to 30 so a tampered query string
    cannot cause the SQL to scan an unbounded history.

    Falls back to a zeroed-out dict when the DB isn't reachable so the
    page still renders during a database outage."""
    # Whitelist + clamp the trend window. The route handler should
    # already constrain this, but keep a defensive copy so any internal
    # caller that builds the dashboard data directly cannot trigger an
    # unbounded INTERVAL.
    if trend_days not in (7, 14, 21, 30):
        trend_days = 30
    from datetime import date, timedelta
    # Trend chart deliberately omits 'info' (high-volume, low-signal
    # noise that flattens the more interesting bands). Other UI
    # surfaces still show info; this restriction is chart-only.
    sev_chart_order = ("critical", "high", "medium", "low")
    empty = {
        "kpi": {"open": 0, "delta_7d": 0, "validated": 0, "false_positive": 0,
                "targets": 0, "assessments": 0, "last_scan": None,
                "risk_score": None, "sev": {s: 0 for s in
                    ("critical", "high", "medium", "low", "info")}},
        "trend": {"days": [], "series": {s: [] for s in sev_chart_order},
                  "bands": [], "max_total": 0, "w": 1000.0, "h": 200.0,
                  "filter": "", "filter_targets": [], "filter_matched": True},
        "targets": [], "ages": {">30 days": {}, ">60 days": {}, ">90 days": {}},
        "resolved_ages": {">30 days": {}, ">60 days": {}, ">90 days": {}},
        "recent": [],
    }
    if not db.healthy():
        return empty

    # Every count on this dashboard treats triaged findings as "done":
    # false-positive (suppressed), fixed (resolved), and accepted_risk
    # (archived) all drop out so the dashboard mirrors what's actually
    # actionable. The same exclusion drives the per-target live risk
    # below and the trend-chart series.
    triage_clause = "status NOT IN ('false_positive', 'fixed', 'accepted_risk')"

    sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for r in db.query(
            f"SELECT severity, COUNT(*) AS n FROM findings "
            f"WHERE {triage_clause} GROUP BY severity"):
        sev[r["severity"]] = int(r["n"] or 0)
    open_total = sum(sev.values())

    # 7-day delta: open findings created in the last 7 days vs the prior
    # 7-day window. Negative means we're trending down (good).
    last7 = db.query_one(
        f"SELECT COUNT(*) AS n FROM findings WHERE {triage_clause} "
        f"AND created_at > NOW() - INTERVAL 7 DAY")["n"] or 0
    prev7 = db.query_one(
        f"SELECT COUNT(*) AS n FROM findings WHERE {triage_clause} "
        f"AND created_at > NOW() - INTERVAL 14 DAY "
        f"AND created_at <= NOW() - INTERVAL 7 DAY")["n"] or 0
    if prev7 > 0:
        delta_pct = round(100 * (last7 - prev7) / prev7)
    elif last7 > 0:
        delta_pct = 100
    else:
        delta_pct = 0

    validated = db.query_one(
        f"SELECT COUNT(*) AS n FROM findings WHERE validation_status='validated' "
        f"AND {triage_clause}"
    )["n"] or 0
    fp = db.query_one(
        "SELECT COUNT(*) AS n FROM findings WHERE status='false_positive'"
    )["n"] or 0

    targets_total = db.query_one(
        "SELECT COUNT(DISTINCT fqdn) AS n FROM assessments")["n"] or 0
    assessments_total = db.query_one(
        "SELECT COUNT(*) AS n FROM assessments WHERE status='done'")["n"] or 0
    last_row = db.query_one(
        "SELECT MAX(finished_at) AS last_at FROM assessments WHERE status='done'")
    last_at = last_row.get("last_at") if last_row else None

    # Live per-target risk: pull every finding from each target's most
    # recent assessment in one query and run _live_risk_score on the
    # group. This replaces the previous use of a.risk_score (the LLM-
    # written value, frozen at consolidation time and stale the moment
    # the analyst triages). Same demerit math as the assessment page.
    live_per_aid: dict[int, int] = {}
    findings_by_aid: dict[int, list[dict]] = {}
    rows = db.query(
        "SELECT f.assessment_id, f.severity, f.status, f.validation_status "
        "FROM findings f "
        "JOIN (SELECT fqdn, MAX(id) AS mid FROM assessments "
        "      WHERE status='done' GROUP BY fqdn) t "
        "  ON f.assessment_id = t.mid")
    for r in rows:
        findings_by_aid.setdefault(r["assessment_id"], []).append(r)
    for aid, fs in findings_by_aid.items():
        live_per_aid[aid] = _live_risk_score(fs)

    # Overall risk: average across the per-target live scores so one
    # host with 50 scans doesn't dominate the dashboard headline.
    overall_risk = None
    if live_per_aid:
        overall_risk = round(sum(live_per_aid.values()) / len(live_per_aid))

    # Findings-by-day for the selected trend window (7/14/21/30 days),
    # broken down by severity. Info severity is excluded from the chart
    # series (high-volume / low-signal noise that flattens the
    # criticals visually). The other dashboard surfaces still surface
    # info totals.
    days = [(date.today() - timedelta(days=i)).isoformat()
            for i in range(trend_days - 1, -1, -1)]
    sev_chart_order = ("critical", "high", "medium", "low")
    series = {s: [0] * len(days) for s in sev_chart_order}
    day_idx = {d: i for i, d in enumerate(days)}

    # Optional trend filter: restrict the series to findings whose
    # owning assessment matches `trend_filter` on either fqdn or
    # application_id (case-insensitive substring). Resolved server-
    # side to a list of assessment ids so the per-day query stays
    # efficient. `filter_matched` lets the UI distinguish "no filter"
    # from "filter matched zero targets" (useful empty-state).
    trend_filter = (trend_filter or "").strip()
    matched_aids: Optional[list[int]] = None
    filter_matched = True
    if trend_filter:
        like = f"%{trend_filter[:128].lower()}%"
        matched = db.query(
            "SELECT id FROM assessments "
            "WHERE LOWER(fqdn) LIKE %s "
            "   OR LOWER(COALESCE(application_id, '')) LIKE %s",
            (like, like),
        )
        matched_aids = [r["id"] for r in matched]
        filter_matched = bool(matched_aids)

    trend_sql = (
        f"SELECT DATE(created_at) AS d, severity, COUNT(*) AS n "
        f"FROM findings WHERE {triage_clause} "
        f"  AND severity != 'info' "
        f"  AND created_at > NOW() - INTERVAL {int(trend_days)} DAY "
    )
    trend_params: list = []
    if matched_aids is not None:
        # An empty matched_aids means the filter matched no targets;
        # short-circuit by passing an impossible WHERE so the chart
        # renders an empty state rather than the full series.
        if not matched_aids:
            trend_sql += "  AND 1=0 "
        else:
            ph = ",".join(["%s"] * len(matched_aids))
            trend_sql += f"  AND assessment_id IN ({ph}) "
            trend_params.extend(matched_aids)
    trend_sql += "GROUP BY DATE(created_at), severity"
    for r in db.query(trend_sql, trend_params):
        d = r["d"].isoformat() if hasattr(r["d"], "isoformat") else str(r["d"])
        if d in day_idx and r["severity"] in series:
            series[r["severity"]][day_idx[d]] = int(r["n"] or 0)

    # Pre-compute the SVG geometry for the trend chart so the template
    # doesn't have to fight with Jinja's sandbox over list mutation.
    # We render bands from low->critical so critical sits on top
    # visually. Each band's polygon walks the top-edge points left to
    # right then the bottom-edge points right to left.
    chart_w, chart_h, n_pts = 1000.0, 200.0, len(days)
    step = chart_w / max(1, n_pts - 1)
    max_total = 0
    for i in range(n_pts):
        t = sum(series[s][i] for s in sev_chart_order)
        if t > max_total:
            max_total = t

    # "Nice" Y-axis ceiling -- the chart scales to this so the grid
    # labels come out as round numbers (0/15/30/45/60) instead of the
    # awkward fractions you get from dividing the raw max into 4. For
    # max_total=0 we still need a non-zero denominator below.
    def _nice_ceiling(n: int) -> int:
        if n <= 0:
            return 4
        for c in (4, 8, 12, 16, 20, 24, 40, 60, 80, 100, 120, 160,
                  200, 240, 300, 400, 500, 600, 800, 1000, 1200,
                  1600, 2000, 2500, 3000, 4000, 5000, 6000, 8000, 10000):
            if c >= n:
                return c
        # Fall back to next multiple of 1000 for very large counts.
        return ((n + 999) // 1000) * 1000

    nice_max = _nice_ceiling(max_total)
    # Y-axis tick values (one per grid line, top→bottom). Cast to int
    # so the template doesn't have to format floats.
    y_ticks = [int(round(nice_max * g, 0)) for g in (1.0, 0.75, 0.5, 0.25, 0.0)]

    bottoms = [0.0] * n_pts
    bands: list[dict] = []
    if max_total > 0:
        for sev_name in ("low", "medium", "high", "critical"):
            tops = [bottoms[i] + series[sev_name][i] for i in range(n_pts)]
            top_points = [(round(i * step, 2),
                           round(chart_h - (tops[i] / nice_max) * chart_h, 2))
                          for i in range(n_pts)]
            bot_points = [(round(i * step, 2),
                           round(chart_h - (bottoms[i] / nice_max) * chart_h, 2))
                          for i in range(n_pts - 1, -1, -1)]
            poly = " ".join(f"{x},{y}" for x, y in top_points + bot_points)
            bands.append({"sev": sev_name, "points": poly})
            bottoms = tops

    # Datalist for the trend filter typeahead: every distinct fqdn +
    # every distinct non-empty application_id ever seen. Sorted, deduped.
    filter_targets: list[str] = []
    seen: set[str] = set()
    for r in db.query("SELECT DISTINCT fqdn FROM assessments "
                      "WHERE fqdn IS NOT NULL ORDER BY fqdn"):
        v = r["fqdn"]
        if v and v not in seen:
            seen.add(v); filter_targets.append(v)
    for r in db.query("SELECT DISTINCT application_id FROM assessments "
                      "WHERE application_id IS NOT NULL "
                      "  AND application_id != '' ORDER BY application_id"):
        v = r["application_id"]
        if v and v not in seen:
            seen.add(v); filter_targets.append(v)

    # Unresolved findings broken down by age bucket. Triaged rows
    # (false-positive, resolved, archived) are excluded so the matrix
    # matches the actionable list. The `>N` buckets are cumulative
    # (everything older than N days), while the `<30 days` bucket is
    # the complement: findings created within the last 30 days. The
    # fresh-bucket row sits at the top of the table so analysts see
    # incoming work first, then the aging tail.
    sev_order = ("critical", "high", "medium", "low", "info")
    ages = {"<30 days": {s: 0 for s in sev_order},
            ">30 days": {s: 0 for s in sev_order},
            ">60 days": {s: 0 for s in sev_order},
            ">90 days": {s: 0 for s in sev_order}}
    for bucket, bound in (("90 days", 90), ("60 days", 60), ("30 days", 30)):
        rows = db.query(
            f"SELECT severity, COUNT(*) AS n FROM findings "
            f"WHERE {triage_clause} "
            f"  AND created_at < NOW() - INTERVAL %s DAY "
            f"GROUP BY severity",
            (bound,))
        for r in rows:
            ages[f">{bucket}"][r["severity"]] = int(r["n"] or 0)
    # `<30 days` complements the cumulative >N buckets: rows whose
    # created_at falls within the last 30 days. Computed as a separate
    # query rather than (total - >30) so the severity breakdown stays
    # internally consistent (one query → one severity histogram).
    for r in db.query(
            f"SELECT severity, COUNT(*) AS n FROM findings "
            f"WHERE {triage_clause} "
            f"  AND created_at >= NOW() - INTERVAL 30 DAY "
            f"GROUP BY severity"):
        ages["<30 days"][r["severity"]] = int(r["n"] or 0)

    # Resolved findings broken down by age bucket. Counterpart to the
    # `ages` matrix: shows what the team has cleared (status fixed or
    # accepted_risk), bucketed by the original finding's age. Useful
    # for measuring backlog burndown -- "we resolved this many old
    # criticals." Aged on created_at because the schema doesn't track
    # status_changed_at.
    resolved_ages = {"<30 days": {s: 0 for s in sev_order},
                     ">30 days": {s: 0 for s in sev_order},
                     ">60 days": {s: 0 for s in sev_order},
                     ">90 days": {s: 0 for s in sev_order}}
    for bucket, bound in (("90 days", 90), ("60 days", 60), ("30 days", 30)):
        rows = db.query(
            "SELECT severity, COUNT(*) AS n FROM findings "
            "WHERE status IN ('fixed', 'accepted_risk') "
            "  AND created_at < NOW() - INTERVAL %s DAY "
            "GROUP BY severity",
            (bound,))
        for r in rows:
            resolved_ages[f">{bucket}"][r["severity"]] = int(r["n"] or 0)
    # Recent-resolution counterpart to the unresolved <30 days row.
    for r in db.query(
            "SELECT severity, COUNT(*) AS n FROM findings "
            "WHERE status IN ('fixed', 'accepted_risk') "
            "  AND created_at >= NOW() - INTERVAL 30 DAY "
            "GROUP BY severity"):
        resolved_ages["<30 days"][r["severity"]] = int(r["n"] or 0)

    # Assessments table is empty here — the route handler resolves the
    # paginated query separately and merges it in. Keeping the heavy
    # /assessment-list logic out of _dashboard_data avoids re-running
    # the per-finding aggregation for the 25 displayed rows when the
    # user is just toggling the trend window.
    recent: list[dict] = []
    recent_total = 0
    recent_status_options: list[str] = []
    recent_fqdn_suggest: list[str] = []

    return {
        "kpi": {
            "open": open_total,
            "delta_7d": delta_pct,
            "validated": validated,
            "false_positive": fp,
            "targets": targets_total,
            "assessments": assessments_total,
            "last_scan": last_at,
            "risk_score": overall_risk,
            "sev": sev,
        },
        "trend": {"days": days, "series": series,
                  "bands": bands, "max_total": max_total,
                  "nice_max": nice_max, "y_ticks": y_ticks,
                  "w": chart_w, "h": chart_h,
                  "filter": trend_filter,
                  "filter_targets": filter_targets,
                  "filter_matched": filter_matched,
                  "window_days": trend_days,
                  "window_options": [7, 14, 21, 30]},
        "ages": ages,
        "resolved_ages": resolved_ages,
        "recent": recent,
        "recent_total": recent_total,
        "recent_status_options": recent_status_options,
        "recent_fqdn_suggest": recent_fqdn_suggest,
        # Internal pass-through so the route handler's table helper
        # can reuse the per-assessment live risk scores already
        # computed for the KPI strip. Stripped before the dict is
        # rendered; templates do not see this key.
        "_live_per_aid": live_per_aid,
    }


# Whitelist of sortable columns on the dashboard's Assessments table.
# Maps the URL `a_sort` value to a real SQL fragment so the route
# handler never interpolates user input into ORDER BY. The "when"
# alias resolves to COALESCE(finished_at, created_at) so a still-
# running assessment sorts by its start instead of NULL-tail.
_ASSESSMENTS_SORT_COLUMNS: dict[str, str] = {
    "id": "id",
    "fqdn": "fqdn",
    "application_id": "COALESCE(application_id, '')",
    "profile": "profile",
    "status": "status",
    "when": "COALESCE(finished_at, created_at)",
}

# Sort rank for letter grades. A is the best (highest rank); F is the
# worst. Mirrors reports._GRADE_RANK but kept locally so we don't pull
# a non-public name across module boundaries. Any letter outside this
# map (e.g. a future "—" sentinel) sorts below every real grade in
# ascending order via the -1 fallback in _assessments_table_data.
_GRADE_RANK_FOR_SORT: dict[str, int] = {
    "A": 4, "B": 3, "C": 2, "D": 1, "F": 0,
}


# Sortable columns that are computed AFTER the SQL fetch from the
# per-assessment live finding aggregate. Sorting these in SQL would
# require either correlated subqueries or denormalised cache columns;
# instead the table helper switches to a "fetch the entire matched
# set, decorate, sort in Python, then paginate" path when one of
# these keys is requested. Acceptable cost at the install sizes this
# tool sees (hundreds of assessments, not millions).
_ASSESSMENTS_LIVE_SORT_KEYS: set[str] = {"open", "risk", "grade"}


def _assessments_table_data(*, q: str, status: str, size: int, page: int,
                            sort: str, direction: str,
                            live_per_aid: dict) -> dict:
    """Resolve the dashboard's Assessments table from the query string.

    `q` matches against fqdn or application_id (case-insensitive
    substring), `status` filters to a single status enum value, `size`
    and `page` paginate, `sort` and `direction` order. Sortable columns
    are whitelisted in `_ASSESSMENTS_SORT_COLUMNS`; an unknown value
    falls back to id-desc, matching the prior default.

    Returns rows for the current page plus the total row count (for
    pagination), the list of distinct fqdns (for typeahead), and the
    status options the dropdown should expose. live_per_aid is reused
    when present so the table's risk score matches what the KPI strip
    already computed for the same assessment ids.
    """
    if not db.healthy():
        return {"rows": [], "total": 0,
                "status_options": [], "fqdn_suggest": []}

    size = max(1, min(100, int(size or 25)))
    page = max(1, int(page or 1))
    direction_lc = (direction or "").lower()
    is_ascending = direction_lc == "asc"
    direction_sql = "ASC" if is_ascending else "DESC"

    # Sort key resolves into one of three buckets:
    #   * SQL-sortable column → ORDER BY in the main query, paginate
    #     with LIMIT/OFFSET (cheap, works at any scale).
    #   * Live-aggregate column (open / risk / grade) → fetch the
    #     entire matched set, decorate with live counts, sort in
    #     Python, then slice to the page. The matched set is
    #     bounded by the WHERE filter so the cost stays proportional
    #     to what the analyst is actually browsing.
    #   * Unknown value → fall back to id-desc.
    if sort in _ASSESSMENTS_SORT_COLUMNS:
        sort_key = sort
        live_sort = False
    elif sort in _ASSESSMENTS_LIVE_SORT_KEYS:
        sort_key = sort
        live_sort = True
    else:
        sort_key = "id"
        live_sort = False

    where_parts: list[str] = []
    params: list = []
    q = (q or "").strip()
    if q:
        like = f"%{q[:128].lower()}%"
        where_parts.append(
            "(LOWER(fqdn) LIKE %s OR "
            "LOWER(COALESCE(application_id, '')) LIKE %s)")
        params.extend([like, like])
    status = (status or "").strip()
    # Validate status against the enum so a tampered query doesn't
    # produce a malformed query. Empty string means "any status".
    valid_status = {"queued", "running", "consolidating", "done",
                    "error", "cancelled", "deleting"}
    if status and status in valid_status:
        where_parts.append("status = %s")
        params.append(status)
    where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    total_row = db.query_one(
        f"SELECT COUNT(*) AS n FROM assessments {where_sql}", params)
    total = int((total_row or {}).get("n") or 0)
    offset = (page - 1) * size

    if live_sort:
        # Live-aggregate sort: pull every matched assessment, decorate
        # with the live open / risk / grade fields, sort in Python on
        # the chosen key, then slice to the requested page. The
        # decorate-then-sort path also applies to rows the page would
        # not have shown, but at hundreds-of-rows scale this is
        # still under a second; if an install crosses into the
        # tens-of-thousands range the live keys can move to a
        # denormalised cache column without changing the URL contract.
        rows = db.query(
            f"SELECT id, fqdn, application_id, profile, llm_tier, status, "
            f"       total_findings, created_at, finished_at "
            f"FROM assessments {where_sql} ORDER BY id DESC", params)
    else:
        order_sql = f"{_ASSESSMENTS_SORT_COLUMNS[sort_key]} {direction_sql}"
        rows = db.query(
            f"SELECT id, fqdn, application_id, profile, llm_tier, status, "
            f"       total_findings, created_at, finished_at "
            f"FROM assessments {where_sql} "
            f"ORDER BY {order_sql} LIMIT %s OFFSET %s",
            params + [size, offset])

    # Decorate every row we have in hand with the live open-findings
    # count, risk score, and grade dict. Two separate paths share the
    # same decoration code below; on the SQL-sort path we only fetched
    # one page, on the live-sort path we have the whole matched set.
    #
    # The grade comes from reports.compute_overall_grade, the same
    # pipeline the PDF cover uses, so the letter shown next to a row
    # on the dashboard matches the letter on that assessment's PDF.
    # owasp_category and source_tool are pulled here because the
    # grade pipeline needs them (per-category demerit cap and the
    # exploitability tier classifier) -- the older live_risk path
    # could get away with just severity + validation_status.
    if rows:
        import reports as reports_mod
        ids = [r["id"] for r in rows]
        ph = ",".join(["%s"] * len(ids))
        findings_by_aid: dict[int, list[dict]] = {aid: [] for aid in ids}
        for f in db.query(
                f"SELECT assessment_id, severity, status, validation_status, "
                f"       owasp_category, source_tool "
                f"FROM findings WHERE assessment_id IN ({ph})", ids):
            findings_by_aid.setdefault(f["assessment_id"], []).append(f)
        for r in rows:
            fs = findings_by_aid.get(r["id"], [])
            # Filter out triaged-away findings before grading -- the
            # PDF body does the same, so the grade input must match.
            graded_set = [f for f in fs
                          if (f.get("status") or "open")
                              not in EXCLUDED_FROM_SCORE]
            r["open_findings"] = len(graded_set)
            r["risk_score"] = (live_per_aid.get(r["id"])
                               if r["id"] in live_per_aid
                               else _live_risk_score(fs))
            # Skip per-row PQC analysis on the dashboard (too
            # expensive at table scale); PQC bonus only fires on the
            # PDF cover. Everything else in the pipeline runs.
            overall = reports_mod.compute_overall_grade(graded_set,
                                                        scan_ids=None)
            r["grade"] = {
                "letter": overall["grade"],
                "cls": overall["grade"].lower(),
                "rank": _GRADE_RANK_FOR_SORT.get(overall["grade"], -1),
                "score": overall["score"],
            }

    if live_sort and rows:
        # Sort the decorated set on the chosen live column, then
        # slice. Reverse=True for descending; secondary key on id
        # (descending) to make ties order by recency, which matches
        # what the analyst expects when two assessments share a
        # grade or open count.
        if sort_key == "open":
            rows.sort(key=lambda r: (r.get("open_findings") or 0, r["id"]),
                      reverse=not is_ascending)
        elif sort_key == "risk":
            rows.sort(key=lambda r: (r.get("risk_score") or 0, r["id"]),
                      reverse=not is_ascending)
        elif sort_key == "grade":
            # grade.rank: 4 = A (best) ... 0 = F (worst), -1 = no data.
            # Higher rank = better grade. Descending on rank shows
            # the best-rated assessments first; ascending shows the
            # worst.
            rows.sort(
                key=lambda r: ((r.get("grade") or {}).get("rank", -1),
                                r["id"]),
                reverse=not is_ascending)
        rows = rows[offset:offset + size]

    # Distinct fqdns drive the typeahead. Cap at 200 so the page weight
    # stays reasonable on installs with thousands of assessments.
    suggest = [r["fqdn"] for r in db.query(
        "SELECT DISTINCT fqdn FROM assessments "
        "WHERE fqdn IS NOT NULL AND fqdn != '' "
        "ORDER BY fqdn LIMIT 200")]

    # Status options come from the enum order to keep the dropdown
    # stable across DB states (a fresh install has no rows yet but
    # should still expose every status value).
    status_options = ["queued", "running", "consolidating",
                       "done", "error", "cancelled", "deleting"]

    return {"rows": rows, "total": total,
            "status_options": status_options,
            "fqdn_suggest": suggest}


@app.get("/", response_class=HTMLResponse)
def index(request: Request,
          trend: str = "", trend_days: int = 30,
          a_q: str = "", a_status: str = "",
          a_size: int = 25, a_page: int = 1,
          a_sort: str = "id", a_dir: str = "desc"):
    """Dashboard. `trend` and `trend_days` drive the Risk Trending
    chart; `a_*` parameters drive the Assessments table (search,
    status filter, page size, page index, sort column + direction).
    All Assessments query params are namespaced with `a_` so the chart
    typeahead form and the table form can coexist in the same URL."""
    data = _dashboard_data(trend_filter=trend, trend_days=trend_days)
    table = _assessments_table_data(
        q=a_q, status=a_status, size=a_size, page=a_page,
        sort=a_sort, direction=a_dir,
        live_per_aid=data.pop("_live_per_aid", {}))
    data["recent"] = table["rows"]
    data["recent_total"] = table["total"]
    data["recent_status_options"] = table["status_options"]
    data["recent_fqdn_suggest"] = table["fqdn_suggest"]
    # Echo the resolved table-state back so the template can render
    # the active sort indicator, page-size dropdown, and pagination
    # bar without re-deriving anything from request.query_params.
    page_size = max(1, min(100, int(a_size or 25)))
    page = max(1, int(a_page or 1))
    total_pages = max(1, (table["total"] + page_size - 1) // page_size)
    data["recent_state"] = {
        "q": a_q, "status": a_status,
        "size": page_size, "page": min(page, total_pages),
        "sort": (a_sort if a_sort in _ASSESSMENTS_SORT_COLUMNS
                  or a_sort in _ASSESSMENTS_LIVE_SORT_KEYS else "id"),
        "dir": "asc" if (a_dir or "").lower() == "asc" else "desc",
        "total_pages": total_pages,
        "size_options": [25, 50, 100],
    }
    return templates.TemplateResponse("index.html", ctx(request, **data))


# Proxy ------------------------------------------------------------------------

@app.get("/proxy", response_class=HTMLResponse)
def proxy_page(request: Request):
    return templates.TemplateResponse("proxy.html", ctx(request))


@app.post("/proxy/config")
def proxy_config(
    listen_host: str = Form("127.0.0.1"),
    listen_port: int = Form(9443),
    upstream: str = Form(...),
    upstream_host_header: str = Form(""),
    ssl_insecure: Optional[str] = Form(None),
):
    s = load_state()
    s["proxy"].update({
        "listen_host": listen_host or "127.0.0.1",
        "listen_port": int(listen_port),
        "upstream": upstream,
        "upstream_host_header": upstream_host_header,
        "ssl_insecure": ssl_insecure is not None,
    })
    save_state(s)
    if proxy_pid() is not None:
        ok, msg = start_proxy(s["proxy"])  # restart with new config
        s["proxy"]["running"] = ok
        s["proxy"]["last_message"] = msg
        save_state(s)
    return redirect("/proxy")


@app.post("/proxy/start")
def proxy_start():
    s = load_state()
    ok, msg = start_proxy(s["proxy"])
    s["proxy"]["running"] = ok
    s["proxy"]["last_message"] = msg
    save_state(s)
    return redirect("/proxy")


@app.post("/proxy/stop")
def proxy_stop():
    stop_proxy()
    s = load_state()
    s["proxy"]["running"] = False
    s["proxy"]["last_message"] = "stopped"
    save_state(s)
    return redirect("/proxy")


@app.post("/proxy/clear")
def proxy_clear():
    if FLOW_LOG.exists():
        FLOW_LOG.unlink()
    return redirect("/proxy")


@app.get("/proxy/log", response_class=PlainTextResponse)
def proxy_log_view():
    if not PROXY_LOG.exists():
        return ""
    data = PROXY_LOG.read_bytes()[-8000:]
    return data.decode("utf-8", "replace")


# Flows ------------------------------------------------------------------------

@app.get("/flows", response_class=HTMLResponse)
def flows_page(request: Request, limit: int = 200):
    flows = read_flows(limit)
    return templates.TemplateResponse("flows.html",
                                      ctx(request, flows=flows, limit=limit))


@app.get("/flows.json")
def flows_json(limit: int = 200):
    return JSONResponse(read_flows(limit))


@app.get("/flow/{flow_id}", response_class=HTMLResponse)
def flow_detail(request: Request, flow_id: str):
    f = read_flow(flow_id)
    if not f:
        raise HTTPException(404, "flow not found")
    req_path = FLOWS_DIR / f.get("request_file", f"{flow_id}_request.txt")
    resp_path = FLOWS_DIR / f.get("response_file", f"{flow_id}_response.txt")
    request_text = req_path.read_text(errors="replace") if req_path.exists() else "(missing)"
    response_text = resp_path.read_text(errors="replace") if resp_path.exists() else "(missing)"
    # cap rendered size to keep the UI snappy
    cap = 200_000
    if len(request_text) > cap:
        request_text = request_text[:cap] + f"\n\n…[truncated, full file at {req_path}]"
    if len(response_text) > cap:
        response_text = response_text[:cap] + f"\n\n…[truncated, full file at {resp_path}]"
    analyzes = _flow_analyses(flow_id)
    endpoints = db.query("SELECT id, name, backend, model FROM llm_endpoints ORDER BY name") if db.healthy() else []
    return templates.TemplateResponse(
        "flow_detail.html",
        ctx(request, flow=f, request_text=request_text,
            response_text=response_text, analyzes=analyzes,
            llm_endpoints=endpoints),
    )


@app.get("/flow/{flow_id}/request.txt", response_class=PlainTextResponse)
def flow_request_raw(flow_id: str):
    p = FLOWS_DIR / f"{flow_id}_request.txt"
    if not p.exists():
        raise HTTPException(404)
    return p.read_text(errors="replace")


@app.get("/flow/{flow_id}/response.txt", response_class=PlainTextResponse)
def flow_response_raw(flow_id: str):
    p = FLOWS_DIR / f"{flow_id}_response.txt"
    if not p.exists():
        raise HTTPException(404)
    return p.read_text(errors="replace")


# Scans ------------------------------------------------------------------------

@app.get("/scan", response_class=HTMLResponse)
def scan_page(request: Request):
    uas = (db.query("SELECT id, label, user_agent, is_default FROM user_agents "
                    "ORDER BY is_default DESC, label")
           if db.healthy() else [])
    return templates.TemplateResponse(
        "scan.html",
        ctx(request, scans=list_scans(), profiles=auth_mod.list_profiles(),
            user_agents=uas),
    )


def _opt_int(v) -> Optional[int]:
    """Form field coercion. FastAPI's int validator rejects empty strings,
    which is what HTML <select> emits for the '— default —' option."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _opt_float(v) -> Optional[float]:
    """Same shape as _opt_int but for decimal-typed inputs (per-scan
    budget, max_spend). Empty string and unparseable values both yield
    None so the calling form path can apply its default rather than
    crashing on a stray comma."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _system_default_budget_usd() -> float:
    """Read the system-default Enhanced-AI per-scan budget from the
    config k/v table. Falls back to 25.0 if the row is missing — the
    schema seeds 25 on a fresh DB but a heal-failure scenario could
    leave the row absent on an upgraded DB. Returning a sensible
    default keeps the assessment form usable."""
    if not db.healthy():
        return 25.0
    row = db.query_one(
        "SELECT value FROM config WHERE `key`='advanced_ai_budget_default_usd'")
    if row and (row.get("value") or "").strip():
        try:
            return round(float(row["value"]), 2)
        except (TypeError, ValueError):
            pass
    return 25.0


def _resolve_enhanced_ai_budget(submitted: Optional[float],
                                 user: Optional[dict]) -> Optional[float]:
    """Compute the effective per-scan Enhanced-AI budget at submit time.

    Rules:
      1. Hard cap = system default (config row).
      2. If the user has a max_spend_usd set, hard cap drops to that.
      3. Submitted value is clamped to [0, hard_cap]. None / empty
         submission inherits the hard cap.
      4. Non-superadmin users have their submission ignored — they
         always get the hard cap. Submit-time enforcement so a tampered
         form (read-only field defeated by devtools) cannot exceed the
         user's allowance.
    Returns the clamped budget as a float (USD, two decimals). Always
    returns a positive value so the storage column stays non-NULL when
    the assessment is on the advanced tier (the column itself stays
    NULLable to allow non-advanced scans to skip it entirely).
    """
    sysd = _system_default_budget_usd()
    user_cap: Optional[float] = None
    if user and user.get("max_spend_usd") is not None:
        try:
            user_cap = float(user["max_spend_usd"])
        except (TypeError, ValueError):
            user_cap = None
    hard_cap = min(sysd, user_cap) if user_cap is not None else sysd

    is_super = bool(user and user.get("role") == "superadmin")
    if not is_super or submitted is None:
        # Plain admin: ignore whatever the form sent — they get the cap.
        # Superadmin who omitted the field: same default.
        return round(hard_cap, 2)
    return round(max(0.0, min(float(submitted), hard_cap)), 2)


def _resolve_user_agent(uid: Optional[int]) -> Optional[str]:
    if not db.healthy():
        return None
    if uid:
        row = db.query_one("SELECT user_agent FROM user_agents WHERE id=%s", (uid,))
        return row["user_agent"] if row else None
    row = db.query_one("SELECT user_agent FROM user_agents WHERE is_default=1 LIMIT 1")
    return row["user_agent"] if row else None


@app.post("/scan")
def scan_start(tool: str = Form(...), target: str = Form(...),
               extra: str = Form(""), auth_profile: str = Form(""),
               user_agent_id: str = Form("")):
    target = target.strip()
    if tool in ("wapiti",) and not re.match(r"^https?://", target):
        target = f"http://{target}"
    if not target:
        raise HTTPException(400, "target required")
    ua = _resolve_user_agent(_opt_int(user_agent_id))
    sid, _warn = start_scan(tool, target, extra,
                            auth_profile=auth_profile, user_agent=ua)
    return redirect(f"/scan/{sid}")


def _scan_flows(sdir: Path, limit: int = 500) -> list[dict]:
    log = sdir / "flows.jsonl"
    if not log.exists():
        return []
    out = []
    for line in log.read_text(errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return list(reversed(out))


def _primary_report(sdir: Path) -> Optional[str]:
    """Pick the most useful report file to link prominently."""
    rep = sdir / "report"
    if rep.is_dir():
        # wapiti emits both a Mako template (report.html, raw $vars) and a
        # populated dated .html. Prefer the populated one.
        candidates = [p for p in rep.glob("*.html") if "$" not in p.read_text(errors="replace")[:2000]]
        if candidates:
            best = max(candidates, key=lambda p: p.stat().st_size)
            return f"report/{best.name}"
    if (sdir / "report.html").exists():
        return "report.html"
    if (sdir / "report.jsonl").exists():
        return "report.jsonl"
    if (sdir / "report.json").exists():
        return "report.json"
    return None


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_view(request: Request, scan_id: str):
    sdir = SCANS_DIR / scan_id
    if not (sdir / "meta.json").exists():
        raise HTTPException(404)
    meta = json.loads((sdir / "meta.json").read_text())
    if meta.get("status") == "running" and meta.get("pid") and not psutil.pid_exists(meta["pid"]):
        meta["status"] = "finished"
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        (sdir / "meta.json").write_text(json.dumps(meta, indent=2))
    # display-only: redact any credential-bearing flags from the cmd echo
    meta["cmd"] = mask_command(meta.get("cmd") or [])
    output = (sdir / "output.log").read_text(errors="replace") if (sdir / "output.log").exists() else ""
    primary = _primary_report(sdir)
    all_flows = _scan_flows(sdir)
    target_flows = [f for f in all_flows if not f.get("is_oob")]
    oob_flows = [f for f in all_flows if f.get("is_oob")]
    artifacts = []
    HIDE = {"meta.json", "output.log", "flows.jsonl", "flows", "proxy.log"}
    for p in sorted(sdir.iterdir()):
        if p.name in HIDE:
            continue
        artifacts.append({"name": p.name, "size": p.stat().st_size,
                          "is_dir": p.is_dir()})
    return templates.TemplateResponse(
        "scan_detail.html",
        ctx(request, meta=meta, output=output, artifacts=artifacts,
            scan_id=scan_id, primary_report=primary,
            scan_flows=target_flows, oob_flows=oob_flows),
    )


@app.get("/scan/{scan_id}/output", response_class=PlainTextResponse)
def scan_output(scan_id: str):
    p = SCANS_DIR / scan_id / "output.log"
    if not p.exists():
        raise HTTPException(404)
    return p.read_text(errors="replace")


_INLINE_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm":  "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".jsonl": "application/json; charset=utf-8",
    ".txt":  "text/plain; charset=utf-8",
    ".log":  "text/plain; charset=utf-8",
    ".xml":  "application/xml; charset=utf-8",
    ".svg":  "image/svg+xml",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".ico":  "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf":  "font/ttf",
    ".pdf":  "application/pdf",
}


@app.get("/scan/{scan_id}/file/{name:path}")
def scan_file(scan_id: str, name: str):
    base_dir = (SCANS_DIR / scan_id).resolve()
    target = (base_dir / name).resolve()
    if not str(target).startswith(str(base_dir)) or not target.exists():
        raise HTTPException(404)
    if target.is_dir():
        rel = name.rstrip("/")
        parent_link = ""
        if rel:
            parent = "/".join(rel.split("/")[:-1])
            parent_url = f"{ROOT_PATH}/scan/{scan_id}/file" + (f"/{parent}" if parent else "")
            parent_link = f'<p><a href="{parent_url}">../</a></p>'
        rows = []
        for p in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            entry = (rel + "/" + p.name) if rel else p.name
            label = p.name + ("/" if p.is_dir() else "")
            size = "" if p.is_dir() else f' <span style="color:#8a96a3">({p.stat().st_size} B)</span>'
            rows.append(
                f'<li><a href="{ROOT_PATH}/scan/{scan_id}/file/{entry}">{label}</a>{size}</li>'
            )
        body = (
            f'<!doctype html><meta charset="utf-8"><title>{name or "/"}</title>'
            f'<style>body{{font-family:ui-monospace,Menlo,monospace;background:#0f1419;color:#d8dee5;padding:1.5em}}'
            f'a{{color:#5fb3d7;text-decoration:none}}a:hover{{text-decoration:underline}}</style>'
            f'<h3>{name or "/"}</h3>{parent_link}<ul>{"".join(rows)}</ul>'
        )
        return HTMLResponse(body)
    ctype = _INLINE_TYPES.get(target.suffix.lower(), "application/octet-stream")
    return FileResponse(str(target), media_type=ctype)


@app.post("/scan/{scan_id}/kill")
def scan_kill(scan_id: str):
    kill_scan(scan_id)
    return redirect(f"/scan/{scan_id}")


@app.post("/scans/delete")
async def scans_delete(request: Request):
    """Bulk-delete one or more scan dirs. Each scan_id is independently
    validated by the cleanup module's strict regex + path-resolve guard,
    so a malformed value can't traverse out of /data/scans."""
    form = await request.form()
    scan_ids = [s for s in form.getlist("scan_ids") if s]
    if not scan_ids:
        return redirect("/scan?msg=nothing+selected")

    removed = 0
    failed: list[str] = []
    for sid in scan_ids:
        result = cleanup_mod.delete_scan(sid)
        if result.get("ok") and result.get("removed"):
            removed += 1
            # Detach this scan_id from any owning assessment so the
            # detail page doesn't list a dangling reference.
            for row in db.query(
                "SELECT id, scan_ids FROM assessments WHERE scan_ids LIKE %s",
                (f"%{sid}%",)):
                ids = [s for s in (row["scan_ids"] or "").split(",")
                       if s and s != sid]
                db.execute(
                    "UPDATE assessments SET scan_ids = %s WHERE id = %s",
                    (",".join(ids), row["id"]))
        else:
            failed.append(sid)

    msg = f"deleted+{removed}"
    if failed:
        msg += f"+failed:{len(failed)}"
    return redirect(f"/scan?msg={msg}")


# Auth profiles ---------------------------------------------------------------

@app.get("/auth", response_class=HTMLResponse)
def auth_page(request: Request, msg: str = ""):
    return templates.TemplateResponse(
        "auth.html",
        ctx(request, profiles=auth_mod.list_profiles(), msg=msg),
    )


@app.post("/auth/profile")
def auth_save(
    name: str = Form(...),
    type: str = Form(...),
    host_filter: str = Form(""),
    # basic
    basic_username: str = Form(""),
    basic_password: str = Form(""),
    # form
    form_login_url: str = Form(""),
    form_username: str = Form(""),
    form_password: str = Form(""),
    # bearer
    bearer_token: str = Form(""),
    # cookies (paste raw "Cookie: a=1; b=2" or "a=1; b=2")
    cookies_raw: str = Form(""),
):
    name = name.strip()
    if not name:
        raise HTTPException(400, "name required")
    p: dict = {"name": name, "type": type, "host_filter": host_filter.strip()}
    if type == "basic":
        p["basic"] = {"username": basic_username, "password": basic_password}
    elif type == "form":
        p["form_login"] = {
            "login_url": form_login_url,
            "username": form_username,
            "password": form_password,
        }
    elif type == "bearer":
        p["bearer"] = {"token": bearer_token}
    elif type == "cookies":
        cookies = []
        raw = cookies_raw.strip()
        if raw.lower().startswith("cookie:"):
            raw = raw.split(":", 1)[1].strip()
        for piece in raw.split(";"):
            piece = piece.strip()
            if not piece:
                continue
            n, _, v = piece.partition("=")
            if n:
                cookies.append({
                    "name": n.strip(), "value": v.strip(),
                    "path": "/", "domain": host_filter,
                    "secure": False, "httponly": False,
                })
        p["cookies"] = cookies
        p["headers"] = {}
    else:
        raise HTTPException(400, f"unknown type {type}")
    auth_mod.save_profile(p)
    return redirect(f"/auth?msg=saved+{name}")


@app.post("/auth/profile/{name}/delete")
def auth_delete(name: str):
    auth_mod.delete_profile(name)
    return redirect(f"/auth?msg=deleted+{name}")


@app.post("/auth/capture")
def auth_capture(flow_id: str = Form(...), name: str = Form(...),
                 host_filter: str = Form("")):
    try:
        auth_mod.capture_from_flow(flow_id, name.strip(), host_filter.strip())
    except FileNotFoundError:
        raise HTTPException(404, "flow files not found")
    return redirect(f"/auth?msg=captured+{name}")


# LLM endpoints + analysis ----------------------------------------------------

@app.get("/llm", response_class=HTMLResponse)
def llm_page(request: Request, msg: str = ""):
    endpoints = []
    if db.healthy():
        endpoints = db.query("SELECT * FROM llm_endpoints ORDER BY name")
    return templates.TemplateResponse(
        "llm.html",
        ctx(request, endpoints=endpoints, msg=msg, db_ok=db.healthy(),
            ai_budget_system_default=_system_default_budget_usd()),
    )


@app.post("/llm/budget_default")
def llm_budget_default_save(request: Request,
                              advanced_ai_budget_default_usd: str = Form(""),
                              csrf_token: str = Form("")):
    """Superadmin-only. Updates the system-wide default per-scan
    Enhanced-AI budget (the value pre-filled into the assess form when
    the user has no per-user max_spend cap)."""
    require_superadmin(request)
    check_csrf(request, csrf_token)
    raw = (advanced_ai_budget_default_usd or "").strip()
    try:
        val = round(float(raw), 2)
    except ValueError:
        return redirect("/llm?msg=budget+must+be+a+number")
    if val < 0:
        return redirect("/llm?msg=budget+cannot+be+negative")
    db.execute(
        "INSERT INTO config (`key`, value) VALUES "
        "('advanced_ai_budget_default_usd', %s) "
        "ON DUPLICATE KEY UPDATE value=VALUES(value)",
        (str(val),))
    audit_mod.log_event(
        "system_budget_changed",
        actor=audit_mod.actor_from_user(current_user(request)),
        ip=client_ip(request),
        extra={"new_default_usd": val},
    )
    return redirect("/llm?msg=system+default+budget+updated")


@app.post("/llm/endpoint")
def llm_endpoint_save(
    name: str = Form(...),
    backend: str = Form(...),
    base_url: str = Form(""),
    api_key: str = Form(""),
    model: str = Form(...),
    extra_headers: str = Form(""),
    is_default: Optional[str] = Form(None),
):
    if backend not in ("anthropic", "openai_compat"):
        raise HTTPException(400, f"invalid backend {backend!r}")
    if backend == "openai_compat" and not base_url.strip():
        raise HTTPException(400, "openai_compat needs base_url")
    is_def = 1 if is_default else 0
    if is_def:
        db.execute("UPDATE llm_endpoints SET is_default = 0")
    db.execute(
        "INSERT INTO llm_endpoints "
        "(name, backend, base_url, api_key, model, is_default, extra_headers) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) "
        "ON DUPLICATE KEY UPDATE backend=VALUES(backend), base_url=VALUES(base_url), "
        "api_key=VALUES(api_key), model=VALUES(model), is_default=VALUES(is_default), "
        "extra_headers=VALUES(extra_headers)",
        (name.strip(), backend, base_url.strip(), api_key.strip(),
         model.strip(), is_def, extra_headers.strip()),
    )
    return redirect(f"/llm?msg=saved+{name}")


@app.post("/llm/endpoint/{eid}/delete")
def llm_endpoint_delete(eid: int):
    db.execute("DELETE FROM llm_endpoints WHERE id = %s", (eid,))
    return redirect("/llm?msg=deleted")


# ---- AI Prompts admin (Enhanced-AI-Testing scenarios) ----------------------
# Superadmin-only CRUD for the ai_prompts table. Plain admins / readonly
# users hit a 403 from require_superadmin in every handler. The templates
# also condition on is_superadmin so the link doesn't render below that
# tier — the require_superadmin call is the actual security gate.

@app.get("/admin/ai-prompts", response_class=HTMLResponse)
def admin_ai_prompts_page(request: Request, msg: str = ""):
    require_superadmin(request)
    rows = db.query(
        "SELECT id, slot, name, description, category, fire_when, "
        "sort_order, batch_size, is_active, is_seeded, version, "
        "updated_at FROM ai_prompts ORDER BY slot, sort_order, id")
    # Group by slot for the page so the operator sees scenarios listed
    # under their slot heading.
    grouped: dict[str, list[dict]] = {}
    for r in rows:
        grouped.setdefault(r["slot"], []).append(r)
    return templates.TemplateResponse(
        "admin/ai_prompts.html",
        ctx(request, grouped=grouped, msg=msg))


@app.get("/admin/ai-prompts/new", response_class=HTMLResponse)
def admin_ai_prompts_new(request: Request, slot: str = "",
                          msg: str = ""):
    """Render the editor for a brand-new prompt. The form posts to
    /admin/ai-prompts on submit. We pre-fill slot from the query string
    (the listing page links here as ?slot=advanced_ai_testing.weakness_discovery)
    so the editor knows which placeholder set to surface."""
    require_superadmin(request)
    import enhanced_ai_prompts as eap
    placeholders = sorted(eap.PLACEHOLDERS_BY_SLOT.get(
        slot, eap.PLACEHOLDERS_BY_SLOT[eap.SLOT_WEAKNESS]))
    row = {
        "id": None, "slot": slot or eap.SLOT_WEAKNESS,
        "name": "", "description": "",
        "system_prompt": eap.HEADER + "\n\n[Persona + analytical task here]\n"
                         + eap.FOOTER_TEMPLATE.format(category="custom"),
        "user_template": "TARGET\n======\n{fqdn}\n\n[Data placeholders here]\n",
        "category": "", "fire_when": "", "sort_order": 999,
        "batch_size": None, "is_active": 1, "is_seeded": 0, "version": 0,
    }
    return templates.TemplateResponse(
        "admin/ai_prompt_edit.html",
        ctx(request, row=row, placeholders=placeholders,
            slot_options=sorted(eap.PLACEHOLDERS_BY_SLOT.keys()),
            msg=msg, is_new=True))


@app.get("/admin/ai-prompts/{pid}", response_class=HTMLResponse)
def admin_ai_prompts_edit(request: Request, pid: int, msg: str = ""):
    require_superadmin(request)
    import enhanced_ai_prompts as eap
    row = db.query_one("SELECT * FROM ai_prompts WHERE id=%s", (pid,))
    if not row:
        raise HTTPException(404)
    placeholders = sorted(eap.PLACEHOLDERS_BY_SLOT.get(
        row["slot"], eap.PLACEHOLDERS_BY_SLOT[eap.SLOT_WEAKNESS]))
    return templates.TemplateResponse(
        "admin/ai_prompt_edit.html",
        ctx(request, row=row, placeholders=placeholders,
            slot_options=sorted(eap.PLACEHOLDERS_BY_SLOT.keys()),
            msg=msg, is_new=False))


@app.post("/admin/ai-prompts")
def admin_ai_prompts_create(request: Request,
                              slot: str = Form(...),
                              name: str = Form(...),
                              description: str = Form(""),
                              system_prompt: str = Form(...),
                              user_template: str = Form(...),
                              category: str = Form(""),
                              fire_when: str = Form(""),
                              sort_order: str = Form("999"),
                              batch_size: str = Form(""),
                              is_active: Optional[str] = Form(None),
                              csrf_token: str = Form("")):
    require_superadmin(request)
    check_csrf(request, csrf_token)
    name = name.strip()
    if not name:
        raise HTTPException(400, "name required")
    sort_i = _opt_int(sort_order) or 999
    batch_i = _opt_int(batch_size)
    pid = db.execute(
        """INSERT INTO ai_prompts
              (slot, name, description, system_prompt, user_template,
               category, fire_when, sort_order, batch_size,
               is_active, is_seeded, version,
               created_by_user_id, updated_by_user_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, 1, %s, %s)""",
        (slot, name, description, system_prompt, user_template,
         category.strip() or None, fire_when.strip(),
         sort_i, batch_i,
         1 if is_active else 0,
         (current_user(request) or {}).get("id"),
         (current_user(request) or {}).get("id")))
    audit_mod.log_event(
        "ai_prompt_created",
        actor=audit_mod.actor_from_user(current_user(request)),
        target={"id": pid, "slot": slot, "name": name},
        ip=client_ip(request))
    return redirect(f"/admin/ai-prompts?msg=created+{name.replace(' ', '+')}")


@app.post("/admin/ai-prompts/{pid}")
def admin_ai_prompts_save(request: Request, pid: int,
                            name: str = Form(...),
                            description: str = Form(""),
                            system_prompt: str = Form(...),
                            user_template: str = Form(...),
                            category: str = Form(""),
                            fire_when: str = Form(""),
                            sort_order: str = Form("999"),
                            batch_size: str = Form(""),
                            is_active: Optional[str] = Form(None),
                            csrf_token: str = Form("")):
    require_superadmin(request)
    check_csrf(request, csrf_token)
    existing = db.query_one("SELECT id, slot, name FROM ai_prompts WHERE id=%s",
                              (pid,))
    if not existing:
        raise HTTPException(404)
    sort_i = _opt_int(sort_order) or 999
    batch_i = _opt_int(batch_size)
    db.execute(
        """UPDATE ai_prompts
              SET name=%s, description=%s, system_prompt=%s,
                  user_template=%s, category=%s, fire_when=%s,
                  sort_order=%s, batch_size=%s, is_active=%s,
                  version=version+1, updated_by_user_id=%s
            WHERE id=%s""",
        (name.strip(), description, system_prompt, user_template,
         category.strip() or None, fire_when.strip(),
         sort_i, batch_i,
         1 if is_active else 0,
         (current_user(request) or {}).get("id"),
         pid))
    audit_mod.log_event(
        "ai_prompt_edited",
        actor=audit_mod.actor_from_user(current_user(request)),
        target={"id": pid, "slot": existing["slot"], "name": existing["name"]},
        ip=client_ip(request))
    return redirect("/admin/ai-prompts?msg=saved")


@app.post("/admin/ai-prompts/{pid}/restore")
def admin_ai_prompts_restore(request: Request, pid: int,
                              csrf_token: str = Form("")):
    """Reset a single seeded prompt back to its in-code default. The
    caller must own a superadmin session — the restore action rewrites
    the system_prompt body, so a tenant-wide weakening of safety rules
    by a compromised admin is denied here."""
    require_superadmin(request)
    check_csrf(request, csrf_token)
    import enhanced_ai_prompts as eap
    row = db.query_one("SELECT id, slot, name FROM ai_prompts WHERE id=%s",
                        (pid,))
    if not row:
        raise HTTPException(404)
    result = eap.restore_defaults(
        db, only_slot=row["slot"], only_name=row["name"],
        updated_by_user_id=(current_user(request) or {}).get("id"))
    audit_mod.log_event(
        "ai_prompt_restored",
        actor=audit_mod.actor_from_user(current_user(request)),
        target={"id": pid, "slot": row["slot"], "name": row["name"]},
        ip=client_ip(request),
        extra=result)
    return redirect("/admin/ai-prompts?msg=restored+to+default")


@app.post("/admin/ai-prompts/{pid}/delete")
def admin_ai_prompts_delete(request: Request, pid: int,
                              csrf_token: str = Form("")):
    require_superadmin(request)
    check_csrf(request, csrf_token)
    row = db.query_one("SELECT id, slot, name FROM ai_prompts WHERE id=%s",
                        (pid,))
    if not row:
        raise HTTPException(404)
    db.execute("DELETE FROM ai_prompts WHERE id=%s", (pid,))
    audit_mod.log_event(
        "ai_prompt_deleted",
        actor=audit_mod.actor_from_user(current_user(request)),
        target={"id": pid, "slot": row["slot"], "name": row["name"]},
        ip=client_ip(request))
    return redirect("/admin/ai-prompts?msg=deleted")


# ---- LLM Debug Log per assessment ------------------------------------------

@app.get("/assessment/{aid}/llm-debug", response_class=HTMLResponse)
def assessment_llm_debug(request: Request, aid: int):
    """View every LLM call captured for this assessment.

    Superadmin-only because the captured prompts can include cookies,
    bearer tokens, and other live secrets the scanner observed. Showing
    the page to an admin tier would broaden the credential blast radius
    for very little operational value (admins can already see the
    finding-level outputs through the regular assessment page)."""
    require_superadmin(request)
    a = db.query_one(
        "SELECT id, fqdn, llm_debug, llm_tier, status FROM assessments "
        "WHERE id=%s", (aid,))
    if not a:
        raise HTTPException(404)
    rows = db.query(
        "SELECT id, target_type, target_id, endpoint_name, model, status, "
        "request_tokens, response_tokens, "
        "request_prompt, raw_response, error_text, "
        "created_at, finished_at "
        "FROM llm_analyses WHERE assessment_id=%s "
        "ORDER BY created_at, id", (aid,))
    return templates.TemplateResponse(
        "llm_debug_log.html",
        ctx(request, assessment=a, rows=rows))


def _resolve_endpoint(endpoint_id: Optional[int]) -> Optional[dict]:
    if endpoint_id:
        return db.query_one("SELECT * FROM llm_endpoints WHERE id = %s", (endpoint_id,))
    row = db.query_one("SELECT * FROM llm_endpoints WHERE is_default = 1 LIMIT 1")
    if row:
        return row
    return db.query_one("SELECT * FROM llm_endpoints ORDER BY id LIMIT 1")


@app.post("/flow/{flow_id}/analyze")
def flow_analyze(flow_id: str, endpoint_id: str = Form("")):
    flow = read_flow(flow_id)
    if not flow:
        raise HTTPException(404, "flow not found")
    endpoint = _resolve_endpoint(_opt_int(endpoint_id))
    if not endpoint:
        raise HTTPException(400, "no LLM endpoints configured — add one on /llm")

    req_path = FLOWS_DIR / flow.get("request_file", f"{flow_id}_request.txt")
    resp_path = FLOWS_DIR / flow.get("response_file", f"{flow_id}_response.txt")
    request_text = req_path.read_text(errors="replace") if req_path.exists() else ""
    response_text = resp_path.read_text(errors="replace") if resp_path.exists() else ""

    analysis_id = db.execute(
        "INSERT INTO llm_analyses "
        "(target_type, target_id, endpoint_id, endpoint_name, model, status) "
        "VALUES ('flow', %s, %s, %s, %s, 'running')",
        (flow_id, endpoint["id"], endpoint["name"], endpoint["model"]),
    )

    result = llm_mod.analyze(endpoint, request_text, response_text,
                             flow.get("findings"))

    if result.get("ok"):
        db.execute(
            "UPDATE llm_analyses SET status='done', request_tokens=%s, "
            "response_tokens=%s, raw_response=%s, findings_json=%s, "
            "finished_at=NOW() WHERE id=%s",
            (result.get("in_tokens"), result.get("out_tokens"),
             result.get("raw"),
             json.dumps(result.get("findings")) if result.get("findings") is not None else None,
             analysis_id),
        )
    else:
        db.execute(
            "UPDATE llm_analyses SET status='error', raw_response=%s, "
            "error_text=%s, finished_at=NOW() WHERE id=%s",
            (result.get("raw"), result.get("error"), analysis_id),
        )
    return redirect(f"/flow/{flow_id}#analysis-{analysis_id}")


# From-flow scans -------------------------------------------------------------

@app.post("/flow/{flow_id}/scan")
def flow_scan(flow_id: str, tool: str = Form(...), extra: str = Form("")):
    """Launch sqlmap / dalfox / nuclei / etc. against the URL of a captured flow.

    For sqlmap and dalfox we propagate the cookie header from the captured
    request so the scan inherits the session.
    """
    if tool not in ("sqlmap", "dalfox", "nuclei", "wapiti", "nikto", "testssl"):
        raise HTTPException(400, f"unsupported tool: {tool}")
    flow = read_flow(flow_id)
    if not flow:
        raise HTTPException(404, "flow not found")
    target = flow["url"]
    extra_args = []
    # carry session cookie from the captured request, when present
    req_path = FLOWS_DIR / flow.get("request_file", f"{flow_id}_request.txt")
    cookie_header = ""
    if req_path.exists():
        head = req_path.read_text(errors="replace").split("\r\n\r\n", 1)[0]
        for line in head.splitlines():
            if line.lower().startswith("cookie:"):
                cookie_header = line.split(":", 1)[1].strip()
                break
    if cookie_header:
        if tool == "sqlmap":
            extra_args += ["--cookie", cookie_header]
        elif tool == "dalfox":
            extra_args += ["--cookie", cookie_header]
        elif tool == "nuclei":
            extra_args += ["-H", f"Cookie: {cookie_header}"]
    combined_extra = " ".join(shlex.quote(a) for a in extra_args)
    if extra:
        combined_extra = (combined_extra + " " + extra).strip()
    sid, _ = start_scan(tool, target, combined_extra)
    return redirect(f"/scan/{sid}")


def _flow_analyses(flow_id: str) -> list[dict]:
    if not db.healthy():
        return []
    rows = db.query(
        "SELECT id, endpoint_name, model, status, request_tokens, response_tokens, "
        "findings_json, error_text, created_at, finished_at "
        "FROM llm_analyses WHERE target_type='flow' AND target_id=%s "
        "ORDER BY id DESC", (flow_id,))
    for r in rows:
        try:
            r["findings"] = json.loads(r["findings_json"]) if r.get("findings_json") else None
        except Exception:
            r["findings"] = None
    return rows


# Assessments (orchestrated multi-tool scans) --------------------------------

@app.get("/assess", response_class=HTMLResponse)
def assess_page(request: Request):
    endpoints = (db.query("SELECT id, name, model FROM llm_endpoints ORDER BY name")
                 if db.healthy() else [])
    uas = (db.query("SELECT id, label, user_agent, is_default FROM user_agents "
                    "ORDER BY is_default DESC, label")
           if db.healthy() else [])
    recent = (db.query("SELECT id, fqdn, profile, status, total_findings, "
                       "created_at FROM assessments ORDER BY id DESC LIMIT 20")
              if db.healthy() else [])
    # Re-scan prefill. The "Re-scan" button on assessment_detail.html
    # links here with ?from=<aid>; we look up that row and hand the
    # template a `prefill` dict so every input arrives populated.
    #
    # The password value is NEVER echoed into the rendered HTML --
    # screenshots and DOM dumps would otherwise leak it. Instead the
    # template shows a fixed "**************" placeholder if a
    # password is on file, plus a hidden `prefill_creds_from=<aid>`
    # token. On POST, when the password field is left as the all-
    # asterisks sentinel (or empty), the server resolves the stored
    # password from the source assessment via that token. Typing a
    # new password in the field overrides the stored one; clearing
    # the field entirely produces an anonymous re-scan.
    prefill: dict = {}
    src_id = _opt_int(request.query_params.get("from"))
    if src_id and db.healthy():
        src = db.query_one(
            "SELECT fqdn, application_id, scan_http, scan_https, profile, "
            "llm_tier, llm_endpoint_id, user_agent_id, creds_username, "
            "login_url, keep_only_latest, creds_password "
            "FROM assessments WHERE id = %s", (src_id,))
        if src:
            prefill = dict(src)
            prefill["from_id"] = src_id
            # Boolean only -- the actual value never reaches the
            # template (and thus never reaches the rendered DOM).
            prefill["creds_password_stored"] = bool(src.get("creds_password"))
            prefill.pop("creds_password", None)
    # Resolve the current user's effective Enhanced-AI budget cap so the
    # per-scan field can pre-fill min(system_default, user.max_spend_usd).
    # Re-scan paths take precedence: if the source assessment had a
    # specific budget, use that, but still server-side-clamped to the
    # user's cap on submit.
    user = current_user(request) or {}
    sysd = _system_default_budget_usd()
    user_cap_raw = user.get("max_spend_usd")
    try:
        user_cap = (float(user_cap_raw)
                    if user_cap_raw is not None else None)
    except (TypeError, ValueError):
        user_cap = None
    effective_cap = (min(sysd, user_cap) if user_cap is not None else sysd)
    return templates.TemplateResponse(
        "assess.html",
        ctx(request, endpoints=endpoints, user_agents=uas, recent=recent,
            prefill=prefill,
            ai_budget_default=effective_cap,
            ai_budget_system_default=sysd,
            ai_budget_user_cap=user_cap),
    )


@app.post("/assess")
def assess_start(
    request: Request,
    fqdn: str = Form(...),
    profile: str = Form("standard"),
    llm_tier: str = Form("none"),
    llm_endpoint_id: str = Form(""),
    user_agent_id: str = Form(""),
    scan_http: Optional[str] = Form(None),
    scan_https: Optional[str] = Form(None),
    creds_username: str = Form(""),
    creds_password: str = Form(""),
    login_url: str = Form(""),
    application_id: str = Form(""),
    keep_only_latest: Optional[str] = Form(None),
    # Enhanced-AI controls — only meaningful on llm_tier='advanced'.
    # llm_debug enables the prompt+response capture used by the View
    # LLM Debug Log page. enhanced_ai_budget_usd is the per-scan spend
    # cap (USD); _resolve_enhanced_ai_budget clamps it to the lesser of
    # system default and the user's max_spend_usd, and ignores
    # whatever a non-superadmin submitted.
    llm_debug: Optional[str] = Form(None),
    enhanced_ai_budget_usd: str = Form(""),
    # Re-scan flow. When the form was reached via "Re-scan" on an
    # assessment detail page, this hidden field carries the source
    # assessment id. If the visible password field is left as the
    # all-asterisks sentinel (the placeholder rendered by the
    # template when a stored password exists), we resolve the real
    # password from this assessment server-side -- the actual value
    # never appeared in the DOM. Empty string = greenfield path,
    # ignored.
    prefill_creds_from: str = Form(""),
    # Optional schedule-mode fields. When `schedule_mode` is "schedule"
    # we route the request to the scheduling code path instead of starting
    # an immediate scan. Kept on the same endpoint so the form can submit
    # to one URL and the server picks the right action.
    schedule_mode: str = Form("now"),
    schedule_name: str = Form(""),
    cron_expr: str = Form(""),
    start_after: str = Form(""),
    end_before: str = Form(""),
    skip_if_running: Optional[str] = Form(None),
):
    # Resolve the stored password from the source Re-scan assessment
    # when the visible field still holds the all-asterisks sentinel.
    # We require both: (a) the sentinel is intact (user did not type
    # anything), AND (b) the source assessment's FQDN matches what
    # the form is now scanning. The FQDN guard means a hijacked
    # `prefill_creds_from` cannot pull a password from an unrelated
    # customer's prior scan -- the user has to actually be re-
    # scanning the same target.
    if (creds_password and creds_password.strip("*") == ""
            and prefill_creds_from):
        src_id = _opt_int(prefill_creds_from)
        if src_id and db.healthy():
            src = db.query_one(
                "SELECT fqdn, creds_password FROM assessments "
                "WHERE id = %s", (src_id,))
            normalized_fqdn = re.sub(r"^https?://", "",
                                     fqdn.strip().lower()).split("/", 1)[0]
            if (src and src.get("creds_password")
                    and (src.get("fqdn") or "").lower() == normalized_fqdn):
                creds_password = src["creds_password"]
            else:
                # No match -- clear the sentinel so we do NOT pass a
                # literal "**********" through to the orchestrator.
                creds_password = ""
    elif creds_password and creds_password.strip("*") == "":
        # Sentinel without a token (e.g. typed by the user in the
        # greenfield form). Treat as empty rather than scanning with
        # a literal asterisk password.
        creds_password = ""
    llm_endpoint_id_i = _opt_int(llm_endpoint_id)
    user_agent_id_i = _opt_int(user_agent_id)
    fqdn = fqdn.strip().lower()
    fqdn = re.sub(r"^https?://", "", fqdn).split("/", 1)[0]
    if not fqdn:
        raise HTTPException(400, "fqdn required")
    if profile not in ("quick", "standard", "thorough", "premium"):
        raise HTTPException(400, "invalid profile")
    if llm_tier not in ("none", "basic", "advanced"):
        raise HTTPException(400, "invalid llm_tier")
    # Trim and length-cap the optional caller-supplied application_id. We
    # don't enforce a format because every customer's CMDB taxonomy is
    # different — they put in whatever string identifies the app on their
    # side. Empty string normalises to NULL so the column index stays clean.
    application_id = (application_id or "").strip()[:128] or None
    keep_flag = 1 if keep_only_latest else 0
    # Resolve the Enhanced-AI flags. Only persisted when the assessment
    # is on the advanced tier; on basic/none tiers we store NULL/0 so
    # nothing in the orchestrator's enhanced_ai branch picks up stray
    # values, and the assessment page doesn't render a debug-log button
    # for a tier that produced no LLM calls.
    submitted_budget = _opt_float(enhanced_ai_budget_usd)
    if llm_tier == "advanced":
        effective_budget = _resolve_enhanced_ai_budget(
            submitted_budget, current_user(request))
        debug_flag = 1 if llm_debug else 0
    else:
        effective_budget = None
        debug_flag = 0

    # Schedule branch: persist a scan_schedules row instead of running now.
    # Validation lives in app/schedules.py; we surface ValueError as a 400
    # so the form can re-render with the message inline.
    if schedule_mode == "schedule":
        try:
            sid = schedules_mod.create({
                "name": schedule_name or fqdn,
                "fqdn": fqdn,
                "scan_http": 1 if scan_http else 0,
                "scan_https": 1 if scan_https else 0,
                "profile": profile,
                "llm_tier": llm_tier,
                "llm_endpoint_id": llm_endpoint_id_i,
                "user_agent_id": user_agent_id_i,
                "creds_username": creds_username or None,
                "creds_password": creds_password or None,
                "login_url": login_url or None,
                "application_id": application_id,
                "cron_expr": cron_expr,
                "start_after": start_after or None,
                "end_before": end_before or None,
                "enabled": 1,
                "skip_if_running": 1 if skip_if_running else 0,
                "keep_only_latest": keep_flag,
                "llm_debug": debug_flag,
                "enhanced_ai_budget_usd": effective_budget,
            })
        except ValueError as e:
            raise HTTPException(400, str(e))
        return redirect(f"/schedule/{sid}")

    aid = db.execute(
        """INSERT INTO assessments
           (fqdn, scan_http, scan_https, profile, llm_tier, llm_endpoint_id,
            user_agent_id, creds_username, creds_password, login_url,
            application_id, keep_only_latest, llm_debug,
            enhanced_ai_budget_usd, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                   'queued')""",
        (fqdn,
         1 if scan_http else 0,
         1 if scan_https else 0,
         profile, llm_tier, llm_endpoint_id_i,
         user_agent_id_i,
         creds_username or None,
         creds_password or None,
         login_url or None,
         application_id,
         keep_flag,
         debug_flag,
         effective_budget),
    )
    # spawn detached orchestrator
    log_path = LOGS_DIR / f"orchestrator_{aid}.log"
    log_fh = open(log_path, "ab", buffering=0)
    subprocess.Popen(
        ["python", "-m", "scripts.orchestrator", str(aid)],
        stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/app",
    )
    return redirect(f"/assessment/{aid}")


@app.get("/assessments", response_class=HTMLResponse)
def assessments_list(request: Request,
                     q: str = "", status: str = "",
                     size: int = 25, page: int = 1,
                     sort: str = "id", dir: str = "desc"):
    """Standalone Assessments listing. Same filter / sort / pagination
    shape as the dashboard's Assessments card; the underlying helper
    is shared so any change to the SQL or sort allowlist applies
    uniformly.

    URL params here are NOT prefixed with `a_` because this page has
    a single form (the dashboard uses `a_*` because it shares the URL
    with the trend chart's form)."""
    table = _assessments_table_data(
        q=q, status=status, size=size, page=page,
        sort=sort, direction=dir,
        live_per_aid={})
    page_size = max(1, min(100, int(size or 25)))
    page_num = max(1, int(page or 1))
    total_pages = max(1, (table["total"] + page_size - 1) // page_size)
    state = {
        "q": q, "status": status,
        "size": page_size, "page": min(page_num, total_pages),
        "sort": (sort if sort in _ASSESSMENTS_SORT_COLUMNS
                  or sort in _ASSESSMENTS_LIVE_SORT_KEYS else "id"),
        "dir": "asc" if (dir or "").lower() == "asc" else "desc",
        "total_pages": total_pages,
        "size_options": [25, 50, 100],
    }
    return templates.TemplateResponse(
        "assessments.html",
        ctx(request,
            assessments=table["rows"],
            assessments_total=table["total"],
            status_options=table["status_options"],
            fqdn_suggest=table["fqdn_suggest"],
            state=state))


# ---------------------------------------------------------------------------
# Scheduled scans
#
# A scan_schedules row is a recipe + cron expression. The lifespan sweeper
# calls schedules_mod.tick() once a minute to materialize due rows into a
# real assessments row. The pages below let an admin list, inspect, edit,
# enable/disable, run-now, or delete schedules.
# ---------------------------------------------------------------------------

@app.get("/schedules", response_class=HTMLResponse)
def schedules_list(request: Request):
    """Admin/operator schedules index. Lists every scan_schedules row with
    its current next_run_at and a summary of the most recent fire."""
    rows = schedules_mod.list_all() if db.healthy() else []
    # Decorate with a 3-fire preview so the user can see at a glance when
    # the schedule will fire next without staring at a cron string.
    for r in rows:
        r["preview"] = schedules_mod.preview_runs(r.get("cron_expr") or "", 3)
    return templates.TemplateResponse(
        "schedules.html", ctx(request, schedules=rows),
    )


@app.get("/schedule/{sid}", response_class=HTMLResponse)
def schedule_detail(request: Request, sid: int):
    sched = schedules_mod.get(sid)
    if not sched:
        raise HTTPException(404, "schedule not found")
    sched["preview"] = schedules_mod.preview_runs(
        sched.get("cron_expr") or "", 5,
    )
    # All assessments materialized from this schedule, newest first.
    runs = db.query(
        "SELECT id, status, total_findings, started_at, finished_at "
        "FROM assessments WHERE schedule_id=%s ORDER BY id DESC LIMIT 100",
        (sid,),
    )
    endpoints = (db.query("SELECT id, name, model FROM llm_endpoints "
                          "ORDER BY id")
                 if db.healthy() else [])
    uas = (db.query("SELECT id, label, is_default FROM user_agents "
                    "ORDER BY label")
           if db.healthy() else [])
    return templates.TemplateResponse(
        "schedule_detail.html",
        ctx(request, schedule=sched, runs=runs,
            endpoints=endpoints, user_agents=uas),
    )


@app.post("/schedule/{sid}/update")
def schedule_update(
    request: Request,
    sid: int,
    name: str = Form(""),
    fqdn: str = Form(""),
    profile: str = Form(""),
    llm_tier: str = Form(""),
    llm_endpoint_id: str = Form(""),
    user_agent_id: str = Form(""),
    scan_http: Optional[str] = Form(None),
    scan_https: Optional[str] = Form(None),
    creds_username: str = Form(""),
    creds_password: str = Form(""),
    login_url: str = Form(""),
    application_id: str = Form(""),
    cron_expr: str = Form(""),
    start_after: str = Form(""),
    end_before: str = Form(""),
    skip_if_running: Optional[str] = Form(None),
    keep_only_latest: Optional[str] = Form(None),
    # Same Enhanced-AI controls as /assess. The schedule update path is
    # the long-lived authority for a recurring scan, so persisting them
    # here means every materialization inherits the right values without
    # touching schedules_mod._materialize beyond the column list.
    llm_debug: Optional[str] = Form(None),
    enhanced_ai_budget_usd: str = Form(""),
):
    """Apply edits from the schedule detail form. Empty strings are
    forwarded to schedules_mod.update which normalizes them to NULL for
    nullable columns; the cron expression is re-validated there."""
    submitted_budget = _opt_float(enhanced_ai_budget_usd)
    if (llm_tier or "") == "advanced":
        effective_budget = _resolve_enhanced_ai_budget(
            submitted_budget, current_user(request))
        debug_flag = 1 if llm_debug else 0
    else:
        effective_budget = None
        debug_flag = 0
    payload = {
        "name": name, "fqdn": fqdn,
        "profile": profile or None, "llm_tier": llm_tier or None,
        "llm_endpoint_id": _opt_int(llm_endpoint_id),
        "user_agent_id": _opt_int(user_agent_id),
        "scan_http": 1 if scan_http else 0,
        "scan_https": 1 if scan_https else 0,
        "creds_username": creds_username,
        "creds_password": creds_password,
        "login_url": login_url,
        "application_id": application_id,
        "cron_expr": cron_expr,
        "start_after": start_after,
        "end_before": end_before,
        "skip_if_running": 1 if skip_if_running else 0,
        "keep_only_latest": 1 if keep_only_latest else 0,
        "llm_debug": debug_flag,
        "enhanced_ai_budget_usd": effective_budget,
    }
    try:
        schedules_mod.update(sid, payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return redirect(f"/schedule/{sid}?msg=saved")


@app.post("/schedule/{sid}/toggle")
def schedule_toggle(sid: int):
    """Flip the `enabled` flag. Wrapped in its own endpoint (rather than
    folding into /update) so the schedules list can offer a one-click
    pause without re-validating the whole row."""
    row = schedules_mod.get(sid)
    if not row:
        raise HTTPException(404, "schedule not found")
    schedules_mod.set_enabled(sid, not int(row.get("enabled") or 0))
    return redirect("/schedules?msg=toggled")


@app.post("/schedule/{sid}/run")
def schedule_run_now(sid: int):
    """Manual one-off fire. Materializes the schedule into an assessment
    without touching next_run_at, so the cron cadence is undisturbed."""
    aid = schedules_mod.spawn_one_off(sid)
    if aid is None:
        raise HTTPException(404, "schedule not found")
    return redirect(f"/assessment/{aid}")


@app.post("/schedule/{sid}/delete")
def schedule_delete(sid: int):
    """Hard delete. Historical assessments produced by this schedule keep
    their schedule_id pointer; the application code tolerates a stale
    reference and renders "(deleted schedule)"."""
    schedules_mod.delete(sid)
    return redirect("/schedules?msg=deleted")


@app.get("/assessment/{aid}", response_class=HTMLResponse)
def assessment_detail(request: Request, aid: int,
                      status: str = "open",
                      sev: str = "",
                      sort: str = "severity",
                      q: str = ""):
    """Per-assessment workspace.

    Query params drive the findings list:
      status = open | closed | all
      sev    = critical | high | medium | low | info | "" (all)
      sort   = severity | newest | tool
      q      = case-insensitive title substring

    The page renders the full findings list (no pagination at this
    scale) plus a header card with the severity rollup and the PDF
    report list. Selection state lives in the URL hash (#finding-<id>)
    and is restored client-side so refresh / share-link works.
    """
    a = db.query_one("SELECT * FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)

    if status not in ("open", "closed", "all"):
        status = "open"
    # `false_positive`, `resolved`, `fixed`, and `accepted_risk` are
    # statuses, not severities, but we expose them in the same dropdown
    # as the severities for one-click access. When any of them is
    # selected we ignore the Open/Closed/All status tab below and show
    # only matching findings — see the visible-list loop further down
    # for the override. `resolved` and `fixed` both map to the DB status
    # 'fixed' and behave identically — `resolved` is kept as a
    # human-friendly alias for the same outcome.
    if sev not in ("", "critical", "high", "medium", "low", "info",
                   "false_positive", "resolved", "fixed",
                   "accepted_risk"):
        sev = ""
    if sort not in ("severity", "newest", "tool"):
        sort = "severity"
    q = (q or "").strip()

    # Pull every finding once. We do server-side sorting + filtering on
    # the dict list so the same data drives the visible list AND the
    # severity-rollup tiles, which always reflect the unfiltered counts.
    rows = db.query(
        "SELECT id, source_tool, source_scan_id, severity, owasp_category, "
        "cwe, cvss, title, description, evidence_url, evidence_method, "
        "remediation, status, validation_status, validation_run_at, "
        "COALESCE(seen_count, 1) AS seen_count, created_at "
        "FROM findings WHERE assessment_id = %s",
        (aid,))

    # Severity rollup — anything the analyst has triaged out is
    # excluded so the KPI strip and the live risk score reflect what's
    # actually open. Three statuses count as "triaged":
    #   false_positive (suppressed by analyst or probe)
    #   fixed          (analyst marked resolved)
    #   accepted_risk  (archived; risk explicitly accepted)
    # Counts of each triage outcome are surfaced separately below the
    # rollup so the analyst can see what's been resolved without it
    # influencing the score.
    sev_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    fp_count = 0
    resolved_count = 0
    archived_count = 0
    counts_by_status = {"open": 0, "closed": 0, "all": 0}
    info_hidden = 0
    filter_info = bool(a.get("filter_info"))
    for f in rows:
        counts_by_status["all"] += 1
        st = f.get("status") or "open"
        if st == "false_positive":   fp_count += 1
        elif st == "fixed":          resolved_count += 1
        elif st == "accepted_risk":  archived_count += 1
        if st in ("open", "confirmed"):
            counts_by_status["open"] += 1
        else:
            counts_by_status["closed"] += 1
        if st in EXCLUDED_FROM_SCORE:
            continue
        if filter_info and f.get("severity") == "info":
            info_hidden += 1
            continue
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Compute the live risk score from the current state of findings.
    # We deliberately don't read a.risk_score (the LLM-written value is
    # frozen at consolidation time and goes stale as the analyst
    # triages). The PDF report uses its own derivation in reports.py;
    # this is the workspace-page equivalent.
    live_risk = _live_risk_score(rows)

    # Apply the visible filters to derive the list shown in the workspace.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    visible: list[dict] = []
    for f in rows:
        st = f.get("status") or "open"

        # "False positives" pseudo-severity — selected from the same
        # dropdown as the severities, but it filters by status instead.
        # Status tabs and the info-hide toggle are intentionally ignored
        # so picking "False positives" reliably surfaces every
        # suppressed row regardless of where the analyst was when they
        # picked it.
        if sev == "false_positive":
            if st != "false_positive":
                continue
            if q and q.lower() not in (f.get("title") or "").lower():
                continue
            visible.append(f)
            continue

        # "Resolved" / "Fixed" pseudo-severity — same shape as False
        # positives, but filters by status='fixed'. Both labels match
        # the same DB state; the dropdown carries both names because
        # the side-panel button reads "Resolve (mark fixed)" and we
        # want either word the analyst remembers to lead them back to
        # those findings. The Open tab and rollup hide them, so the
        # dropdown is the only way to surface them again.
        if sev in ("resolved", "fixed"):
            if st != "fixed":
                continue
            if q and q.lower() not in (f.get("title") or "").lower():
                continue
            visible.append(f)
            continue

        # "Archive (accepted risk)" pseudo-severity — filters by
        # status='accepted_risk'. Same rationale as the false-positive
        # and resolved filters: the Open tab hides accepted-risk rows,
        # so the dropdown is the way back to them.
        if sev == "accepted_risk":
            if st != "accepted_risk":
                continue
            if q and q.lower() not in (f.get("title") or "").lower():
                continue
            visible.append(f)
            continue

        # Hide triaged-out rows from any severity view (whether the
        # analyst picked "All severities" or a specific level like
        # "critical"). FP / fixed / accepted_risk are reachable via the
        # dedicated dropdown options below the severities — keeping
        # them out of the default "everything" view stops the workspace
        # from drowning real findings in already-resolved noise. This
        # exclusion runs BEFORE the Status tabs so it overrides them
        # for severity selections; the four pseudo-status branches
        # above already short-circuited their own paths so picking
        # "False positives" still surfaces them as expected.
        if sev in ("", "critical", "high", "medium", "low", "info") \
                and st in ("false_positive", "fixed", "accepted_risk"):
            continue

        # Status tabs
        if status == "open" and st not in ("open", "confirmed"):
            continue
        if status == "closed" and st in ("open", "confirmed"):
            continue
        if sev and f.get("severity") != sev:
            continue
        # The persistent "hide info-severity findings" toggle on the
        # assessment row hides info rows from the workspace AND the PDF.
        # The dropdown filter (sev=) lets the analyst still see info
        # rows on demand — explicit filter beats the toggle.
        if filter_info and not sev and f.get("severity") == "info":
            continue
        if q and q.lower() not in (f.get("title") or "").lower():
            continue
        visible.append(f)

    if sort == "newest":
        visible.sort(key=lambda f: (f.get("created_at") or 0), reverse=True)
    elif sort == "tool":
        visible.sort(key=lambda f: (f.get("source_tool") or "",
                                     sev_rank.get(f.get("severity"), 9),
                                     f.get("id") or 0))
    else:
        visible.sort(key=lambda f: (sev_rank.get(f.get("severity"), 9),
                                     -(f.get("id") or 0)))

    scan_ids = (a.get("scan_ids") or "").split(",") if a.get("scan_ids") else []
    scan_ids = [s for s in scan_ids if s]
    reports = reports_mod.list_reports(aid)

    # The detail + aside columns render the FIRST visible finding so the
    # workspace is never blank on first paint. Subsequent clicks swap
    # the panels in via fetch (no page reload).
    initial = visible[0] if visible else None
    detail_ctx = _finding_panel_context(initial)

    return templates.TemplateResponse(
        "assessment_detail.html",
        ctx(request, a=a, findings=visible, sev_counts=sev_counts,
            fp_count=fp_count, resolved_count=resolved_count,
            archived_count=archived_count,
            live_risk=live_risk,
            info_hidden=info_hidden,
            filter_info=filter_info,
            scan_ids=scan_ids, reports=reports,
            counts=counts_by_status,
            filter_status=status, filter_sev=sev, sort=sort, q=q,
            **detail_ctx),
    )


EXCLUDED_FROM_SCORE = ("false_positive", "fixed", "accepted_risk")

# Demerit weights for the live risk-score derivation. Higher = worse,
# so the resulting number matches the LLM's risk_score convention
# (0 = no meaningful issues, 100 = critical / treat as incident).
# Validated findings carry roughly 2x the unvalidated weight so a
# probe-confirmed bug moves the dial harder than a scanner suspicion.
_SEV_RISK_VALIDATED = {"critical": 15.0, "high": 8.0,
                       "medium": 3.0, "low": 1.0, "info": 0.0}
_SEV_RISK_UNVALIDATED = {"critical": 8.0, "high": 4.0,
                         "medium": 1.5, "low": 0.5, "info": 0.0}


def _live_risk_score(findings: list[dict]) -> int:
    """0-100 risk derived from the CURRENT state of `findings`.

    Excludes anything the analyst has triaged out (false-positive,
    resolved, archived). Validated findings hit harder than scanner
    suspicions. Capped at 100. Returns an int so the KPI strip can
    render it without a format spec.
    """
    risk = 0.0
    for f in findings or []:
        if (f.get("status") or "open") in EXCLUDED_FROM_SCORE:
            continue
        sev = f.get("severity") or "info"
        validated = (f.get("validation_status") == "validated")
        table = _SEV_RISK_VALIDATED if validated else _SEV_RISK_UNVALIDATED
        risk += table.get(sev, 0.0)
    return min(100, int(round(risk)))


def _finding_panel_context(f: Optional[dict]) -> dict:
    """Build the variables the finding_panel.html / _finding_aside.html /
    finding_detail.html templates expect: f, e (enrichment), repro
    (reproduction block), probe (matched validation probe), io
    (captured request/response, 'what to look for' indicator, and
    Validate / Test eligibility). Tolerant of f=None — used as the
    empty-state path."""
    if not f:
        return {"f": None, "e": None, "repro": None, "probe": None, "io": None}
    e = None
    if f.get("enrichment_id"):
        e = db.query_one(
            "SELECT * FROM finding_enrichment WHERE id = %s",
            (f["enrichment_id"],))
        if e:
            # Decode JSON-encoded list columns into actual lists. The
            # finding_detail.html template renders both directly.
            try:
                e["steps"] = json.loads(e.get("remediation_steps") or "[]")
            except Exception:
                e["steps"] = []
            try:
                e["references"] = json.loads(e.get("references_json") or "[]")
            except Exception:
                e["references"] = []
    # Decode the raw_data JSON once so reproduction and evidence helpers
    # both see structured fields (matcher-name, http_request, etc.) rather
    # than each having to parse the blob on its own.
    if f.get("raw_data") and not f.get("raw"):
        try:
            f["raw"] = json.loads(f["raw_data"])
        except Exception:
            f["raw"] = None
    repro = reports_mod._repro_for(f)
    probe = toolkit_mod.find_probe_for_finding(f)
    io = _finding_io_evidence(f)
    # The Validate button (inline, modal) is only offered when a probe
    # is matched, the probe is declared read-only, and we have a URL to
    # send it to. Anything else falls back to the inline Challenge
    # button — same modal, but the action submits to /challenge_inline
    # (admin-only) and accepts probe-class as well as read-only. Only
    # 'destructive' probes still require the standalone form.
    has_url = bool((f.get("evidence_url") or "").strip())
    io["validatable"] = bool(
        probe
        and (probe.get("safety_class") == "read-only")
        and has_url
    )
    io["challengeable"] = bool(
        probe
        and (probe.get("safety_class") in ("read-only", "probe"))
        and has_url
        and not io["validatable"]    # don't double-render when validate fits
    )
    if io["validatable"] or io["challengeable"]:
        io["probe_name"] = probe.get("name")
        io["probe_safety"] = probe.get("safety_class")
        io["probe_budget_typical"] = probe.get("request_budget_typical")
        io["probe_budget_max"] = probe.get("request_budget_max")
    # The Test button is the no-probe sibling: just fires the bare
    # reproduction request once and surfaces the response. Allowed for
    # any GET / HEAD against a host inside the assessment scope.
    a_for_scope = (db.query_one("SELECT fqdn FROM assessments WHERE id = %s",
                                (f.get("assessment_id"),))
                   if f.get("assessment_id") else None)
    testable, _why, kind = _finding_testable(f, a_for_scope)
    io["testable"] = testable
    io["test_kind"] = kind   # 'http' or 'tls' — used for the button label
    return {"f": f, "e": e, "repro": repro, "probe": probe, "io": io}


def _testssl_indicator(test_id: str, finding: str) -> Optional[str]:
    """Map a testssl check id to a one-line 'what should the analyst see
    in their re-run' string. The indicator is shown as the 'Look for:'
    line under the curl in the Reproduce-&-verify panel, so it has to
    be specific enough that the analyst can grep/eyeball for it without
    interpreting testssl's output format.

    Returned strings frame the *current* (vulnerable) state. The fix is
    confirmed when the openssl / curl / testssl re-run no longer shows
    the indicator (handshake failure, no header, grade A, etc.)."""
    tid = (test_id or "").strip()
    finding = (finding or "").strip()
    if not tid and not finding:
        return None

    # Cipher offered against a specific protocol — openssl s_client
    # negotiates it = vulnerable.
    if re.match(r"^cipher-tls1(?:_1|_2|_3)?_x[0-9a-fA-F]+$", tid):
        return ("Successful TLS handshake on the named protocol with the "
                f"flagged cipher — testssl says: {finding}")
    # Cipher-order checks: 'no preference' / 'client preference'.
    if tid.startswith("cipher_order"):
        return ("Server is not enforcing its own cipher preference — "
                "nmap/testssl reports the protocol with no server-side "
                "ordering. Current state: " + (finding or "no preference"))
    # Cipherlist checks (NULL, aNULL, OBSOLETED, AVERAGE, 3DES).
    if tid.startswith("cipherlist_"):
        kind = tid.replace("cipherlist_", "")
        return (f"At least one {kind} cipher is still offered. After the "
                "cipher list is cleaned up, openssl s_client -cipher "
                f"{kind} should fail with 'no cipher match'.")
    # Protocol-availability checks: TLS1, TLS1_1, SSLv2/3.
    if tid in ("TLS1", "TLS1_1", "SSLv2", "SSLv3"):
        return (f"Protocol {tid} negotiates a successful handshake. "
                "Disable it server-side; the openssl s_client command "
                "above should then fail with 'protocol version'.")
    if tid == "BREACH":
        return ("Response carries a Content-Encoding header on HTTPS, "
                "which is the precondition BREACH needs. After disabling "
                "compression for sensitive responses, the curl --compressed "
                "probe must omit the header.")
    if tid.startswith("BEAST_CBC"):
        return ("CBC ciphers are still negotiated on the named legacy "
                "protocol. Removing TLS 1.0/1.1 (or all CBC suites) makes "
                "this go away.")
    if tid == "LUCKY13":
        return ("CBC ciphers susceptible to Lucky13 are still in the "
                "advertised list. Move to AEAD-only (AES-GCM, ChaCha20).")
    if tid == "HSTS":
        return ("Strict-Transport-Security header is missing or weak. "
                "Look for 'max-age=63072000; includeSubDomains; preload' "
                "in the curl -skI output once fixed.")
    if tid.startswith("cert_trust"):
        return ("Certificate uses a wildcard or anonymous trust path that "
                "testssl flagged. The openssl s_client | x509 -text "
                "command above shows the SAN list to confirm.")
    if tid.startswith("FS"):
        return ("Forward-secrecy posture is below the testssl threshold. "
                "The narrowed --fs re-run scopes the table to the FS rows "
                "for quick verification.")
    if tid == "overall_grade":
        return (f"testssl assigns this server an overall grade of "
                f"'{finding or '?'}'. Aim for A (or A+ with HSTS preload "
                "+ AEAD-only ciphers).")
    # Unknown/uncovered check id — fall back to the original message but
    # include enough context that the analyst can still act on it.
    return (f"testssl check '{tid}' reported: {finding}").strip()


def _finding_io_evidence(f: dict) -> dict:
    """Surface the per-tool 'reproduce & verify' evidence for the panel.

    Returns three optional fields:
      request    raw HTTP request the scanner sent (string, or None)
      response   raw HTTP response the scanner received (string, or None)
      indicator  one-line, human-readable "what to confirm" string an
                 analyst can grep for in their own re-run (or None)

    Only nuclei (request + response) and wapiti (request only) capture
    full HTTP traffic today. The indicator string is best-effort across
    every scanner so the analyst always has *something* concrete to look
    for after pasting the curl. Truncates large blobs at ~64 KB so a
    single bad finding can not balloon the panel HTML.
    """
    raw = f.get("raw") or {}
    tool = (f.get("source_tool") or "").lower()
    out: dict = {"request": None, "response": None, "indicator": None}

    def _clip(s):
        if not s:
            return None
        s = str(s)
        return s if len(s) <= 65536 else (s[:65536] + "\n[…truncated…]")

    if tool == "nuclei":
        out["request"] = _clip(raw.get("request"))
        out["response"] = _clip(raw.get("response"))
        matcher = raw.get("matcher-name") or ""
        target = raw.get("matched-at") or raw.get("url") or ""
        if matcher and target:
            out["indicator"] = (
                f"Nuclei matcher '{matcher}' fired on {target} — "
                "the same indicator should appear in your re-run.")
        elif target:
            out["indicator"] = (
                f"Nuclei template '{raw.get('template-id', '?')}' "
                f"matched at {target}.")
    elif tool == "wapiti":
        out["request"] = _clip(raw.get("http_request"))
        info = raw.get("info") or ""
        param = raw.get("parameter") or ""
        if info and param:
            out["indicator"] = f"{info} — vulnerable parameter: {param}"
        elif info:
            out["indicator"] = info
    elif tool == "testssl":
        # testssl check ids encode WHICH lever the analyst should look at
        # in their re-run. A blanket "testssl reported X" is useless for
        # validating a fix — instead we pick the indicator that matches
        # the test family (cipher offered, protocol reachable, header
        # missing, grade letter, etc.) so the line tells the analyst
        # exactly what state to confirm against.
        tid = raw.get("id") or ""
        finding = raw.get("finding") or ""
        out["indicator"] = _testssl_indicator(tid, finding)
    elif tool == "nikto":
        line = raw.get("line") or ""
        if line:
            out["indicator"] = line
    elif tool == "ffuf":
        url = raw.get("url") or ""
        status = raw.get("status")
        length = raw.get("length")
        if url and status is not None:
            out["indicator"] = (
                f"HTTP {status} response ({length} bytes) at {url} — "
                "this path is reachable on the target.")
    elif tool == "dalfox":
        payload = raw.get("payload") or raw.get("data") or ""
        param = raw.get("param") or raw.get("parameter") or ""
        if payload:
            base = f"Reflected XSS payload: {payload}"
            out["indicator"] = base + (f" via parameter {param}" if param else "")
    elif tool == "enhanced_testing":
        # Enhanced-testing probes don't always store the full HTTP
        # round-trip but they DO store enough to reconstruct a useful
        # summary: url + method + status + size + a body snippet (or,
        # for probes that opt in, the request_body and a clipped
        # response_body_excerpt). Synthesize a request and response so
        # the same Scan-request / Scan-response modal that nuclei
        # populates with real bytes also works here, with explicit
        # "synthesized from scan evidence" headers so the analyst is
        # not misled.
        ev = raw.get("evidence") or {}
        confirmed = ev.get("confirmed") or []
        attempts = ev.get("attempts") or []
        # `confirmed` is sometimes a single dict (auth-default-creds and
        # similar single-shot probes) and sometimes a list of dicts
        # (multi-finding probes). Coalesce both shapes; failing that,
        # fall back to the first attempt row.
        first = None
        if isinstance(confirmed, dict):
            first = confirmed
        elif isinstance(confirmed, list) and confirmed:
            first = confirmed[0]
        elif isinstance(attempts, list) and attempts:
            first = attempts[0]
        if isinstance(first, dict):
            # Prefer the row's own method when present (auth probes
            # POST), otherwise fall back to the finding's
            # evidence_method (mostly GET-shaped checks).
            # Some auth probes (auth_sql_login_bypass,
            # auth_default_admin_credentials) store login_path rather
            # than a full url, and don't bother recording the method
            # because they always POST. Combine with the assessment
            # origin and default the method to POST in that case so
            # the synthesized request reflects what actually happened
            # on the wire.
            login_path = first.get("login_path") or ""
            ent_url = first.get("url") or ""
            if not ent_url:
                origin = (raw.get("evidence") or {}).get("origin") or ""
                if origin and login_path:
                    ent_url = origin.rstrip("/") + login_path
            if not ent_url:
                ent_url = f.get("evidence_url") or ""
            ent_method = (first.get("method")
                          or ("POST" if login_path else None)
                          or f.get("evidence_method")
                          or "GET").upper()
            ent_status = first.get("status")
            ent_size = first.get("size")
            ent_family = first.get("error_family") or ""
            ent_snippet = first.get("snippet") or ""
            ent_label = first.get("label") or ""
            # Newer enhanced_testing probes (auth_default_admin_credentials
            # v1.1+) record the full request body and a clipped response
            # body excerpt — use them in preference to the older
            # url+status+snippet shape so the modal shows what was
            # actually sent (e.g. the JSON {email, password} POST body)
            # and what came back (e.g. the JWT response).
            req_body = first.get("request_body") or ""
            resp_excerpt = first.get("response_body_excerpt") or ""
            from urllib.parse import urlparse as _u
            host = _u(ent_url).hostname or ""
            req_lines = [f"{ent_method} {ent_url}"]
            if host:
                req_lines.append(f"Host: {host}")
            if req_body:
                # Probes that POST a JSON body always send
                # Content-Type: application/json — surface that here
                # so the synthesized request is faithful enough to
                # paste into curl.
                req_lines.append("Content-Type: application/json")
            if ent_label:
                req_lines.append(f"# Probe attempt: {ent_label}")
            req_lines.append("")
            if req_body:
                req_lines.append(req_body)
                req_lines.append("")
                req_lines.append("# Request reconstructed from scan "
                                 "evidence (probe recorded url, method, "
                                 "and full request body).")
            else:
                req_lines.append("# Synthesized from scan evidence — "
                                 "the enhanced_testing probe recorded "
                                 "the URL it sent but not full request "
                                 "headers / body.")
            out["request"] = _clip("\n".join(req_lines))

            resp_lines = []
            if ent_status is not None:
                resp_lines.append(f"HTTP {ent_status}")
            if ent_size is not None:
                resp_lines.append(f"Content-Length: {ent_size}")
            if ent_family:
                resp_lines.append(f"X-Detected-Error-Family: {ent_family}")
            resp_lines.append("")
            if resp_excerpt:
                # Probes that capture a body excerpt: emit it
                # untransformed so the analyst sees exactly what came
                # back (JWT, error envelope, etc).
                resp_lines.append(resp_excerpt)
                resp_lines.append("")
                resp_lines.append("# Response body excerpt as captured "
                                  "by the probe (clipped at 1.5 KB).")
            elif ent_snippet:
                resp_lines.append("--- response body snippet that "
                                  "triggered detection ---")
                resp_lines.append(ent_snippet)
                resp_lines.append("--- end snippet ---")
                resp_lines.append("")
                resp_lines.append("# Synthesized from scan evidence — "
                                  "only the detection snippet was "
                                  "captured.")
            else:
                resp_lines.append("[scanner did not capture a body "
                                  "snippet or excerpt]")
                resp_lines.append("")
                resp_lines.append("# Synthesized from scan evidence — "
                                  "full response body was not captured "
                                  "by the probe.")
            out["response"] = _clip("\n".join(resp_lines))

            indicator_bits = []
            if ent_status is not None:
                indicator_bits.append(f"HTTP {ent_status}")
            if ent_family:
                indicator_bits.append(f"'{ent_family}'")
            if ent_snippet:
                indicator_bits.append(f"body contains '{ent_snippet}'")
            # Default-credential confirmation: highlight the JWT-claim
            # signal that proved the session was administrative,
            # since that's the actual indicator the analyst looks for
            # rather than just status code.
            jwt_claim = first.get("jwt_admin_claim")
            if jwt_claim:
                indicator_bits.append(f"JWT carries {jwt_claim}")
            if indicator_bits:
                out["indicator"] = ("Re-running the request should reproduce "
                                    + " · ".join(indicator_bits) + ".")
    return out


# ----------------------------------------------------------------------
# Inline "Test" button — runs the finding's reproduction request once,
# server-side, with hard safety gates. Lets the analyst confirm
# something like "is /vendor/composer/installed.json actually present"
# without dropping to a terminal. NOT a probe (no verdict logic) —
# just a one-shot fetch with the response surfaced into a modal.
# ----------------------------------------------------------------------

# Hostnames considered "internal" — anything resolving here is refused
# regardless of scope, so the Test button cannot be coerced into a
# server-side request forgery vehicle against the orchestrator's own
# private network.
import ipaddress as _ipaddress
import socket as _socket

# Per-user token bucket: 30 Test invocations per 60s window. Crude but
# enough to stop a tab full of buttons being slammed in a loop, and
# resets across container restarts which is fine for an internal tool.
_TEST_RATE_LIMIT_WINDOW_S = 60
_TEST_RATE_LIMIT_MAX = 30
_test_rate_limit_state: dict[str, list[float]] = {}


def _test_rate_limit_check(user_key: str) -> Optional[float]:
    """Return None if under the cap, else the seconds-until-window-resets."""
    now = time.monotonic()
    bucket = _test_rate_limit_state.setdefault(user_key, [])
    cutoff = now - _TEST_RATE_LIMIT_WINDOW_S
    # Drop expired hits in-place.
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= _TEST_RATE_LIMIT_MAX:
        return _TEST_RATE_LIMIT_WINDOW_S - (now - bucket[0])
    bucket.append(now)
    return None


def _is_private_host(host: str) -> bool:
    """True if `host` resolves to a non-public IP. Refused before any
    request is sent so an attacker can't pivot Test through the
    container's network into private services. Checks every A/AAAA
    record (a host might have one public + one private; treat the
    whole hostname as private if any record is private)."""
    try:
        infos = _socket.getaddrinfo(host, None)
    except OSError:
        # DNS failure — let the actual request error out with a
        # clearer message rather than masking it as "private host".
        return False
    for info in infos:
        try:
            ip = _ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return True
    return False


def _finding_testable(finding: dict,
                      assessment: Optional[dict]) -> tuple[bool, str, str]:
    """Decide whether the inline Test button should be offered for this
    finding. Returns (testable, reason, kind). Reason is a short string
    for the tooltip / refusal payload; only meaningful when testable
    is False. Kind is one of:
      "http" — verify by sending a single GET / HEAD request and
               showing the live response (the curl-equivalent path).
      "tls"  — verify by re-running testssl.sh with a narrowly scoped
               flag for the specific check id, and surfacing the JSON
               row(s) that match. Used for testssl-source findings,
               where the source_tool already wrote a TLS verdict and
               an HTTP request would not exercise the same posture.

    Gates (common to both kinds):
      * URL host is in the assessment's scope (exact match or subdomain
        of the assessment's fqdn) — keeps the analyst from coaxing the
        tool into off-target traffic.
    Kind-specific gates:
      * http: method is GET / HEAD, scheme is http(s).
      * tls:  source_tool == 'testssl' (the TLS suite is the only
              one whose findings reflect transport-layer state rather
              than HTTP responses).
    Per-request gates (private-IP refusal, rate limit) live in the
    handler itself.
    """
    url = (finding.get("evidence_url") or "").strip()
    if not url:
        return (False, "finding has no evidence URL", "")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return (False, f"unsupported scheme {parsed.scheme!r}", "")
    host = (parsed.hostname or "").lower()
    if not host:
        return (False, "URL has no host", "")
    if assessment and assessment.get("fqdn"):
        fqdn = assessment["fqdn"].lower()
        if not (host == fqdn or host.endswith("." + fqdn)):
            return (False, f"host {host!r} is outside the assessment scope", "")

    tool = (finding.get("source_tool") or "").lower()
    if tool == "testssl":
        # testssl findings only make sense to verify via a TLS probe.
        # Even when evidence_url is just `https://host`, the test runs
        # against the host:port directly.
        #
        # Exception: `overall_grade` is a letter-grade roll-up of
        # every other testssl row in the report (weak ciphers, weak
        # protocols, missing headers, expired certs). There is
        # nothing to "re-test" — the constituent rows ARE the test.
        # parse_testssl drops these at scan ingest now, but defend
        # the UI in case a row pre-dates that filter. The Test
        # button surfaces the refusal reason instead of running.
        title = (finding.get("title") or "").strip().lower()
        raw = finding.get("raw") or {}
        raw_id = (raw.get("id") or "").strip().lower()
        if title == "overall_grade" or raw_id == "overall_grade":
            return (False,
                    "overall_grade is a roll-up of the other TLS "
                    "findings on this assessment — there's nothing "
                    "to re-test on its own. Review the constituent "
                    "rows (weak ciphers, weak protocols, missing "
                    "headers).",
                    "")
        return (True, "", "tls")

    if tool == "nuclei":
        # Nuclei findings are template-matcher events. A bare HTTP GET
        # wouldn't run the matcher logic, so a generic Test would just
        # echo the response without saying whether the original
        # template would still fire. Re-run nuclei narrowly with the
        # specific template id so the analyst sees whether the
        # matcher reproduces. Requires a usable template-id in the
        # raw_data; if missing we fall through to the http path so
        # there's still SOMETHING to click.
        raw = finding.get("raw") or {}
        if (raw.get("template-id") or "").strip():
            return (True, "", "nuclei")

    # Findings from non-testssl tools that are STILL clearly about
    # certificate / SSL / TLS posture (e.g. Nikto's "wildcard
    # certificate" notice). An HTTP GET would not surface the cert
    # details the analyst needs — handshake-level information does.
    if parsed.scheme == "https" and _looks_like_cert_finding(finding):
        return (True, "", "tls_info")

    method = (finding.get("evidence_method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        return (False,
                f"only GET / HEAD are testable — finding is {method}",
                "")
    return (True, "", "http")


# Keywords that, when present in a finding's title or description,
# indicate the finding is about certificate / TLS posture rather than
# HTTP behavior. Conservative on purpose — we only divert to a TLS
# probe when the user clearly cares about the handshake / cert.
_CERT_FINDING_KEYWORDS = (
    "wildcard certificate", "wildcard cert",
    "ssl certificate", "tls certificate",
    "certificate is", "certificate has",
    "certificate revocation", "certificate chain",
    "certificate expir", "expired certificate",
    "self-signed", "self signed",
    "subject alt", " san ",
    " cn=",
    "weak cert", "ssl/tls", "ssl info",
    "ssl detail", "tls detail",
)


def _looks_like_cert_finding(finding: dict) -> bool:
    """True when the finding's wording indicates a TLS / certificate
    posture issue. Used to dispatch the Test button to a cert-info
    probe (openssl s_client + x509 -text) instead of an HTTP GET."""
    blob = " ".join([
        (finding.get("title") or "").lower(),
        (finding.get("description") or "").lower(),
    ])
    return any(k in blob for k in _CERT_FINDING_KEYWORDS)


def _highlight_terms_for(finding: dict) -> list[str]:
    """Per-finding shortlist of strings the modal should mark in the
    response body. Drawn from the same raw_data fields the indicator
    text uses, plus a few generic banners that always interest an
    analyst (Server, X-Powered-By). Kept short (≤8 terms) so the
    modal isn't drowned in highlights."""
    raw = finding.get("raw") or {}
    tool = (finding.get("source_tool") or "").lower()
    terms: list[str] = []
    if tool == "nuclei":
        for key in ("matcher-name", "extracted-results"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                terms.append(v)
            elif isinstance(v, list):
                terms += [str(x) for x in v if x]
    elif tool == "wapiti":
        for key in ("parameter", "info"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                terms.append(v)
    elif tool == "nikto":
        # The Nikto line frequently mentions a substring that should
        # show up in the response (e.g. 'PHP Composer configuration').
        # We split off any 'See: <url>' tail so the highlight isn't
        # an external reference URL.
        line = raw.get("line") or ""
        if line and ":" in line:
            after = line.split(":", 1)[1].strip()
            tail = after.split(" See: ", 1)[0].strip()
            if tail:
                terms.append(tail[:80])
    # Always also scan for these generic disclosure banners.
    terms += ["Server:", "X-Powered-By:", "Set-Cookie"]
    # De-dup, drop empties, cap length per term.
    seen: set = set()
    out = []
    for t in terms:
        t = (t or "").strip()
        if t and t.lower() not in seen and len(t) >= 3:
            seen.add(t.lower())
            out.append(t[:200])
    return out[:8]


# Pick the right testssl.sh flag for a given testssl finding id. The
# narrower the run, the faster the verdict — full-suite testssl runs
# are minutes, narrow runs are 5-30 seconds. Keys are matched in order:
# regex prefixes first, then exact-id sets, then a default fallback.
_TESTSSL_DISPATCH: list[tuple[object, str, str]] = [
    # (matcher, flag, human label)
    (re.compile(r"^cipherlist_"),       "-s",  "standard cipher categories"),
    (re.compile(r"^cipher_order"),      "-P",  "server cipher preference"),
    (re.compile(r"^cipher_(?:negotiated|x|tls)"),
                                        "-e",  "each-cipher enumeration"),
    (re.compile(r"^cert(?:_|ificate)"), "-S",  "server defaults / certificate"),
    (re.compile(r"^chain"),             "-S",  "certificate chain"),
    (re.compile(r"^DH(?:_|$)|^GOOD_DH"), "-f", "forward secrecy"),
    (re.compile(r"^FS"),                "-f",  "forward secrecy"),
    ({"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"},
                                        "-p",  "protocols"),
    ({"BREACH", "CRIME_TLS", "POODLE_SSL", "FREAK", "DROWN", "LOGJAM",
      "BEAST", "RC4", "SWEET32", "WINSHOCK", "HEARTBLEED",
      "CCS_INJECTION", "TICKETBLEED", "ROBOT", "SECURE_RENEGO",
      "SECURE_CLIENT_RENEGO", "LUCKY13", "FALLBACK_SCSV"},
                                        "-U",  "vulnerability suite"),
    (re.compile(r"^HSTS|^HPKP|^banner|^cookie",
                re.IGNORECASE),         "-h",  "HTTP / TLS headers"),
]


def _pick_testssl_flag(testssl_id: str) -> tuple[str, str]:
    """Map a testssl id (e.g. 'cipherlist_aNULL', 'TLS1', 'HEARTBLEED')
    to the narrowest CLI flag that will exercise that check, plus a
    human label for the modal. Falls back to '-s' (standard cipher
    categories) if nothing matches — covers most ciphersuite findings
    and runs in under 10 seconds."""
    if not testssl_id:
        return ("-s", "standard cipher categories")
    for matcher, flag, label in _TESTSSL_DISPATCH:
        if isinstance(matcher, set):
            if testssl_id in matcher:
                return (flag, label)
        elif matcher.search(testssl_id):
            return (flag, label)
    return ("-s", "standard cipher categories")


def _finding_test_header_fast(host: str, port: int,
                                testssl_id: str,
                                finding: dict) -> JSONResponse:
    """Fast verification for header-presence findings (HSTS, CSP,
    X-Frame-Options, security headers, server/X-Powered-By banners).
    One HTTPS GET, parse headers, decide. Sub-second instead of the
    30-60 seconds testssl.sh -h would take to ask the same question.

    Returns the same JSON envelope as _finding_test_tls so the modal
    renders identically. The `command` field documents that this run
    used a single HTTP request instead of testssl.sh, and
    `matched_rows` is synthesized from the parsed headers so the
    existing table renderer keeps working.

    Verdicts:
      reproduced     — finding's `_missing` claim still holds (header
                       absent or, for HSTS time, max-age below threshold)
      not_reproduced — header is now present (and policy is reasonable
                       for HSTS — max-age >= 6 months)
      inconclusive   — request failed (DNS / TLS / network)
    """
    import time as _time
    import ssl as _ssl
    import urllib.request as _urlreq
    import urllib.error as _urlerr

    # Two callers: the testssl-id dispatch (keys by _HEADER_FAST_ID_TO_HEADER)
    # AND the tool-agnostic _detect_header_check_target dispatch (passes
    # a direct header name like "strict-transport-security" because
    # nikto/wapiti/nuclei/LLM findings don't carry a testssl id but
    # still encode the same "this header is missing" question).
    # Accept either form: if the testssl_id IS itself a known
    # response-header name, treat it as a direct passthrough.
    target_header = _HEADER_FAST_ID_TO_HEADER.get(testssl_id.lower())
    if not target_header:
        if testssl_id.lower() in _HEADER_FAST_ID_TO_HEADER.values():
            target_header = testssl_id.lower()
    if not target_header:
        return JSONResponse({
            "ok": False, "error": "no_header_for_id",
            "message": f"testssl id {testssl_id!r} is not in the "
                        "header-fast map.",
        }, status_code=500)

    url = f"https://{host}:{port}/"
    # User-Agent comes from the assessment's configured UA so the
    # response we get matches what the original scan would have got.
    # Some WAFs / CDNs respond differently to scanner-shaped UAs; using
    # the assessment's UA avoids spurious diffs when an analyst re-tests.
    ua_string = _resolve_assessment_user_agent(finding.get("assessment_id"))
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):
            return None

    opener = _urlreq.build_opener(
        _urlreq.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )
    req = _urlreq.Request(url, method="GET", headers={
        "User-Agent": ua_string,
        "Accept": "*/*",
    })

    t_start = _time.monotonic()
    status = 0
    headers_lower: dict[str, str] = {}
    err_text: str | None = None
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            for k, v in resp.headers.items():
                # Lowercase keys for match; keep ORIGINAL value so an
                # analyst sees casing artifacts (e.g. "max-age=15552000;
                # includeSubDomains") in the rendered row.
                headers_lower[k.lower()] = v
    except _urlerr.HTTPError as he:
        status = he.code
        try:
            for k, v in (he.headers or {}).items():
                headers_lower[k.lower()] = v
        except Exception:
            pass
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"
    elapsed_ms = int((_time.monotonic() - t_start) * 1000)

    # Curl-equivalent that an analyst can copy-paste to reproduce the
    # exact same request the fast path made. -kIL = follow redirects,
    # ignore cert errors, HEAD-style headers; -A passes the same UA we
    # actually sent. NOTE: this curl is documentation only — the
    # in-process urllib above is the path that produced the verdict.
    reproduce_curl = (
        f"curl -s -kIL -A {ua_string!r} {url}")
    cmd_label = (f"single HTTPS GET to {url} "
                 f"(header-presence fast path: {testssl_id} → {target_header})")

    if err_text:
        return JSONResponse({
            "ok": True, "kind": "tls",
            "host": host, "port": port,
            "command": cmd_label,
            "reproduce_command": reproduce_curl,
            "elapsed_ms": elapsed_ms, "exit_code": -1,
            "flag": "fast-path",
            "flag_label": cmd_label,
            "testssl_id": testssl_id,
            "verdict": "inconclusive",
            "matched_rows": [{
                "id": testssl_id,
                "severity": "INFO",
                "finding": (f"HTTPS request failed: {err_text}. Run "
                            "the full testssl.sh suite from the "
                            "Challenge form for a deeper check."),
            }],
            "stdout_excerpt": "", "stderr_excerpt": err_text,
        })

    header_value = headers_lower.get(target_header)
    verdict = "inconclusive"
    severity_out = "INFO"
    finding_text = ""

    # HSTS-specific policy assessment: presence alone isn't enough —
    # the spec requires max-age >= 6 months for "preload" eligibility,
    # and most browsers ignore HSTS with max-age < 1 minute. We treat
    # max-age < 15552000 (180 days) as "still problematic, finding
    # still reproduced" because that's the conventional remediation
    # threshold the original finding would have wanted.
    is_hsts = (target_header == "strict-transport-security")
    HSTS_MIN_MAX_AGE = 15552000   # 180 days

    if header_value is None:
        # Header is absent — the *_missing finding is reproduced.
        verdict = "reproduced"
        severity_out = "MEDIUM"
        finding_text = (f"Response header {target_header!r} is absent "
                        f"from GET {url} (HTTP {status}). The original "
                        f"missing-header finding still applies.")
    else:
        if is_hsts:
            # Parse max-age=N out of the header value. Tolerant of
            # whitespace and ordering; any non-numeric or missing
            # max-age = browsers ignore the header, so still vulnerable.
            import re as _re
            m = _re.search(r"max-age\s*=\s*(\d+)", header_value, _re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age >= HSTS_MIN_MAX_AGE:
                verdict = "not_reproduced"
                finding_text = (f"HSTS header is present and policy is "
                                f"reasonable: {header_value!r} (max-age="
                                f"{max_age}, ≥ recommended "
                                f"{HSTS_MIN_MAX_AGE}). Finding looks "
                                f"remediated.")
            else:
                verdict = "reproduced"
                severity_out = "LOW"
                finding_text = (f"HSTS header is present but max-age="
                                f"{max_age} is below the recommended "
                                f"{HSTS_MIN_MAX_AGE} (180 days). "
                                f"Browsers may still be vulnerable to "
                                f"first-visit downgrade attacks.")
        else:
            # Generic header — presence flips verdict to not-reproduced.
            verdict = "not_reproduced"
            finding_text = (f"Response header {target_header!r} is "
                            f"present: {header_value!r}. The original "
                            f"missing-header finding is no longer "
                            f"reproduced.")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label,
        "reproduce_command": reproduce_curl,
        "elapsed_ms": elapsed_ms, "exit_code": 0,
        "flag": "fast-path",
        "flag_label": cmd_label,
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [{
            "id": testssl_id,
            "severity": severity_out,
            "finding": finding_text,
        }],
        "stdout_excerpt": "",
        "stderr_excerpt": "",
        # Surface the actual response headers so the analyst can copy
        # the live values into a ticket without leaving the modal.
        "response_status": status,
        "response_headers": list(headers_lower.items()),
    })


def _finding_test_cert_fast(host: str, port: int,
                            testssl_id: str,
                            finding: dict) -> JSONResponse:
    """Fast verification for cert-shape testssl findings via a direct
    TLS handshake. Sub-second for the common case.

    Returns the same JSON envelope as _finding_test_tls so the modal
    can render it identically — the `command` field documents that
    this run used the in-process handshake instead of testssl.sh, and
    `matched_rows` is synthesized from the parsed cert so the existing
    table renderer keeps working.

    Verdicts:
      reproduced     — the original finding's claim still holds against
                       the live cert.
      not_reproduced — the live cert no longer has the flagged property
                       (e.g. cert was rotated, no longer wildcard).
      inconclusive   — the handshake failed or the testssl_id maps to a
                       check this fast path doesn't fully cover.
    """
    # Late import — keeps the toolkit/lib path off sys.path until we
    # actually need it, and keeps the import error local if /app/toolkit
    # isn't where we expect.
    import sys as _sys
    if "/app/toolkit" not in _sys.path:
        _sys.path.insert(0, "/app/toolkit")
    from lib.tls import fetch_cert

    info = fetch_cert(host, port)
    if not info.ok:
        # Connection couldn't even be made — not the same as testssl
        # timing out, but functionally inconclusive for the analyst.
        return JSONResponse({
            "ok": True,
            "kind": "tls",
            "host": host,
            "port": port,
            "command": f"in-process TLS handshake to {host}:{port} (fast path)",
            "elapsed_ms": info.elapsed_ms,
            "exit_code": -1,
            "flag": "fast-path",
            "flag_label": f"direct TLS handshake (cert-shape fast path: {testssl_id})",
            "testssl_id": testssl_id,
            "verdict": "inconclusive",
            "matched_rows": [{
                "id": testssl_id,
                "severity": "INFO",
                "finding": (f"TLS handshake failed: {info.error}. "
                            "Run the full testssl.sh suite from the "
                            "Challenge form if you need a deeper check."),
            }],
            "stdout_excerpt": "",
            "stderr_excerpt": info.error or "",
        })

    # Per-id verdict logic. Each branch sets `verdict` and `finding_text`
    # to mirror the row testssl would have produced.
    verdict = "inconclusive"
    finding_text = ""
    severity_out = "INFO"

    if testssl_id == "cert_trust_wildcard":
        if info.has_wildcard_san:
            verdict = "reproduced"
            severity_out = "LOW"
            finding_text = (f"Trust is via wildcard cert. SAN "
                            f"{info.wildcard_sans!r} covers all "
                            "subdomains under that pattern.")
        else:
            verdict = "not_reproduced"
            finding_text = ("Cert no longer has a wildcard SAN. "
                            f"Current SANs: {info.sans!r}")

    elif testssl_id in ("cert_subjectAltName", "cert_commonName_wo_SAN"):
        # SAN missing entirely (rare but real on legacy / self-signed)
        if not info.sans:
            verdict = "reproduced"
            severity_out = "MEDIUM"
            finding_text = ("Subject Alternative Name extension is "
                            "absent from the leaf cert. Modern browsers "
                            "(and CA/B Forum requirements) reject CN-only "
                            "certs.")
        else:
            verdict = "not_reproduced"
            finding_text = (f"SAN extension is present with "
                            f"{len(info.sans)} DNS entries: {info.sans!r}")

    elif testssl_id == "cert_commonName":
        finding_text = (f"Subject CN: {info.common_name!r}. "
                        f"SAN dnsNames: {info.sans!r}.")
        # The original finding is essentially informational — surface
        # the data and call it not_reproduced if SAN matches the host.
        if info.sans and any(_san_matches_host(s, host) for s in info.sans):
            verdict = "not_reproduced"
        else:
            verdict = "inconclusive"

    elif testssl_id in ("cert_notAfter", "cert_validityPeriod",
                        "cert_expirationStatus", "cert_extlifeSpan"):
        d = info.days_until_expiry
        finding_text = (f"Cert valid through {info.not_after} "
                        f"({d} days from now).")
        if d is None:
            verdict = "inconclusive"
        elif d < 0:
            verdict = "reproduced"
            severity_out = "HIGH"
            finding_text = (f"Cert EXPIRED on {info.not_after} "
                            f"({-d} days ago).")
        elif d < 30:
            verdict = "reproduced"
            severity_out = "MEDIUM"
            finding_text = (f"Cert expires in {d} days "
                            f"(after {info.not_after}).")
        else:
            verdict = "not_reproduced"

    elif testssl_id == "cert_notBefore":
        from datetime import datetime, timezone
        try:
            nb = datetime.fromisoformat(info.not_before)
            now = datetime.now(timezone.utc)
            if nb > now:
                verdict = "reproduced"
                severity_out = "HIGH"
                finding_text = (f"Cert is not yet valid. notBefore = "
                                f"{info.not_before}, current time = "
                                f"{now.isoformat()}.")
            else:
                verdict = "not_reproduced"
                finding_text = (f"Cert is currently within its validity "
                                f"window (notBefore = {info.not_before}).")
        except Exception:
            verdict = "inconclusive"
            finding_text = (f"notBefore = {info.not_before}.")

    elif testssl_id == "cert_signatureAlgorithm":
        algo = (info.signature_algorithm or "").lower()
        finding_text = f"Signature algorithm: {info.signature_algorithm}"
        if any(weak in algo for weak in ("md5", "sha1", "sha-1")):
            verdict = "reproduced"
            severity_out = "HIGH"
            finding_text = (f"Weak signature algorithm: "
                            f"{info.signature_algorithm}. CA/B Forum "
                            "deprecated SHA-1 in 2017; MD5 is broken.")
        elif algo:
            verdict = "not_reproduced"
        else:
            verdict = "inconclusive"

    elif testssl_id == "cert_keySize":
        size = info.public_key_size
        algo = info.public_key_algorithm
        finding_text = (f"Public key: {algo} {size} bits"
                        if size else f"Public key: {algo}")
        if size is None:
            # Ed25519 / Ed448 don't have a meaningful "size" — they're
            # always considered strong. Mark not_reproduced.
            verdict = "not_reproduced"
        elif algo.startswith("RSA") and size < 2048:
            verdict = "reproduced"
            severity_out = "HIGH"
            finding_text = (f"RSA key is {size} bits — below the "
                            "2048-bit minimum required by current "
                            "CA/B Forum baseline requirements.")
        elif algo.startswith("DSA") and size < 2048:
            verdict = "reproduced"
            severity_out = "HIGH"
            finding_text = f"DSA {size}-bit key is too weak."
        elif algo.startswith("EC") and size < 256:
            verdict = "reproduced"
            severity_out = "MEDIUM"
            finding_text = f"EC {size}-bit curve is too weak."
        else:
            verdict = "not_reproduced"

    elif testssl_id == "cert_chain_of_trust":
        # We only fetch the leaf here — chain-of-trust verification
        # needs the full chain plus a trust store. Surface what we
        # know but call it inconclusive so the analyst knows the fast
        # path didn't dig in.
        if info.is_self_signed:
            verdict = "reproduced"
            severity_out = "HIGH"
            finding_text = ("Leaf cert is self-signed (subject == issuer). "
                            "No CA chain to verify.")
        else:
            verdict = "inconclusive"
            finding_text = ("Leaf cert is CA-issued; full chain "
                            "verification needs the testssl.sh -S run "
                            "via the Challenge form for an authoritative "
                            "answer.")

    else:
        # Defensive — _CERT_FAST_TESTSSL_IDS gate above prevents this in
        # practice, but if a new id slips through, surface a benign row.
        verdict = "inconclusive"
        finding_text = (f"Cert-shape fast path has no specific check for "
                        f"{testssl_id!r}. Cert summary: CN={info.common_name!r}, "
                        f"SANs={info.sans!r}.")

    # Synthesize the row shape testssl.sh would have produced so the
    # modal's existing rendering ('matched_rows' table) keeps working
    # without a special-case branch on the frontend.
    matched_row = {
        "id": testssl_id,
        "severity": severity_out,
        "finding": finding_text,
        "ip": f"{host}/{host}",
        "port": str(port),
    }

    return JSONResponse({
        "ok": True,
        "kind": "tls",
        "host": host,
        "port": port,
        "command": (f"in-process TLS handshake to {host}:{port} "
                    f"(cert-shape fast path: {testssl_id})"),
        "elapsed_ms": info.elapsed_ms,
        "exit_code": 0,
        "flag": "fast-path",
        "flag_label": "direct TLS handshake — leaf cert inspection",
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [matched_row],
        "stdout_excerpt": json.dumps({
            "protocol": info.protocol,
            "cipher": info.cipher,
            "subject": info.subject,
            "issuer": info.issuer,
            "common_name": info.common_name,
            "sans": info.sans,
            "san_ips": info.san_ips,
            "not_before": info.not_before,
            "not_after": info.not_after,
            "days_until_expiry": info.days_until_expiry,
            "signature_algorithm": info.signature_algorithm,
            "public_key_algorithm": info.public_key_algorithm,
            "public_key_size": info.public_key_size,
            "is_self_signed": info.is_self_signed,
        }, indent=2)[:8000],
        "stderr_excerpt": "",
    })


def _san_matches_host(san: str, host: str) -> bool:
    """RFC 6125-ish wildcard match: '*.example.com' matches
    'foo.example.com' but not 'example.com' or 'a.b.example.com'."""
    san = (san or "").lower()
    host = (host or "").lower()
    if not san or not host:
        return False
    if san == host:
        return True
    if san.startswith("*."):
        suffix = san[1:]      # '.example.com'
        # Wildcard binds exactly one label.
        if host.endswith(suffix):
            head = host[:-len(suffix)]
            return bool(head) and "." not in head
    return False


# ---------------------------------------------------------------------
# Fast-path tooling decisions for TLS / header verification.
# ---------------------------------------------------------------------
# Empirical benchmarks against a real production target (HTTP/2 502
# Cloudhub vhost, EC2/CloudFront edge):
#
#   Header presence (HSTS): Python urllib in-process       150–300 ms
#                            curl -sI                       150–300 ms
#                            testssl.sh -h                  ~15 s
#
#   Single cipher attempt:  openssl s_client -cipher        80–120 ms
#                            curl --ciphers                 ~290 ms
#                            testssl.sh -e (full enum)      ~57 s
#
#   Single protocol probe:  openssl s_client -tls1_X        ~80 ms
#                            (system openssl for TLS1.2+,
#                             bundled openssl with OPENSSL_CONF= for
#                             SSLv2/3 + TLS1.0/1.1 — system openssl
#                             refuses deprecated protocols by build)
#
#   Full cipher enumeration: nmap --script ssl-enum-ciphers ~600 ms
#                            testssl.sh -e                  ~57 s
#
# Decisions, in order of dispatch in _finding_test_tls():
#   1. Header IDs        → in-process urllib (no subprocess fork).
#   2. Cert-shape IDs    → in-process Python ssl + cert parse.
#   3. Single cipher IDs → system openssl (modern) or bundled openssl
#                          (legacy, with OPENSSL_CONF= empty).
#   4. Protocol IDs      → system openssl (modern) or bundled openssl
#                          (legacy).
#   5. Full enumeration  → nmap --script ssl-enum-ciphers.
#   6. Heavy vuln tests  → testssl.sh subprocess (the only path that
#                          actually exercises HEARTBLEED, ROBOT,
#                          SWEET32-oracle, etc. — kept as the
#                          fallback, with a 180 s timeout).
#
# Every fast-path also surfaces a "reproduce_command" string in its
# JSON so the analyst can copy-paste the exact CLI invocation that
# produced the verdict — closes the audit gap that the in-process
# branches would otherwise have.
# ---------------------------------------------------------------------


# Path to the testssl-bundled openssl 1.0.2-bad binary that supports
# legacy ciphers / protocols the system openssl 3.x build refuses to
# even attempt. testssl.sh uses this internally; we re-use it for our
# legacy-cipher / legacy-protocol fast paths. The OPENSSL_CONF env
# var must be empty when invoking it (default config tries to load
# unavailable providers and the binary errors out).
_LEGACY_OPENSSL = "/opt/testssl/bin/openssl.Linux.x86_64"

# testssl IDs (and protocol-name shorthands) that need the legacy
# binary because system openssl 3.x rejects the protocol/cipher at
# build time. Anything not in this set goes through the system openssl
# at /usr/bin/openssl.
_LEGACY_PROTOCOL_IDS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1"}
_LEGACY_CIPHER_NAMES = {"NULL", "aNULL", "eNULL", "EXPORT",
                          "LOW", "DES", "MD5", "RC4", "3DES"}


# Header-missing detector that works across every source tool. The
# claim "this response is missing header X" is tool-agnostic — nikto,
# wapiti, nuclei, testssl, enhanced_testing, and the LLM all phrase it
# differently but all reduce to "fetch the URL once, look at the
# headers". This regex catalog covers the wordings each scanner uses
# for the common headers; whatever the source, route to the same
# verdict-producing fast path instead of returning a raw HTTP dump.
#
# Each entry is (regex, response_header_name). The regex is matched
# case-insensitively against the finding's title field. First match
# wins. Patterns are ordered most-specific first so e.g. an explicit
# "missing strict-transport-security" wins over a generic "HSTS"
# match that might also fire on findings about HSTS configuration.
_HEADER_TITLE_PATTERNS: list[tuple[str, str]] = [
    # nikto: "Suggested security header missing: <NAME>"
    (r"suggested security header missing:?\s*strict-transport-security",
     "strict-transport-security"),
    (r"suggested security header missing:?\s*content-security-policy",
     "content-security-policy"),
    (r"suggested security header missing:?\s*x-frame-options",
     "x-frame-options"),
    (r"suggested security header missing:?\s*x-content-type-options",
     "x-content-type-options"),
    (r"suggested security header missing:?\s*referrer-policy",
     "referrer-policy"),
    (r"suggested security header missing:?\s*permissions-policy",
     "permissions-policy"),
    (r"suggested security header missing:?\s*x-xss-protection",
     "x-xss-protection"),
    # nikto: "<HEADER> header is not set" / "header is deprecated"
    (r"x-content-type-options header is not set",
     "x-content-type-options"),
    (r"x-frame-options header.*deprecated",
     "x-frame-options"),
    # wapiti: "HTTP Strict Transport Security (HSTS)" / "Clickjacking Protection"
    (r"http strict transport security|hsts\b",
     "strict-transport-security"),
    (r"clickjacking protection",
     "x-frame-options"),
    # nuclei: "HTTP Missing Security Headers"
    (r"http missing security headers?",
     # Generic — nuclei doesn't name which one. We default to HSTS as
     # the most-asked-for, but better to render a multi-header table.
     # _finding_test_header_fast handles a single header at a time;
     # for the generic case the analyst gets HSTS verdict and the
     # full Set-Cookie/headers dump, which usually answers the
     # follow-up they would have had.
     "strict-transport-security"),
    # enhanced_testing config_*_missing aliases
    (r"config_hsts_missing",                "strict-transport-security"),
    (r"config_csp_missing",                 "content-security-policy"),
    (r"config_xfo_missing",                 "x-frame-options"),
    (r"config_xcto_missing",                "x-content-type-options"),
    (r"config_referrer_policy_missing",     "referrer-policy"),
    (r"config_permissions_policy_missing",  "permissions-policy"),
    # LLM-emitted titles (enhanced_ai_testing). The model tends to
    # phrase findings as "missing X header" or "X not configured" or
    # "Strict-Transport-Security absent". Match the longest header
    # name first so e.g. "x-content-type-options" doesn't shadow a
    # narrower "content-type" match.
    (r"missing.*strict-transport-security|strict-transport-security.*(absent|missing|not (configured|set))",
     "strict-transport-security"),
    (r"missing.*content-security-policy|content-security-policy.*(absent|missing|not (configured|set))",
     "content-security-policy"),
    (r"missing.*x-content-type-options|x-content-type-options.*(absent|missing|not (configured|set))",
     "x-content-type-options"),
    (r"missing.*x-frame-options|x-frame-options.*(absent|missing|not (configured|set))",
     "x-frame-options"),
    (r"missing.*referrer-policy|referrer-policy.*(absent|missing|not (configured|set))",
     "referrer-policy"),
    (r"missing.*permissions-policy|permissions-policy.*(absent|missing|not (configured|set))",
     "permissions-policy"),
]


# Cookie-attribute findings work the same way as header-missing
# findings — nuclei, nikto, and the LLM all phrase them slightly
# differently but they all reduce to "fetch the URL once, parse
# Set-Cookie, check the named flag." Pattern → which attribute to
# verify (httponly / secure / samesite). First match wins.
# Permissive on purpose: testssl is last resort, so any plausible
# cookie-attribute phrasing should route here. Each pattern fires on
# the cookie attribute keyword (httponly / secure / samesite) appearing
# anywhere in a title that mentions cookies.
_COOKIE_TITLE_PATTERNS: list[tuple[str, str]] = [
    # SameSite: nuclei "Missing Cookie SameSite Strict",
    #          "Cookies SameSite=Lax warning", LLM "missing samesite", etc.
    (r"\bsamesite\b", "samesite"),
    # HttpOnly: nikto "Cookie X created without the httponly flag",
    #          LLM "session cookie without HttpOnly", etc.
    (r"\b(httponly|http[-_ ]only)\b", "httponly"),
    # Secure: nuclei "Cookies without Secure attribute - Detect",
    #         LLM "session cookie missing Secure flag", etc.
    (r"cookie[s]?[^\n]*\bsecure\b|\bsecure\b[^\n]*cookie", "secure"),
]


def _detect_cookie_check_target(finding: dict) -> Optional[str]:
    """If the finding's title is about a missing cookie attribute
    (HttpOnly / Secure / SameSite), return the attribute name to
    inspect. Tool-agnostic — works for nuclei "Missing Cookie SameSite
    Strict", nikto "Cookie X created without the httponly flag", and
    the LLM. Returns None for non-cookie findings.

    Lightly gated on the title containing "cookie" or "samesite" so we
    don't false-fire on findings that mention "secure" in another
    context (HSTS preload, secure transport, etc.)."""
    title = (finding.get("title") or "").strip().lower()
    if not title:
        return None
    if "cookie" not in title and "samesite" not in title:
        return None
    for pat, attr in _COOKIE_TITLE_PATTERNS:
        if re.search(pat, title, re.IGNORECASE):
            return attr
    return None


def _finding_test_cookie_fast(host: str, port: int, attribute: str,
                                finding: dict) -> JSONResponse:
    """Cookie-attribute fast path. One HTTPS GET, parse Set-Cookie
    response headers, check whether each cookie carries the named
    attribute. Sub-second. Returns the same JSON envelope as
    _finding_test_header_fast so the modal renders identically."""
    import time as _time
    import ssl as _ssl
    import urllib.error as _urlerr
    import urllib.request as _urlreq

    aid = finding.get("assessment_id")
    ua_string = _resolve_assessment_user_agent(aid)
    url = f"https://{host}:{port}/"
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):
            return None

    opener = _urlreq.build_opener(
        _urlreq.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )
    req = _urlreq.Request(url, method="GET", headers={
        "User-Agent": ua_string,
        "Accept": "*/*",
    })

    t_start = _time.monotonic()
    set_cookies: list[str] = []
    status = 0
    err_text = None
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            # get_all preserves multiple Set-Cookie headers (Python's
            # dict-style headers collapses duplicates).
            set_cookies = resp.headers.get_all("set-cookie") or []
    except _urlerr.HTTPError as he:
        status = he.code
        try:
            set_cookies = (he.headers or {}).get_all("set-cookie") or []
        except Exception:
            pass
    except Exception as e:
        err_text = f"{type(e).__name__}: {e}"
    elapsed_ms = int((_time.monotonic() - t_start) * 1000)

    reproduce_curl = f"curl -s -kI -A {ua_string!r} {url}"
    cmd_label = (f"GET {url} (cookie-attribute fast path: {attribute})")

    if err_text:
        return JSONResponse({
            "ok": True, "kind": "tls",
            "host": host, "port": port,
            "command": cmd_label, "reproduce_command": reproduce_curl,
            "elapsed_ms": elapsed_ms, "exit_code": -1,
            "flag": "fast-path", "flag_label": cmd_label,
            "testssl_id": f"cookie:{attribute}",
            "verdict": "inconclusive",
            "matched_rows": [{
                "id": f"cookie:{attribute}", "severity": "INFO",
                "finding": (f"HTTPS request failed: {err_text}. "
                            f"Re-test from a browser the analyst trusts."),
            }],
            "stdout_excerpt": "", "stderr_excerpt": err_text,
        })

    if not set_cookies:
        return JSONResponse({
            "ok": True, "kind": "tls",
            "host": host, "port": port,
            "command": cmd_label, "reproduce_command": reproduce_curl,
            "elapsed_ms": elapsed_ms, "exit_code": 0,
            "flag": "fast-path", "flag_label": cmd_label,
            "testssl_id": f"cookie:{attribute}",
            "verdict": "inconclusive",
            "matched_rows": [{
                "id": f"cookie:{attribute}", "severity": "INFO",
                "finding": (f"GET {url} returned no Set-Cookie headers "
                            f"(HTTP {status}). The original finding may "
                            f"have come from a different path — try "
                            f"the manual Challenge form."),
            }],
            "stdout_excerpt": "", "stderr_excerpt": "",
            "response_status": status,
        })

    # Inspect each Set-Cookie value for the named attribute. Tolerant
    # of casing and ordering: `; SameSite=Strict`, `;samesite=lax`,
    # `;HttpOnly`, etc.
    cookie_rows: list[dict] = []
    bad = 0
    for sc in set_cookies:
        # Cookie name is everything before the first '='.
        name = sc.split("=", 1)[0].strip()
        attrs_lower = sc.lower()
        present = False
        if attribute == "httponly":
            present = "httponly" in attrs_lower
        elif attribute == "secure":
            # Secure must be its own attribute, not part of a value
            # like Domain=secure.example. Match `; secure` or
            # `; Secure;`.
            present = bool(re.search(r";\s*secure(\s*;|\s*$)",
                                       attrs_lower))
        elif attribute == "samesite":
            present = "samesite=" in attrs_lower
        if not present:
            bad += 1
        cookie_rows.append({
            "id": f"cookie:{name}",
            "severity": "MEDIUM" if not present else "INFO",
            "finding": (f"Set-Cookie {name!r}: {attribute} "
                         f"{'present' if present else 'MISSING'}. "
                         f"Full value: {sc}"),
        })

    if bad > 0:
        verdict = "reproduced"
        finding_text = (f"{bad} of {len(set_cookies)} cookie(s) "
                        f"lack the {attribute} attribute. The "
                        f"original cookie-{attribute} finding still "
                        f"applies.")
    else:
        verdict = "not_reproduced"
        finding_text = (f"All {len(set_cookies)} cookie(s) carry the "
                        f"{attribute} attribute. The original "
                        f"cookie-{attribute} finding looks remediated.")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label, "reproduce_command": reproduce_curl,
        "elapsed_ms": elapsed_ms, "exit_code": 0,
        "flag": "fast-path", "flag_label": cmd_label,
        "testssl_id": f"cookie:{attribute}",
        "verdict": verdict,
        "matched_rows": cookie_rows or [{
            "id": f"cookie:{attribute}",
            "severity": "MEDIUM" if bad else "INFO",
            "finding": finding_text,
        }],
        "stdout_excerpt": "", "stderr_excerpt": "",
        "response_status": status,
        "summary": finding_text,
    })


def _detect_header_check_target(finding: dict) -> Optional[str]:
    """If the finding's title indicates a missing/weak/misconfigured
    HTTP response header (regardless of source tool), return the
    response header name to inspect. Otherwise None.

    Strategy: testssl is last resort, so we cast a WIDE net for
    header findings. Two passes:
      (1) the existing _HEADER_TITLE_PATTERNS catalog (specific
          phrasings like "missing HSTS", "Clickjacking Protection")
      (2) a fallback that matches a known header NAME anywhere in
          the title — covers nuclei "Weak HTTP Strict-Transport-
          Security", wapiti "Content Security Policy Configuration",
          and any future scanner phrasing that just names the header.
    """
    title = (finding.get("title") or "").strip().lower()
    if not title:
        return None
    # Pass 1: specific phrasings (more precise mappings).
    for pat, header_name in _HEADER_TITLE_PATTERNS:
        if re.search(pat, title, re.IGNORECASE):
            return header_name
    # Pass 2: the response header name appears anywhere in the title.
    # This catches "Content Security Policy Configuration", "Weak
    # HTTP Strict-Transport-Security - Detect", "X-Frame-Options
    # missing", etc. — all of which reduce to "fetch URL, look at
    # header X". Order matters here too: put longer/more-specific
    # names first so e.g. "x-content-type-options" beats "x-frame-
    # options" if a title mentioned both (unlikely but defensive).
    for pat, header_name in [
        (r"\bstrict[-_ ]transport[-_ ]security\b", "strict-transport-security"),
        (r"\bcontent[-_ ]security[-_ ]policy\b",   "content-security-policy"),
        (r"\bx[-_ ]content[-_ ]type[-_ ]options\b", "x-content-type-options"),
        (r"\bx[-_ ]xss[-_ ]protection\b",          "x-xss-protection"),
        (r"\bx[-_ ]frame[-_ ]options\b",           "x-frame-options"),
        (r"\breferrer[-_ ]policy\b",               "referrer-policy"),
        (r"\bpermissions[-_ ]policy\b",            "permissions-policy"),
        (r"\bfeature[-_ ]policy\b",                "feature-policy"),
        (r"\bpublic[-_ ]key[-_ ]pins\b",           "public-key-pins"),
        # CORS / Access-Control headers — analyst usually wants to
        # see the full ACAO/ACAC pair; default to ACAO.
        (r"\baccess[-_ ]control[-_ ]allow[-_ ]origin\b|\bacao\b|\bcors\b",
         "access-control-allow-origin"),
    ]:
        if re.search(pat, title, re.IGNORECASE):
            return header_name
    return None


def _resolve_assessment_user_agent(aid: int) -> str:
    """Resolve the User-Agent the assessment expects its fast-path
    probes to send. Mirrors scripts/orchestrator.py:686-693 so the
    Test / Validate / Quick HTTP probe traffic carries the same UA
    the original scan used (avoids WAF / CDN responding differently
    to a "scanner-shaped" client when we re-test, which would itself
    look like a regression). Falls back to is_default user_agent
    then to a generic Chrome string."""
    if aid:
        a = db.query_one(
            "SELECT user_agent_id FROM assessments WHERE id=%s", (aid,))
        if a and a.get("user_agent_id"):
            ua_row = db.query_one(
                "SELECT user_agent FROM user_agents WHERE id=%s",
                (a["user_agent_id"],))
            if ua_row and (ua_row.get("user_agent") or "").strip():
                return ua_row["user_agent"].strip()
    ua_row = db.query_one(
        "SELECT user_agent FROM user_agents WHERE is_default=1 LIMIT 1")
    if ua_row and (ua_row.get("user_agent") or "").strip():
        return ua_row["user_agent"].strip()
    return ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")


# Header-shape testssl IDs (HSTS / security headers / Server banner)
# that can be answered from one HTTPS request. Same idea as
# _CERT_FAST_TESTSSL_IDS — testssl.sh -h takes 30-60s to do what
# `curl -I` does in <200 ms. Each id maps to the response header that
# determines the verdict; "presence" alone flips a *_missing finding to
# not_reproduced. Aliases for enhanced_testing's `config_*_missing`
# probe IDs are included so the same fast path works for findings that
# came from that source tool too. Lowercase keys: matched
# case-insensitively.
_HEADER_FAST_ID_TO_HEADER: dict[str, str] = {
    # testssl native IDs
    "hsts":                    "strict-transport-security",
    "hsts_subdomains":         "strict-transport-security",
    "hsts_preload":            "strict-transport-security",
    "hsts_time":               "strict-transport-security",
    "hpkp":                    "public-key-pins",
    "x-frame-options":         "x-frame-options",
    "xfo":                     "x-frame-options",
    "x-content-type-options":  "x-content-type-options",
    "xcto":                    "x-content-type-options",
    "x-xss-protection":        "x-xss-protection",
    "content-security-policy": "content-security-policy",
    "csp":                     "content-security-policy",
    "referrer-policy":         "referrer-policy",
    "permissions-policy":      "permissions-policy",
    "feature-policy":          "feature-policy",
    "banner_server":           "server",
    "banner_application":      "x-powered-by",
    # enhanced_testing aliases (config_*_missing)
    "config_hsts_missing":            "strict-transport-security",
    "config_csp_missing":             "content-security-policy",
    "config_xfo_missing":             "x-frame-options",
    "config_xcto_missing":            "x-content-type-options",
    "config_referrer_policy_missing": "referrer-policy",
    "config_permissions_policy_missing": "permissions-policy",
    "config_xss_protection_missing":  "x-xss-protection",
    # testssl `security_headers` is a multi-header check ("are any of the
    # common ones present"). The header-fast renderer reports
    # whichever single header it's keyed on, plus the full Set-Cookie
    # / response-header dump in matched_rows so the analyst still sees
    # the other headers. Default the check to HSTS as the most asked-
    # for; the response-headers list in the modal answers the rest.
    "security_headers":               "strict-transport-security",
    # IP address leak in response headers — same urllib fetch surfaces
    # the headers; the analyst spots the IP in the rendered table.
    "ipv4_in_header":                 "server",
}
_HEADER_FAST_TESTSSL_IDS = set(_HEADER_FAST_ID_TO_HEADER.keys())


# Cert-shape testssl IDs that can be answered from a single TLS handshake
# + leaf-cert parse. Routing through testssl.sh for these would take ~30s
# for a question that's actually <200 ms when we just open a TLS socket
# and read the cert directly. The fast path in _finding_test_cert_fast
# returns the same JSON contract _finding_test_tls would have produced
# (kind=tls, verdict, matched_rows, host, port, command, elapsed_ms) so
# the modal doesn't need to know which branch ran.
_CERT_FAST_TESTSSL_IDS = {
    # SAN / hostname-shape findings
    "cert_trust_wildcard",
    "cert_subjectAltName",
    "cert_commonName",
    "cert_commonName_wo_SAN",
    # Validity-window findings
    "cert_extlifeSpan",
    "cert_notAfter",
    "cert_notBefore",
    "cert_validityPeriod",
    "cert_expirationStatus",
    # Algorithm / key-strength findings
    "cert_signatureAlgorithm",
    "cert_keySize",
    # Self-signed / chain-shape findings answerable from the leaf alone
    "cert_chain_of_trust",
}


# Map testssl protocol-availability IDs → openssl s_client flag.
_PROTOCOL_TESTSSL_TO_OPENSSL_FLAG: dict[str, str] = {
    "SSLv2":  "-ssl2",
    "SSLv3":  "-ssl3",
    "TLS1":   "-tls1",
    "TLS1_1": "-tls1_1",
    "TLS1_2": "-tls1_2",
    "TLS1_3": "-tls1_3",
}

# testssl cipherlist_<NAME> suffixes that map cleanly to OpenSSL cipher
# strings recognized by `openssl s_client -cipher <NAME>`. Each is a
# category of weak/legacy ciphers — a successful handshake under that
# string proves the server still offers at least one cipher in the
# category, which is the same claim the testssl row makes.
_CIPHERLIST_OPENSSL_NAME: dict[str, str] = {
    "NULL":      "NULL:eNULL",
    "aNULL":     "aNULL",
    "EXPORT":    "EXPORT",
    "LOW":       "LOW",
    "DES":       "DES:!eDES",
    "3DES":      "3DES",
    "RC4":       "RC4",
    "MD5":       "MD5",
    "MEDIUM":    "MEDIUM",
    # testssl `cipherlist_OBSOLETED` rolls up SSLv2/3 + RC4 + EXPORT
    # + NULL + LOW into one row. The OpenSSL "obsolete" alias is the
    # closest single string; if any handshake under that succeeds,
    # the server still offers something in the obsolete bucket.
    "OBSOLETED": "DEFAULT:!HIGH:!MEDIUM:!ECDH:!DH",
    # `cipherlist_3DES_IDEA` is a combined check; either offered =
    # finding reproduced. IDEA is rarely shipped in modern openssl
    # so the check effectively reduces to 3DES, but try both.
    "3DES_IDEA": "3DES:IDEA",
}


# Vulnerability-check IDs whose claim reduces to "the server still
# accepts protocol P with cipher class C". Each maps to one openssl
# s_client handshake attempt — sub-second answer instead of a 60-180 s
# testssl.sh -U narrowing run. Order matters only for documentation;
# dispatch is by exact id match. Anything not in this map (HEARTBLEED,
# ROBOT, TICKETBLEED, CCS_INJECTION, CRIME_TLS) genuinely needs the
# testssl path because verification requires timing analysis or
# protocol-level injection that openssl alone can't do.
#
# `cipher` is the OpenSSL cipher string that selects the vulnerable
# class — a successful handshake under it = vulnerable. `protocol`
# is the openssl flag (`-tls1`, `-ssl3`, etc.); None means use
# default protocol negotiation.
_VULN_FAST_TESTSSL_PROBES: dict[str, dict] = {
    # CBC-mode + TLS 1.0/1.1: BEAST applies. CVE-2011-3389.
    "BEAST_CBC_TLS1":   {"protocol": "-tls1",   "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.0 with CBC cipher (AES128-SHA)"},
    "BEAST_CBC_TLS1_1": {"protocol": "-tls1_1", "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.1 with CBC cipher (AES128-SHA)"},
    # SSLv3 + any cipher: POODLE oracle. CVE-2014-3566.
    "POODLE_SSL":       {"protocol": "-ssl3",   "cipher": None,
                          "needs_legacy": True,
                          "human": "SSLv3 (any cipher)"},
    # TLS 1.0/1.1 + CBC: LUCKY13 timing oracle. CVE-2013-0169.
    "LUCKY13":          {"protocol": "-tls1",   "cipher": "AES128-SHA",
                          "needs_legacy": True,
                          "human": "TLS 1.0 with CBC cipher (LUCKY13 surface)"},
    # EXPORT cipher offered → FREAK reproducible. CVE-2015-0204.
    "FREAK":            {"protocol": None,      "cipher": "EXPORT",
                          "needs_legacy": True,
                          "human": "EXPORT-grade cipher"},
    # SSLv2 still negotiable → DROWN cross-protocol downgrade attack.
    # CVE-2016-0800.
    "DROWN":            {"protocol": "-ssl2",   "cipher": None,
                          "needs_legacy": True,
                          "human": "SSLv2 negotiation (DROWN surface)"},
    # EXPORT-grade DHE cipher offered → LOGJAM downgrade attack.
    # CVE-2015-4000.
    "LOGJAM":           {"protocol": None,      "cipher": "kEDH+EXPORT",
                          "needs_legacy": True,
                          "human": "EXPORT-grade DHE cipher (LOGJAM)"},
    # Anonymous DH offered → trivially MITMable.
    "ADH":              {"protocol": None,      "cipher": "ADH",
                          "needs_legacy": True,
                          "human": "anonymous DH (ADH) cipher"},
}


def _finding_test_vuln_fast(host: str, port: int, testssl_id: str,
                              finding: dict) -> JSONResponse:
    """Vulnerability-check fast path. Each ID in _VULN_FAST_TESTSSL_PROBES
    maps to one openssl s_client handshake attempt that reproduces (or
    refutes) the testssl claim in <100 ms. Same JSON envelope as the
    other fast paths so the modal renders identically."""
    import subprocess as _subprocess
    import time as _time
    import os as _os

    spec = _VULN_FAST_TESTSSL_PROBES.get(testssl_id)
    if not spec:
        return JSONResponse({
            "ok": False, "error": "no_vuln_spec",
            "message": f"testssl id {testssl_id!r} not in vuln-fast map.",
        }, status_code=500)

    use_legacy = spec.get("needs_legacy", False)
    binary = _LEGACY_OPENSSL if use_legacy else "/usr/bin/openssl"
    env = _os.environ.copy()
    if use_legacy:
        env["OPENSSL_CONF"] = ""

    cmd = [binary, "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-brief"]
    if spec.get("protocol"):
        cmd.append(spec["protocol"])
    if spec.get("cipher"):
        cmd.extend(["-cipher", spec["cipher"]])

    reproduce = (("OPENSSL_CONF= " if use_legacy else "")
                 + " ".join(cmd) + " < /dev/null")

    t0 = _time.monotonic()
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=8.0, check=False, env=env, input="",
        )
        rc = proc.returncode
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except _subprocess.TimeoutExpired:
        rc = -1
        out = "openssl s_client timed out after 8s"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    handshake_ok = (rc == 0 and "CONNECTION ESTABLISHED" in out)
    # Pull the negotiated protocol + cipher for the verdict text — the
    # analyst needs to see the actual combo the server accepted, not
    # just "ok".
    negotiated_proto = ""
    negotiated_cipher = ""
    for line in out.splitlines():
        if line.startswith("Protocol version:"):
            negotiated_proto = line.split(":", 1)[1].strip()
        elif line.startswith("Ciphersuite:"):
            negotiated_cipher = line.split(":", 1)[1].strip()

    if handshake_ok:
        verdict = "reproduced"
        # BEAST/POODLE/LUCKY13/FREAK are all MEDIUM in modern triage —
        # the underlying weaknesses exist but exploitation requires
        # specific MITM positioning. Severity is preserved on the
        # finding row; this is just the matched_rows severity for the
        # modal table.
        severity_out = "MEDIUM"
        finding_text = (f"{testssl_id} reproduced — server accepted "
                        f"a handshake under {spec['human']}. "
                        f"Negotiated: protocol={negotiated_proto!r}, "
                        f"cipher={negotiated_cipher!r}. "
                        f"The original testssl finding still applies.")
    else:
        verdict = "not_reproduced"
        severity_out = "INFO"
        # Pull the openssl error reason out for the analyst.
        reason = ""
        for line in out.splitlines():
            if "no protocols available" in line.lower():
                reason = "protocol disabled by server"; break
            if "alert handshake failure" in line.lower():
                reason = "server refused handshake (no shared cipher)"; break
            if "wrong version number" in line.lower():
                reason = "protocol disabled / refused"; break
            if "alert protocol version" in line.lower():
                reason = "server refused via TLS alert"; break
        if not reason:
            reason = f"handshake failed (exit {rc})"
        finding_text = (f"{testssl_id} no longer reproducible — "
                        f"server refused {spec['human']}: {reason}. "
                        f"Original testssl finding looks remediated.")

    cmd_label = (f"openssl s_client {' '.join(cmd[3:])} "
                 f"({'legacy' if use_legacy else 'system'} openssl)")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label,
        "reproduce_command": reproduce,
        "elapsed_ms": elapsed_ms, "exit_code": rc,
        "flag": spec.get("protocol", "default"),
        "flag_label": cmd_label,
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [{
            "id": testssl_id,
            "severity": severity_out,
            "finding": finding_text,
        }],
        "stdout_excerpt": out[:1500],
        "stderr_excerpt": "",
    })


def _finding_test_protocol_fast(host: str, port: int, testssl_id: str,
                                  finding: dict) -> JSONResponse:
    """Single-protocol availability check via openssl s_client. Sub-
    second per probe vs ~60-90 s for testssl.sh -p. Successful TLS
    handshake = protocol enabled = the original testssl row still
    holds. Picks the bundled testssl-shipped openssl 1.0.2 binary for
    deprecated protocols (SSLv2/3, TLS1.0/1.1) the system openssl
    refuses to even attempt at build time."""
    import subprocess as _subprocess
    import time as _time
    import os as _os

    flag = _PROTOCOL_TESTSSL_TO_OPENSSL_FLAG.get(testssl_id)
    if not flag:
        return JSONResponse({
            "ok": False, "error": "no_protocol_flag",
            "message": f"testssl id {testssl_id!r} not in protocol map.",
        }, status_code=500)

    # System openssl 3.x refuses SSLv2/3/TLS1.0/1.1 — use the bundled
    # 1.0.2 binary for those, with OPENSSL_CONF emptied (the default
    # config tries to load providers that aren't shipped).
    use_legacy = testssl_id in _LEGACY_PROTOCOL_IDS
    binary = _LEGACY_OPENSSL if use_legacy else "/usr/bin/openssl"
    env = _os.environ.copy()
    if use_legacy:
        env["OPENSSL_CONF"] = ""

    cmd = [binary, "s_client", "-connect", f"{host}:{port}",
           flag, "-servername", host, "-brief"]
    reproduce = (("OPENSSL_CONF= " if use_legacy else "")
                 + " ".join(cmd) + " < /dev/null")

    t0 = _time.monotonic()
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=8.0, check=False, env=env,
            input="",   # close stdin so s_client returns immediately
                          # after the handshake instead of waiting for input
        )
        rc = proc.returncode
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except _subprocess.TimeoutExpired:
        rc = -1
        out = "openssl s_client timed out after 8s"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    # openssl s_client exits 0 on a successful handshake, non-zero
    # otherwise. CONNECTION ESTABLISHED appears only on success in
    # -brief output.
    handshake_ok = (rc == 0 and "CONNECTION ESTABLISHED" in out)
    if handshake_ok:
        verdict = "reproduced"
        severity_out = "MEDIUM"
        finding_text = (f"Server still negotiates {testssl_id} — "
                        f"openssl s_client {flag} completed a TLS "
                        f"handshake. The original protocol-enabled "
                        f"finding is reproduced.")
    else:
        verdict = "not_reproduced"
        severity_out = "INFO"
        # Pull the OpenSSL error reason out of the output if we can
        # find one — helps the analyst understand why it refused.
        reason = ""
        for line in out.splitlines():
            if "no protocols available" in line.lower():
                reason = "server refused (protocol disabled)"
                break
            if "wrong version number" in line.lower():
                reason = "server refused (protocol disabled)"
                break
            if "alert protocol version" in line.lower():
                reason = "server refused via alert (protocol disabled)"
                break
        if not reason:
            reason = f"handshake failed (exit {rc})"
        finding_text = (f"Server no longer negotiates {testssl_id} — "
                        f"{reason}. Protocol-enabled finding "
                        f"appears remediated.")

    cmd_label = (f"openssl s_client {flag} {host}:{port} "
                 f"({'legacy' if use_legacy else 'system'} openssl)")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label,
        "reproduce_command": reproduce,
        "elapsed_ms": elapsed_ms, "exit_code": rc,
        "flag": flag,
        "flag_label": cmd_label,
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [{
            "id": testssl_id,
            "severity": severity_out,
            "finding": finding_text,
        }],
        "stdout_excerpt": out[:1500],
        "stderr_excerpt": "",
    })


def _finding_test_cipher_fast(host: str, port: int, testssl_id: str,
                                finding: dict) -> JSONResponse:
    """Single-cipher availability check via openssl s_client -cipher.
    Sub-second per probe vs ~60-90 s for testssl.sh narrow run.
    Successful handshake = cipher offered = original testssl row
    still holds. Uses bundled openssl for legacy ciphers (NULL,
    EXPORT, LOW, DES, RC4, etc.) that the system openssl won't even
    attempt."""
    import subprocess as _subprocess
    import time as _time
    import os as _os

    # testssl_id looks like cipherlist_NULL / cipherlist_3DES / etc.
    # — pull the suffix and map to an openssl cipher string.
    if not testssl_id.startswith("cipherlist_"):
        return JSONResponse({
            "ok": False, "error": "not_cipherlist_id",
            "message": f"testssl id {testssl_id!r} is not a "
                        "cipherlist_* check.",
        }, status_code=500)
    suffix = testssl_id[len("cipherlist_"):]
    cipher_str = _CIPHERLIST_OPENSSL_NAME.get(suffix)
    if not cipher_str:
        return JSONResponse({
            "ok": False, "error": "unknown_cipherlist",
            "message": f"cipherlist suffix {suffix!r} has no openssl mapping.",
        }, status_code=500)

    use_legacy = suffix in _LEGACY_CIPHER_NAMES
    binary = _LEGACY_OPENSSL if use_legacy else "/usr/bin/openssl"
    env = _os.environ.copy()
    if use_legacy:
        env["OPENSSL_CONF"] = ""

    cmd = [binary, "s_client", "-connect", f"{host}:{port}",
           "-cipher", cipher_str,
           "-servername", host, "-brief"]
    reproduce = (("OPENSSL_CONF= " if use_legacy else "")
                 + " ".join(cmd) + " < /dev/null")

    t0 = _time.monotonic()
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=8.0, check=False, env=env, input="",
        )
        rc = proc.returncode
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except _subprocess.TimeoutExpired:
        rc = -1
        out = "openssl s_client timed out after 8s"
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    handshake_ok = (rc == 0 and "CONNECTION ESTABLISHED" in out)
    # Try to surface the negotiated ciphersuite from -brief output —
    # makes the verdict text much more useful than "handshake ok".
    negotiated = ""
    for line in out.splitlines():
        if line.startswith("Ciphersuite:") or "Cipher    :" in line:
            negotiated = line.strip()
            break

    if handshake_ok:
        verdict = "reproduced"
        severity_out = "HIGH" if suffix in {"NULL", "aNULL", "EXPORT",
                                              "DES", "RC4"} else "MEDIUM"
        finding_text = (f"Server still offers a cipher in the {suffix} "
                        f"category. {negotiated or 'Handshake succeeded.'} "
                        f"The {testssl_id} finding is reproduced.")
    else:
        verdict = "not_reproduced"
        severity_out = "INFO"
        reason = ""
        for line in out.splitlines():
            if "handshake failure" in line.lower():
                reason = "TLS handshake failure (no shared cipher)"
                break
            if "no cipher match" in line.lower():
                reason = ("local openssl could not assemble the cipher "
                          "list — try the full Challenge for a deeper "
                          "check")
                break
        if not reason:
            reason = f"handshake refused (exit {rc})"
        finding_text = (f"Server no longer offers any cipher in the "
                        f"{suffix} category — {reason}. Finding looks "
                        f"remediated.")

    cmd_label = (f"openssl s_client -cipher {cipher_str} {host}:{port} "
                 f"({'legacy' if use_legacy else 'system'} openssl)")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label,
        "reproduce_command": reproduce,
        "elapsed_ms": elapsed_ms, "exit_code": rc,
        "flag": "-cipher",
        "flag_label": cmd_label,
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [{
            "id": testssl_id,
            "severity": severity_out,
            "finding": finding_text,
        }],
        "stdout_excerpt": out[:1500],
        "stderr_excerpt": "",
    })


def _finding_test_cipher_enum_fast(host: str, port: int,
                                     testssl_id: str,
                                     finding: dict) -> JSONResponse:
    """Full cipher-suite enumeration via nmap --script ssl-enum-ciphers.
    Empirically ~600 ms vs ~57 s for testssl.sh -e — 95x faster.
    Used for findings whose claim is the overall cipher matrix
    (cipher_negotiated, cipher_x*, cipher_order) rather than a single
    category. Returns the parsed ciphers grouped by TLS protocol so
    the analyst sees exactly what the server still accepts."""
    import subprocess as _subprocess
    import time as _time

    cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port),
           "-Pn", "-n", host]
    reproduce = " ".join(cmd)

    t0 = _time.monotonic()
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=30.0, check=False,
        )
        rc = proc.returncode
        out = proc.stdout or ""
    except _subprocess.TimeoutExpired:
        return JSONResponse({
            "ok": False, "error": "nmap_timeout",
            "message": "nmap ssl-enum-ciphers timed out after 30s.",
        }, status_code=504)
    elapsed_ms = int((_time.monotonic() - t0) * 1000)

    cmd_label = (f"nmap --script ssl-enum-ciphers -p {port} {host}")

    # Parse nmap's output. The script emits sections like:
    #     | ssl-enum-ciphers:
    #     |   TLSv1.0:
    #     |     ciphers:
    #     |       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
    #     ...
    weak_count = 0
    section_lines: list[str] = []
    for line in out.splitlines():
        if "ssl-enum-ciphers" in line or line.startswith("|"):
            section_lines.append(line)
            # Cipher lines that grade C, D, or F are weak.
            if line.rstrip().endswith(("- C", "- D", "- F")):
                weak_count += 1

    verdict = "reproduced" if weak_count > 0 else "not_reproduced"
    severity_out = "MEDIUM" if weak_count > 0 else "INFO"
    finding_text = (f"nmap ssl-enum-ciphers completed; {weak_count} "
                    f"cipher(s) scored C/D/F. Full output below.")

    return JSONResponse({
        "ok": True, "kind": "tls",
        "host": host, "port": port,
        "command": cmd_label,
        "reproduce_command": reproduce,
        "elapsed_ms": elapsed_ms, "exit_code": rc,
        "flag": "--script ssl-enum-ciphers",
        "flag_label": cmd_label,
        "testssl_id": testssl_id,
        "verdict": verdict,
        "matched_rows": [{
            "id": testssl_id,
            "severity": severity_out,
            "finding": finding_text,
        }],
        "stdout_excerpt": "\n".join(section_lines)[:3000] or out[:3000],
        "stderr_excerpt": "",
    })


def _finding_test_tls(finding: dict, parsed) -> JSONResponse:
    """Verify a testssl-source finding by re-checking the live TLS
    posture. For cert-shape check IDs (see _CERT_FAST_TESTSSL_IDS) we
    short-circuit to a direct TLS handshake — sub-second instead of the
    ~30s a narrow testssl.sh -S run takes. Anything outside that set
    falls through to the existing testssl.sh path below.

    The testssl.sh path is bounded by:
      * subprocess timeout (180s — narrow flags finish in <30s typical
        for ciphers/cert work, but the vulnerability suite (-U) on a
        slow target can hit 90-120s; the previous 90s cap was too
        tight and caused intermittent timeouts on real workloads),
      * single testssl invocation per click (rate-limited by caller),
      * jsonfile-pretty output captured to a tmp path under /tmp,
        cleaned up regardless of exit code.
    """
    import subprocess as _subprocess
    import tempfile as _tempfile
    import os as _os

    raw = finding.get("raw") or {}
    testssl_id = raw.get("id") or finding.get("title") or ""

    host = (parsed.hostname or "").lower()
    port = parsed.port or 443

    # Fast path: header-presence IDs answered from a single HTTPS GET.
    # Lowercased lookup so variants like "HSTS" and "hsts" both match.
    if testssl_id and testssl_id.lower() in _HEADER_FAST_TESTSSL_IDS:
        return _finding_test_header_fast(host, port, testssl_id, finding)

    # Fast path: cert-shape IDs answered from the leaf cert.
    if testssl_id in _CERT_FAST_TESTSSL_IDS:
        return _finding_test_cert_fast(host, port, testssl_id, finding)

    # Fast path: protocol-availability IDs answered with one openssl
    # s_client handshake attempt. ~80 ms per check vs ~60-90 s for
    # testssl.sh -p. Bundled openssl 1.0.2 is used for SSLv2/3 +
    # TLS1.0/1.1 because system openssl 3.x removes deprecated
    # protocols at build time.
    if testssl_id in _PROTOCOL_TESTSSL_TO_OPENSSL_FLAG:
        return _finding_test_protocol_fast(host, port, testssl_id, finding)

    # Fast path: cipherlist_<NAME> IDs answered with one openssl
    # s_client -cipher attempt. Bundled openssl is used for legacy
    # categories (NULL, EXPORT, LOW, DES, RC4) the system build
    # doesn't carry.
    if (testssl_id.startswith("cipherlist_")
            and testssl_id[len("cipherlist_"):] in _CIPHERLIST_OPENSSL_NAME):
        return _finding_test_cipher_fast(host, port, testssl_id, finding)

    # Fast path: full cipher-suite enumeration via nmap. ~600 ms vs
    # ~57 s for testssl.sh -e. Used when the testssl row is about the
    # overall cipher matrix. testssl IDs in this class:
    #   cipher_negotiated, cipher_order, cipher_order-tls1,
    #   cipher_order-tls1_1, cipher_order-tls1_2, cipher_order-tls1_3
    # The earlier `startswith("cipher_x")` check was dead — actual IDs
    # use `cipher-tls1_2_x35` (hyphen + protocol + suffix), not
    # `cipher_x*`. Those individual-cipher IDs go to the single-cipher
    # path further down (regex match on the protocol-aware shape).
    if (testssl_id == "cipher_negotiated"
            or testssl_id == "cipher_order"
            or testssl_id.startswith("cipher_order-tls1")):
        return _finding_test_cipher_enum_fast(host, port, testssl_id, finding)

    # Fast path: single-cipher availability via openssl s_client. testssl
    # emits per-cipher IDs of shape `cipher-tls1_X_x<HEX>` (or
    # `cipher-tls1_x<HEX>` for TLS 1.0); each one asks "is this exact
    # cipher offered?" Matching by regex instead of an explicit table
    # because there are ~50 cipher IDs and they evolve with each
    # testssl release. The hex suffix is the IANA cipher-id which we
    # could decode to a name, but openssl's name strings are easier
    # to drive and a successful handshake on the protocol alone is
    # enough to reproduce the original finding (the cipher is offered
    # on that protocol — what testssl was claiming).
    if re.match(r"^cipher-tls1(?:_[123])?_x[0-9a-fA-F]+$", testssl_id):
        return _finding_test_cipher_enum_fast(host, port, testssl_id, finding)

    # Fast path: vulnerability-class IDs whose verification reduces to
    # one openssl handshake attempt (BEAST_CBC_TLS1, BEAST_CBC_TLS1_1,
    # POODLE_SSL, LUCKY13, FREAK). HEARTBLEED, ROBOT, TICKETBLEED,
    # CCS_INJECTION, CRIME_TLS still genuinely need testssl below.
    if testssl_id in _VULN_FAST_TESTSSL_PROBES:
        return _finding_test_vuln_fast(host, port, testssl_id, finding)

    flag, flag_label = _pick_testssl_flag(testssl_id)
    target = f"{host}:{port}"

    fd, json_path = _tempfile.mkstemp(prefix="ngd_test_tls_", suffix=".json")
    _os.close(fd)
    # --jsonfile (flat list of {id, severity, finding, ...} rows) — same
    # shape the orchestrator already parses in scripts/orchestrator.py.
    # The --jsonfile-pretty form wraps everything in a top-level dict
    # under scanResult, which would force a second parsing pass for no
    # value here.
    cmd = ["testssl.sh", flag,
           "--quiet", "--color", "0", "--warnings", "off",
           "--openssl-timeout", "10", "--socket-timeout", "10",
           "--jsonfile", json_path,
           target]

    t_start = time.monotonic()
    proc_stdout = ""
    proc_stderr = ""
    proc_rc = -1
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=180.0, check=False,
        )
        proc_stdout = proc.stdout or ""
        proc_stderr = proc.stderr or ""
        proc_rc = proc.returncode
    except _subprocess.TimeoutExpired:
        return JSONResponse({
            "ok": False, "error": "tls_timeout",
            "message": ("testssl.sh timed out after 180s. Try the manual "
                        "Challenge form on the full detail page if you "
                        "need a deeper run, or use the Quick HTTP probe "
                        "button for a fast sanity check."),
        }, status_code=504)
    except Exception as e:
        return JSONResponse({
            "ok": False, "error": "tls_runtime",
            "message": f"{type(e).__name__}: {e}",
        }, status_code=502)
    finally:
        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                report_text = fh.read()
        except OSError:
            report_text = ""
        try:
            _os.unlink(json_path)
        except OSError:
            pass
    elapsed_ms = int((time.monotonic() - t_start) * 1000)

    rows: list[dict] = []
    try:
        rows = json.loads(report_text or "[]")
        if not isinstance(rows, list):
            rows = []
    except Exception:
        rows = []

    # Filter to rows for the original check id (and any sibling row
    # whose id contains the original — testssl sometimes nests results,
    # e.g. cipherlist_aNULL is reported alongside cipherlist_NULL).
    matched: list[dict] = []
    if testssl_id:
        for r in rows:
            if not isinstance(r, dict):
                continue
            rid = (r.get("id") or "").strip()
            if rid == testssl_id:
                matched.append(r)
        # If nothing matched the exact id, surface every row from the
        # narrow flag run — the analyst still wants to see what the
        # current TLS posture looks like.
        if not matched:
            matched = [r for r in rows if isinstance(r, dict)][:50]
    else:
        matched = [r for r in rows if isinstance(r, dict)][:50]

    # Verdict heuristic — mirror the analyst's reading:
    #   * any matched row whose finding text indicates the issue is
    #     present (offered, deprecated, vulnerable, no, missing)
    #     → reproduced
    #   * any matched row that says "not offered" / "ok" / "fine"
    #     → not reproduced
    #   * else inconclusive
    BAD_PATTERNS = ("offered", "deprecated", "vulnerable",
                    "not ok", "weak", "obsolete")
    GOOD_PATTERNS = ("not offered", "not vulnerable", "ok ", "fine ",
                     "supported", "passed")
    verdict = "inconclusive"
    for r in matched:
        ftxt = (r.get("finding") or "").lower()
        sev = (r.get("severity") or "").upper()
        if sev in ("HIGH", "CRITICAL", "MEDIUM") and any(
                p in ftxt for p in BAD_PATTERNS):
            verdict = "reproduced"
            break
        if any(p in ftxt for p in GOOD_PATTERNS):
            verdict = "not_reproduced"
    if verdict == "inconclusive" and matched:
        # Severity uplift alone — testssl's own severity is enough to
        # call something reproduced even when the finding text is
        # phrased neutrally.
        if any((r.get("severity") or "").upper() in ("HIGH", "CRITICAL")
               for r in matched):
            verdict = "reproduced"

    return JSONResponse({
        "ok": True,
        "kind": "tls",
        "host": host,
        "port": port,
        "command": " ".join(cmd),
        "elapsed_ms": elapsed_ms,
        "exit_code": proc_rc,
        "flag": flag,
        "flag_label": flag_label,
        "testssl_id": testssl_id,
        "verdict": verdict,    # 'reproduced' | 'not_reproduced' | 'inconclusive'
        "matched_rows": matched[:20],
        "stdout_excerpt": (proc_stdout or "")[:8000],
        "stderr_excerpt": (proc_stderr or "")[:2000],
    })


# Nuclei template-id format guard. nuclei template ids are conventionally
# kebab-case lowercase ASCII (tech-detect, CVE-2021-1234, sql-injection,
# etc.) — anything else risks shell metacharacter shenanigans. We refuse
# anything outside this character set rather than escaping it, since a
# valid id will never need escaping in the first place.
_NUCLEI_TEMPLATE_ID_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,128}$")


def _finding_test_nuclei(finding: dict, url: str) -> JSONResponse:
    """Re-run nuclei narrowly with the finding's template-id against
    the finding's URL and return the matched events.

    Run is bounded by:
      * subprocess timeout (60s — single-template runs finish in <15s
        typical),
      * one nuclei invocation per click (rate-limited by caller),
      * jsonl output captured to a tmp path under /tmp, cleaned up
        regardless of exit code.

    Same JSON envelope as _finding_test_tls so the modal can render
    both kinds of test results identically: kind, host, port, command,
    elapsed_ms, exit_code, verdict ('reproduced' / 'not_reproduced' /
    'inconclusive'), matched_rows, stdout/stderr excerpts.

    The verdict is decided on whether nuclei emitted any matched event
    for the template — if the matcher fired again, the original finding
    reproduces; if nuclei ran cleanly but emitted nothing, the matcher
    no longer fires (likely the underlying tech / config has changed).
    """
    import subprocess as _subprocess
    import tempfile as _tempfile
    import os as _os

    raw = finding.get("raw") or {}
    template_id = (raw.get("template-id") or "").strip()
    matcher_name = (raw.get("matcher-name") or "").strip()

    if not _NUCLEI_TEMPLATE_ID_RE.match(template_id):
        return JSONResponse({
            "ok": False, "error": "bad_template_id",
            "message": (f"Template id {template_id!r} does not match the "
                        "expected nuclei id format and was rejected as "
                        "an extra precaution."),
        }, status_code=400)

    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    fd, jsonl_path = _tempfile.mkstemp(prefix="ngd_test_nuclei_", suffix=".jsonl")
    _os.close(fd)
    # -id <template-id>     run only the matching template(s)
    # -u <url>              single target, no scope expansion
    # -jsonl-export <path>  write structured events for parsing
    # -silent               no banner / progress noise on stdout
    # -no-color             plain text, no ANSI in stderr / logs
    # -disable-update-check skip the network round-trip to GitHub
    # -timeout 10           per-request timeout
    # -rl 20 -c 5           rate-limit + concurrency low — single-target
    cmd = ["nuclei",
           "-u", url,
           "-id", template_id,
           "-jsonl-export", jsonl_path,
           "-silent", "-no-color",
           "-disable-update-check",
           "-timeout", "10",
           "-rl", "20", "-c", "5"]

    t_start = time.monotonic()
    proc_stdout = ""
    proc_stderr = ""
    proc_rc = -1
    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=60.0, check=False,
        )
        proc_stdout = proc.stdout or ""
        proc_stderr = proc.stderr or ""
        proc_rc = proc.returncode
    except _subprocess.TimeoutExpired:
        return JSONResponse({
            "ok": False, "error": "nuclei_timeout",
            "message": ("nuclei timed out after 60s. Try the manual "
                        "Challenge form on the full detail page if you "
                        "need a deeper run."),
        }, status_code=504)
    except FileNotFoundError:
        return JSONResponse({
            "ok": False, "error": "nuclei_missing",
            "message": "nuclei binary is not available in this container.",
        }, status_code=500)
    except Exception as e:
        return JSONResponse({
            "ok": False, "error": "nuclei_runtime",
            "message": f"{type(e).__name__}: {e}",
        }, status_code=502)
    finally:
        try:
            with open(jsonl_path, "r", encoding="utf-8", errors="replace") as fh:
                report_text = fh.read()
        except OSError:
            report_text = ""
        try:
            _os.unlink(jsonl_path)
        except OSError:
            pass
    elapsed_ms = int((time.monotonic() - t_start) * 1000)

    # Each line of the jsonl export is one matched event. Parse and
    # synthesize a row that mirrors what _finding_test_tls produces so
    # the existing modal table can render it without a special case.
    rows: list[dict] = []
    for line in (report_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        info = event.get("info") or {}
        rows.append({
            "id": event.get("template-id") or "",
            "severity": (info.get("severity") or "info").upper(),
            "finding": (info.get("name")
                        or event.get("matcher-name")
                        or info.get("description")
                        or "matcher fired"),
            # Surface the bits the analyst usually wants in the table:
            # what the matcher saw, where, and any extracted fields.
            "matcher_name": event.get("matcher-name") or "",
            "matched_at": event.get("matched-at") or "",
            "extracted_results": event.get("extracted-results") or [],
        })

    # Filter to rows for the original matcher when the finding had
    # one — nuclei's tech-detect template, for instance, fires once
    # per detected technology; an analyst clicking Test on the
    # 'bootstrap' row only wants to see whether 'bootstrap' still
    # matches, not the whole tech inventory.
    matched: list[dict] = rows
    if matcher_name:
        narrowed = [r for r in rows if r.get("matcher_name") == matcher_name]
        # Only narrow if we still have something — otherwise show all
        # results so the analyst sees whatever did fire.
        if narrowed:
            matched = narrowed

    # Verdict: any matched event ⇒ reproduced. Empty output but a clean
    # exit ⇒ not_reproduced. Anything weirder (non-zero exit + empty
    # output) ⇒ inconclusive.
    if matched:
        verdict = "reproduced"
    elif proc_rc == 0:
        verdict = "not_reproduced"
    else:
        verdict = "inconclusive"

    return JSONResponse({
        "ok": True,
        "kind": "nuclei",
        "host": host,
        "port": port,
        "command": " ".join(cmd),
        "elapsed_ms": elapsed_ms,
        "exit_code": proc_rc,
        "template_id": template_id,
        "matcher_name": matcher_name,
        "verdict": verdict,
        "matched_rows": matched[:20],
        "stdout_excerpt": (proc_stdout or "")[:8000],
        "stderr_excerpt": (proc_stderr or "")[:2000],
    })


def _finding_test_tls_info(parsed) -> JSONResponse:
    """Surface live certificate + handshake info for a TLS-cert finding.

    Runs `openssl s_client -connect host:port -servername host` once,
    pipes the leaf cert through `openssl x509 -text -noout`, and
    extracts the fields an analyst typically wants to see (Subject,
    Issuer, Validity, SAN, Public Key, Signature Algorithm) plus the
    negotiated protocol + cipher. Both binaries ship in the base image
    (the Dockerfile installs openssl); each subprocess is bounded by a
    short timeout. Read-only by definition — opens a TLS connection,
    reads the cert, closes.
    """
    import subprocess as _sp
    import re as _re

    host = parsed.hostname
    port = parsed.port or 443
    s_cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
            "-servername", host, "-showcerts"]

    t_start = time.monotonic()
    try:
        s_proc = _sp.run(
            s_cmd, input=b"\n", capture_output=True, timeout=15,
        )
    except _sp.TimeoutExpired:
        return JSONResponse(
            {"ok": False, "error": "tls_info_timeout",
             "message": "openssl s_client did not return within 15 s."},
            status_code=504)
    except FileNotFoundError:
        return JSONResponse(
            {"ok": False, "error": "openssl_missing",
             "message": "openssl binary is not available in this container."},
            status_code=500)

    handshake = (s_proc.stdout or b"").decode("utf-8", "replace")
    s_stderr = (s_proc.stderr or b"").decode("utf-8", "replace")

    # Pull negotiated protocol + cipher out of the handshake summary.
    proto_m = _re.search(r"^\s*Protocol\s*:\s*(\S+)\s*$", handshake, _re.MULTILINE)
    cipher_m = _re.search(r"^\s*Cipher\s*:\s*(\S+)\s*$", handshake, _re.MULTILINE)
    sni_m = _re.search(r"^\s*Verification:\s*(.+)$", handshake, _re.MULTILINE)

    # Extract every PEM block; the first one is the leaf certificate.
    pem_blocks = _re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        handshake, _re.DOTALL,
    )
    leaf_pem = pem_blocks[0] if pem_blocks else ""
    chain_count = len(pem_blocks)

    # Parse the leaf via `openssl x509 -text -noout`.
    x509_text = ""
    if leaf_pem:
        try:
            x_proc = _sp.run(
                ["openssl", "x509", "-text", "-noout"],
                input=leaf_pem.encode(), capture_output=True, timeout=10,
            )
            x509_text = (x_proc.stdout or b"").decode("utf-8", "replace")
        except Exception:
            x509_text = ""

    # Pluck the fields most useful to an analyst.
    def _pull(rx, default=""):
        m = _re.search(rx, x509_text, _re.MULTILINE)
        return m.group(1).strip() if m else default

    subject = _pull(r"^\s*Subject:\s*(.+)$")
    issuer = _pull(r"^\s*Issuer:\s*(.+)$")
    not_before = _pull(r"^\s*Not Before\s*:\s*(.+)$")
    not_after = _pull(r"^\s*Not After\s*:\s*(.+)$")
    sig_algo = _pull(r"^\s*Signature Algorithm:\s*(.+)$")
    pub_key = _pull(r"^\s*Public Key Algorithm:\s*(.+)$")
    serial = _pull(r"^\s*Serial Number:\s*(.+)$")
    # SAN spans multiple lines after "Subject Alternative Name:"; grab
    # the next non-blank line of DNS entries.
    san = ""
    san_m = _re.search(
        r"X509v3 Subject Alternative Name:\s*(?:critical)?\s*\n\s*(.+?)\n",
        x509_text)
    if san_m:
        san = san_m.group(1).strip()

    elapsed_ms = int((time.monotonic() - t_start) * 1000)
    return JSONResponse({
        "ok": True,
        "kind": "tls_info",
        "host": host,
        "port": port,
        "command": (" ".join(s_cmd) +
                    " </dev/null | openssl x509 -text -noout"),
        "elapsed_ms": elapsed_ms,
        "exit_code": s_proc.returncode,
        "protocol": proto_m.group(1) if proto_m else "",
        "cipher": cipher_m.group(1) if cipher_m else "",
        "verification": sni_m.group(1).strip() if sni_m else "",
        "chain_count": chain_count,
        "cert": {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "san": san,
            "signature_algorithm": sig_algo,
            "public_key_algorithm": pub_key,
            "serial": serial,
        },
        "x509_text_excerpt": (x509_text or "")[:8000],
        "stderr_excerpt": (s_stderr or "")[:1500],
    })


@app.post("/finding/{fid}/test")
def finding_test(request: Request, fid: int):
    """Run the finding's reproduction request once, server-side, with a
    SafeClient locked to the assessment's scope. Returns the response
    as JSON (status, headers, body preview, elapsed time) plus a list
    of indicator strings the modal should mark up.

    Refusals come back as HTTP 4xx with `{ok:false, error, message}`
    so the modal can render a friendly explanation instead of an opaque
    failure. Successful but non-2xx responses (e.g. a 302 to /login.php)
    are still 'ok' from this endpoint's perspective — the analyst is
    the one judging the response.
    """
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    a = db.query_one("SELECT id, fqdn FROM assessments WHERE id = %s",
                     (f.get("assessment_id"),))
    if not a:
        raise HTTPException(404, "owning assessment is gone")

    # Decode raw_data BEFORE _finding_testable so the nuclei branch
    # there can read raw['template-id']. (The other call site of
    # _finding_testable, the finding-detail view, already decodes
    # before calling — that path was fine; only finding_test was
    # checking the testable flag against an undecoded raw field.)
    if f.get("raw_data") and not f.get("raw"):
        try:
            f["raw"] = json.loads(f["raw_data"])
        except Exception:
            f["raw"] = None

    testable, reason, kind = _finding_testable(f, a)
    if not testable:
        return JSONResponse(
            {"ok": False, "error": "not_testable", "message": reason},
            status_code=409)

    # Rate limit. Identify the user by id when authenticated, falling
    # back to client IP for fail-closed behavior. The bucket is in-
    # memory so a container restart resets — that's intentional, an
    # operator who wants to wipe the limit can just restart the app.
    user = current_user(request) or {}
    user_key = str(user.get("id") or
                   (request.client.host if request.client else "anon"))
    over = _test_rate_limit_check(user_key)
    if over is not None:
        return JSONResponse(
            {"ok": False, "error": "rate_limited",
             "message": (f"Too many Test runs in the last "
                         f"{_TEST_RATE_LIMIT_WINDOW_S}s. "
                         f"Try again in {int(over) + 1}s.")},
            status_code=429)

    url = f["evidence_url"]
    method = (f.get("evidence_method") or "GET").upper()

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if _is_private_host(parsed.hostname or ""):
        return JSONResponse(
            {"ok": False, "error": "private_host",
             "message": (f"Hostname {parsed.hostname!r} resolves to a "
                         "private / loopback / link-local IP. Refusing "
                         "to send the request — Test is restricted to "
                         "external assessment targets only.")},
            status_code=409)

    # TLS-flavoured test: testssl-source findings reflect transport
    # posture (cipher list, protocol versions, vuln presence). An HTTP
    # GET against the host wouldn't exercise the same surface, so we
    # re-run testssl.sh with a narrowly scoped flag for the specific
    # check id and surface the JSON row(s) that match.
    if kind == "tls":
        return _finding_test_tls(f, parsed)

    # Tool-agnostic header-missing fast path. Whether the finding came
    # from nikto ("Suggested security header missing: x-frame-options"),
    # wapiti ("HTTP Strict Transport Security (HSTS)"), nuclei ("HTTP
    # Missing Security Headers"), enhanced_testing
    # (config_*_missing), or the LLM ("missing X header") — they all
    # reduce to "fetch the URL once, look at the headers". Route to
    # the verdict-producing _finding_test_header_fast() so the analyst
    # gets "Header X is absent — finding reproduced" instead of a raw
    # HTTP dump they have to eyeball. Wins over nuclei subprocess and
    # the generic HTTP path for these specifically.
    detected_header = _detect_header_check_target(f)
    if detected_header:
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return _finding_test_header_fast(
            host, port, detected_header, f)

    # Same idea for cookie-attribute findings — nuclei "Missing
    # Cookie SameSite", nikto "Cookie X without httponly flag", and
    # the LLM all reduce to "fetch URL, parse Set-Cookie, check the
    # attribute on each cookie." Sub-second urllib path with a
    # cookie-by-cookie verdict table.
    detected_cookie = _detect_cookie_check_target(f)
    if detected_cookie:
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return _finding_test_cookie_fast(
            host, port, detected_cookie, f)

    # Nuclei test: re-run nuclei narrowly with the original template-id
    # so the matcher logic actually executes against the live target.
    # An HTTP GET would just echo the response without telling the
    # analyst whether the same matcher still fires.
    if kind == "nuclei":
        return _finding_test_nuclei(f, url)

    # Cert-info test: surface the live certificate + handshake details
    # for findings whose wording is about TLS / cert posture but whose
    # source tool isn't testssl (e.g. Nikto's "wildcard certificate").
    if kind == "tls_info":
        return _finding_test_tls_info(parsed)

    # One-shot HTTPS fetch via stdlib. The probe SafeClient lives under
    # /app/toolkit/lib and is loaded as a subprocess elsewhere — using
    # it here would entangle two import roots, and we don't need its
    # audit-log machinery for a single request anyway. The safety we
    # need (method, scheme, scope, private-IP, timeout, body cap) is
    # already enforced above.
    import http.client as _httpclient
    import ssl as _ssl
    import urllib.error as _urlerror
    import urllib.request as _urlreq

    BODY_CAP = 256 * 1024
    REQ_TIMEOUT = 10.0

    # Most pentest targets are self-signed / wildcard / internal; same
    # posture every other DAST tool in this stack uses.
    ssl_ctx = _ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = _ssl.CERT_NONE
    https_handler = _urlreq.HTTPSHandler(context=ssl_ctx)
    # Disable redirect following so a 302 → /login.php (a common false
    # signal) is visible in the response, and so we cannot be coerced
    # off the in-scope host by a Location: header.
    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = _urlreq.build_opener(https_handler, _NoRedirect())

    req = _urlreq.Request(url, method=method, headers={
        "User-Agent": "nextgen-dast/2.1.1 (Test button)",
        "Accept": "*/*",
    })
    t_start = time.monotonic()
    status = 0
    body_bytes = b""
    headers_list: list[tuple[str, str]] = []
    err_msg: Optional[str] = None
    try:
        with opener.open(req, timeout=REQ_TIMEOUT) as resp:
            status = resp.status
            headers_list = list(resp.headers.items())
            try:
                body_bytes = resp.read(BODY_CAP + 1)
            except _httpclient.IncompleteRead as ir:
                body_bytes = ir.partial or b""
    except _urlerror.HTTPError as e:
        # 4xx / 5xx still carry a body — surface it the same as a 2xx.
        status = e.code
        headers_list = list((e.headers or {}).items())
        try:
            body_bytes = e.read() or b""
        except _httpclient.IncompleteRead as ir:
            body_bytes = ir.partial or b""
    except _urlerror.URLError as e:
        err_msg = f"network error: {e.reason}"
    except Exception as e:
        err_msg = f"{type(e).__name__}: {e}"
    elapsed_ms = int((time.monotonic() - t_start) * 1000)

    if err_msg is not None:
        return JSONResponse(
            {"ok": False, "error": "request_error",
             "message": err_msg, "elapsed_ms": elapsed_ms},
            status_code=502)

    truncated = len(body_bytes) > BODY_CAP
    body_text = body_bytes[:BODY_CAP].decode("utf-8", "replace")

    return JSONResponse({
        "ok": True,
        "method": method,
        "url": url,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "headers": headers_list,
        "body": body_text,
        "body_size": len(body_bytes),
        "body_truncated": truncated,
        "highlights": _highlight_terms_for(f),
        "indicator": _finding_io_evidence(f).get("indicator") or "",
    })


@app.post("/assessment/{aid}/filter_info")
def assessment_filter_info(aid: int, enabled: Optional[str] = Form(None)):
    """Persist the 'hide info-severity findings' toggle on the assessment
    row. Affects both the on-screen view (immediately) and the next
    generated PDF report. The checkbox auto-submits via JS so this is
    a one-click toggle."""
    a = db.query_one("SELECT id FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    db.execute("UPDATE assessments SET filter_info = %s WHERE id = %s",
               (1 if enabled else 0, aid))
    return redirect(f"/assessment/{aid}")


@app.post("/assessment/{aid}/delete")
def assessment_delete(aid: int):
    """Mark an assessment for deletion; the background sweeper handles the
    actual filesystem removal asynchronously. Returns immediately so big
    scan dirs (16+ GB) don't block the request."""
    a = db.query_one("SELECT id, status FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    # Refuse to delete a still-running scan; user must cancel/wait first.
    if a["status"] == "running":
        raise HTTPException(409, "assessment is still running — cancel it first")
    db.execute(
        "UPDATE assessments SET status='deleting', "
        "current_step='queued for deletion' WHERE id = %s", (aid,))
    return redirect("/assessments?msg=queued+for+deletion")


@app.get("/assessment/{aid}/status")
def assessment_status_json(aid: int):
    a = db.query_one(
        "SELECT id, status, current_step, total_findings, finished_at "
        "FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    return JSONResponse({k: (v.isoformat() if hasattr(v, "isoformat") else v)
                         for k, v in a.items()})


# User-Agent management ------------------------------------------------------

@app.get("/user-agents", response_class=HTMLResponse)
def user_agents_page(request: Request, msg: str = ""):
    rows = (db.query("SELECT id, label, user_agent, is_default, is_seeded "
                     "FROM user_agents ORDER BY is_default DESC, label")
            if db.healthy() else [])
    return templates.TemplateResponse(
        "user_agents.html",
        ctx(request, user_agents=rows, msg=msg),
    )


@app.post("/user-agents")
def user_agents_add(
    label: str = Form(...),
    user_agent: str = Form(...),
    is_default: Optional[str] = Form(None),
):
    label = label.strip()
    user_agent = user_agent.strip()
    if not label or not user_agent:
        raise HTTPException(400, "label and user_agent are required")
    if is_default:
        db.execute("UPDATE user_agents SET is_default = 0")
    db.execute(
        "INSERT INTO user_agents (label, user_agent, is_default, is_seeded) "
        "VALUES (%s, %s, %s, 0) "
        "ON DUPLICATE KEY UPDATE user_agent=VALUES(user_agent), "
        "is_default=VALUES(is_default)",
        (label, user_agent, 1 if is_default else 0),
    )
    return redirect(f"/user-agents?msg=saved+{label}")


@app.post("/user-agents/{uid}/delete")
def user_agents_delete(uid: int):
    db.execute("DELETE FROM user_agents WHERE id = %s", (uid,))
    return redirect("/user-agents?msg=deleted")


@app.post("/user-agents/{uid}/default")
def user_agents_make_default(uid: int):
    db.execute("UPDATE user_agents SET is_default = 0")
    db.execute("UPDATE user_agents SET is_default = 1 WHERE id = %s", (uid,))
    return redirect("/user-agents?msg=default+set")


# Auth ------------------------------------------------------------------------

def _set_session_cookie(response, user: dict) -> None:
    # Each new session carries a fresh CSRF token. Storing it inside
    # the signed cookie payload means the attacker cannot forge a token
    # without also breaking the HMAC, and we do not need a separate
    # cookie or server-side store.
    payload = {"id": user["id"], "username": user["username"],
               "role": user["role"], "csrf": sessions.new_csrf_token()}
    cookie = sessions.sign(payload)
    response.set_cookie(
        key=sessions.COOKIE_NAME, value=cookie,
        max_age=sessions.DEFAULT_TTL,
        path=ROOT_PATH or "/",
        httponly=True, secure=True, samesite="strict",
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "", error: str = ""):
    # Already logged in? Send them on. (Pre-CSRF sessions are filtered
    # out the same way the auth middleware does it.)
    cookie = request.cookies.get(sessions.COOKIE_NAME)
    payload = sessions.verify(cookie)
    if payload and payload.get("csrf"):
        return RedirectResponse(next or f"{ROOT_PATH}/", status_code=303)
    # Pull just enough branding for the login chrome to match the rest of
    # the app (logo + product name). Wrapped in try/except so a DB outage
    # doesn't make the login page itself unreachable — the template hides
    # the <img> with onerror and falls back to "nextgen-dast" for the name.
    try:
        brand = branding_mod.get() if db.healthy() else {}
    except Exception:
        brand = {}
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "base": ROOT_PATH, "next": next,
         "error": error, "brand": brand},
    )


@app.post("/login")
def login_submit(request: Request,
                 username: str = Form(...),
                 password: str = Form(...),
                 next: str = Form("")):
    # Login CSRF defense. The session cookie is SameSite=Strict (see
    # _set_session_cookie), which prevents an attacker-forced session
    # from being used after the fact, but does not stop the login POST
    # itself from being submitted cross-origin. Reject the POST if the
    # browser tells us it came from somewhere other than this host.
    # Non-browser clients (curl, server-to-server) carry no Origin or
    # Referer and are allowed through.
    if not _same_origin(request):
        audit_mod.log_event(
            "login_origin_rejected", ok=False,
            target={"id": None, "username": username},
            ip=client_ip(request),
        )
        raise HTTPException(status_code=403, detail="cross-origin login rejected")
    u = users_mod.authenticate(username, password)
    ip = client_ip(request)
    if not u:
        # Don't disclose whether the username exists; the audit row only
        # carries the attempted username so an operator can correlate.
        audit_mod.log_event(
            "login_failure", ok=False,
            target={"id": None, "username": username},
            ip=ip,
        )
        return RedirectResponse(
            f"{ROOT_PATH}/login?error=Invalid+credentials"
            + (f"&next={next}" if next else ""),
            status_code=303,
        )
    audit_mod.log_event(
        "login_success",
        actor=audit_mod.actor_from_user(u),
        target=audit_mod.actor_from_user(u),
        ip=ip,
    )
    target = next if next.startswith(ROOT_PATH or "/") else f"{ROOT_PATH}/"
    response = RedirectResponse(target, status_code=303)
    _set_session_cookie(response, u)
    return response


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    me = current_user(request)
    audit_mod.log_event(
        "logout",
        actor=audit_mod.actor_from_user(me),
        target=audit_mod.actor_from_user(me),
        ip=client_ip(request),
    )
    response = RedirectResponse(f"{ROOT_PATH}/login", status_code=303)
    response.delete_cookie(sessions.COOKIE_NAME, path=ROOT_PATH or "/")
    return response


# Admin -----------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_index(request: Request):
    return templates.TemplateResponse("admin/index.html", ctx(request))


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request, msg: str = ""):
    return templates.TemplateResponse(
        "admin/users.html",
        ctx(request, users=users_mod.list_users(), msg=msg),
    )


@app.post("/admin/users")
def admin_users_create(
    request: Request,
    username: str = Form(...),
    role: str = Form("readonly"),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    check_csrf(request, csrf_token)
    username = username.strip()
    if not re.match(r"^[A-Za-z0-9_.\-]{2,64}$", username):
        raise HTTPException(400, "username must be 2–64 chars, [A-Za-z0-9_.-]")
    if role not in users_mod.ROLES:
        raise HTTPException(400, "invalid role")
    # Only a superadmin may create another superadmin. A plain admin
    # creating one would let them bootstrap themselves to the highest
    # tier on a compromised account; the gate here prevents that.
    if role == "superadmin":
        require_superadmin(request)
    if users_mod.get_by_username(username):
        return redirect(f"/admin/users?msg=user+already+exists")
    # Blank field generates a random password — only allowed for the
    # *create* path because a brand-new user has no prior credential to
    # rotate. The /admin/users/{uid}/password endpoint below requires
    # an explicit value to avoid the silent-rotation footgun.
    pw = password.strip() or users_mod.gen_password()
    new_uid = users_mod.create(username, pw, role)
    audit_mod.log_event(
        "user_created",
        actor=audit_mod.actor_from_user(current_user(request)),
        target={"id": new_uid, "username": username},
        ip=client_ip(request),
        extra={"role": role, "password_generated": not password.strip()},
    )
    msg = f"created+{username}+pw={pw}"
    return redirect(f"/admin/users?msg={msg}")


@app.post("/admin/users/{uid}/role")
def admin_users_set_role(request: Request, uid: int,
                         role: str = Form(...),
                         csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    if role not in users_mod.ROLES:
        raise HTTPException(400, "invalid role")
    # Superadmin gate fires when EITHER:
    #   - the new role is 'superadmin' (promoting), OR
    #   - the current role on the target is 'superadmin' (demoting).
    # Both transitions go through superadmin so a compromised admin
    # cannot escalate by promoting a co-conspirator or demoting the
    # only existing superadmin out of the way.
    target = users_mod.get_by_id(uid)
    if (role == "superadmin"
            or (target and target.get("role") == "superadmin")):
        require_superadmin(request)
    try:
        users_mod.set_role(uid, role)
    except ValueError as e:
        # Last-superadmin lockout protection (raised from users.set_role).
        return redirect(
            f"/admin/users?msg={str(e).replace(' ', '+')}")
    target = users_mod.get_by_id(uid)
    audit_mod.log_event(
        "role_changed",
        actor=audit_mod.actor_from_user(current_user(request)),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
        extra={"new_role": role},
    )
    return redirect("/admin/users?msg=role+updated")


@app.post("/admin/users/{uid}/max_spend")
def admin_users_set_max_spend(request: Request, uid: int,
                                max_spend_usd: str = Form(""),
                                csrf_token: str = Form("")):
    """Superadmin-only. Sets or clears the per-user Enhanced-AI per-scan
    budget cap. An empty / cleared field stores NULL, which means the
    system default applies. Negative values are refused; the column
    stores DECIMAL(8,2) so the input accepts cents."""
    require_superadmin(request)
    check_csrf(request, csrf_token)
    raw = (max_spend_usd or "").strip()
    val: Optional[float] = None
    if raw:
        try:
            val = round(float(raw), 2)
        except ValueError:
            return redirect("/admin/users?msg=max_spend+must+be+a+number")
        if val < 0:
            return redirect("/admin/users?msg=max_spend+cannot+be+negative")
    users_mod.set_max_spend(uid, val)
    target = users_mod.get_by_id(uid)
    audit_mod.log_event(
        "max_spend_changed",
        actor=audit_mod.actor_from_user(current_user(request)),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
        extra={"new_max_spend_usd": val},
    )
    return redirect("/admin/users?msg=max_spend+updated")


@app.post("/admin/users/{uid}/disabled")
def admin_users_disabled(request: Request, uid: int,
                         disabled: str = Form(""),
                         csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    is_disabled = bool(disabled)
    # Disabling a superadmin is gated behind another superadmin so a
    # compromised admin cannot freeze the only superadmin out.
    target = users_mod.get_by_id(uid)
    if target and target.get("role") == "superadmin" and is_disabled:
        require_superadmin(request)
    try:
        users_mod.set_disabled(uid, is_disabled)
    except ValueError as e:
        return redirect(
            f"/admin/users?msg={str(e).replace(' ', '+')}")
    target = users_mod.get_by_id(uid)
    audit_mod.log_event(
        "user_disabled" if is_disabled else "user_enabled",
        actor=audit_mod.actor_from_user(current_user(request)),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
    )
    return redirect("/admin/users?msg=disabled+updated")


@app.post("/admin/users/{uid}/password")
def admin_users_password(request: Request, uid: int,
                         password: str = Form(""),
                         csrf_token: str = Form("")):
    """Set a specific user's password. The blank-generates-random
    behavior was removed in 2.1.1: it produced a silent rotation when
    a stray click fired the form. The admin must now type the new
    password, or run scripts/reset.py for a rotation that also rewrites
    the on-disk secrets file."""
    check_csrf(request, csrf_token)
    pw = password.strip()
    if not pw:
        return redirect(
            f"/admin/users?msg=password+required+(blank+rotation+disabled)")
    if len(pw) < 8:
        return redirect(
            f"/admin/users?msg=password+must+be+%E2%89%A5+8+characters")
    users_mod.set_password(uid, pw)
    target = users_mod.get_by_id(uid)
    audit_mod.log_event(
        "password_set",
        actor=audit_mod.actor_from_user(current_user(request)),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
        extra={"via": "admin_users_password"},
    )
    return redirect(
        f"/admin/users?msg=password+updated+for+%23{uid}")


@app.post("/admin/users/{uid}/delete")
def admin_users_delete(request: Request, uid: int,
                       csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    me = current_user(request) or {}
    if int(uid) == int(me.get("id", -1)):
        raise HTTPException(400, "cannot delete the account you're logged in as")
    target = users_mod.get_by_id(uid)
    # Deleting a superadmin is gated behind another superadmin so a
    # compromised admin cannot remove the privilege ceiling.
    if target and target.get("role") == "superadmin":
        require_superadmin(request)
    try:
        users_mod.delete(uid)
    except ValueError as e:
        return redirect(
            f"/admin/users?msg={str(e).replace(' ', '+')}")
    audit_mod.log_event(
        "user_deleted",
        actor=audit_mod.actor_from_user(me),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
    )
    return redirect("/admin/users?msg=deleted")


@app.post("/me/password")
def me_password(request: Request,
                current_password: str = Form(...),
                new_password: str = Form(...),
                csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    me = current_user(request) or {}
    u = users_mod.get_by_id(me.get("id", 0))
    ip = client_ip(request)
    if not u or not users_mod.authenticate(u["username"], current_password):
        audit_mod.log_event(
            "password_set", ok=False,
            actor=audit_mod.actor_from_user(me),
            target=audit_mod.actor_from_user(u),
            ip=ip,
            extra={"via": "me_password", "reason": "current_password_invalid"},
        )
        raise HTTPException(403, "current password incorrect")
    if len(new_password) < 8:
        raise HTTPException(400, "new password must be ≥ 8 characters")
    users_mod.set_password(u["id"], new_password)
    audit_mod.log_event(
        "password_set",
        actor=audit_mod.actor_from_user(me),
        target=audit_mod.actor_from_user(u),
        ip=ip,
        extra={"via": "me_password"},
    )
    return redirect("/?msg=password+changed")


# Branding --------------------------------------------------------------------

@app.get("/admin/branding", response_class=HTMLResponse)
def admin_branding_landing(request: Request, msg: str = ""):
    """Landing page — picks which side to edit (web vs PDF)."""
    return templates.TemplateResponse(
        "admin/branding.html",
        ctx(request, brand=branding_mod.get(),
            web=branding_mod.get_web(),
            pdf=branding_mod.get_pdf(), msg=msg),
    )


@app.get("/admin/branding/web", response_class=HTMLResponse)
def admin_branding_web_page(request: Request, msg: str = ""):
    return templates.TemplateResponse(
        "admin/branding_web.html",
        ctx(request, brand=branding_mod.get(),
            web=branding_mod.get_web(), msg=msg),
    )


@app.get("/admin/branding/pdf", response_class=HTMLResponse)
def admin_branding_pdf_page(request: Request, msg: str = ""):
    return templates.TemplateResponse(
        "admin/branding_pdf.html",
        ctx(request, brand=branding_mod.get(),
            pdf=branding_mod.get_pdf(), msg=msg),
    )


@app.post("/admin/branding/shared")
def admin_branding_save_shared(
    company_name: str = Form(""),
    tagline: str = Form(""),
    classification: str = Form(""),
    contact_email: str = Form(""),
    disclaimer: str = Form(""),
    footer_text: str = Form(""),
    header_text: str = Form(""),
):
    branding_mod.update({
        "company_name": company_name, "tagline": tagline,
        "classification": classification, "contact_email": contact_email,
        "disclaimer": disclaimer,
        "footer_text": footer_text, "header_text": header_text,
    })
    return redirect("/admin/branding?msg=shared+saved")


@app.post("/admin/branding/web")
def admin_branding_save_web(
    web_mode: str = Form("dark"),
    web_primary_color: str = Form(""),
    web_accent_color: str = Form(""),
    web_font_family: str = Form(""),
    web_sev_critical: str = Form(""),
    web_sev_high: str = Form(""),
    web_sev_medium: str = Form(""),
    web_sev_low: str = Form(""),
    web_sev_info: str = Form(""),
):
    if web_mode not in ("dark", "custom"):
        web_mode = "dark"
    branding_mod.update({
        "web_mode": web_mode,
        "web_primary_color": web_primary_color,
        "web_accent_color": web_accent_color,
        "web_font_family": web_font_family,
        "web_sev_critical": web_sev_critical,
        "web_sev_high": web_sev_high,
        "web_sev_medium": web_sev_medium,
        "web_sev_low": web_sev_low,
        "web_sev_info": web_sev_info,
    })
    return redirect("/admin/branding/web?msg=web+branding+saved")


@app.post("/admin/branding/pdf")
def admin_branding_save_pdf(
    primary_color: str = Form(""),
    accent_color: str = Form(""),
    classification_color: str = Form(""),
    pdf_font_family: str = Form(""),
    pdf_cover_text_color: str = Form(""),
    pdf_header_color: str = Form(""),
    pdf_body_color: str = Form(""),
    pdf_link_color: str = Form(""),
    pdf_sev_critical: str = Form(""),
    pdf_sev_high: str = Form(""),
    pdf_sev_medium: str = Form(""),
    pdf_sev_low: str = Form(""),
    pdf_sev_info: str = Form(""),
):
    branding_mod.update({
        "primary_color": primary_color,
        "accent_color": accent_color,
        "classification_color": classification_color,
        "pdf_font_family": pdf_font_family,
        "pdf_cover_text_color": pdf_cover_text_color,
        "pdf_header_color": pdf_header_color,
        "pdf_body_color": pdf_body_color,
        "pdf_link_color": pdf_link_color,
        "pdf_sev_critical": pdf_sev_critical,
        "pdf_sev_high": pdf_sev_high,
        "pdf_sev_medium": pdf_sev_medium,
        "pdf_sev_low": pdf_sev_low,
        "pdf_sev_info": pdf_sev_info,
    })
    return redirect("/admin/branding/pdf?msg=pdf+branding+saved")


def _branding_section_for(kind: str) -> str:
    """Map a logo kind to the admin sub-page that owns it. Used so upload
    and delete redirects land back on the page the user was actually
    looking at (web vs PDF) — landing on the branding index makes the new
    logo appear absent because the index doesn't render the logo at all."""
    if kind == "web_header":
        return "/admin/branding/web"
    # pdf_header, pdf_footer and the legacy header/footer aliases all live
    # on the PDF page.
    return "/admin/branding/pdf"


@app.post("/admin/branding/logo/{kind}")
async def admin_branding_logo_upload(kind: str, file: UploadFile = File(...)):
    if kind not in branding_mod.ALLOWED_KINDS:
        raise HTTPException(400, "kind must be 'header' or 'footer'")
    data = await file.read()
    result = branding_mod.save_logo(kind, data)
    section = _branding_section_for(kind)
    if not result.get("ok"):
        return redirect(f"{section}?msg=upload+failed:+{result.get('error','?')}")
    return redirect(f"{section}?msg={kind}+logo+saved")


@app.post("/admin/branding/logo/{kind}/delete")
def admin_branding_logo_delete(kind: str):
    if kind not in branding_mod.ALLOWED_KINDS:
        raise HTTPException(400, "kind must be 'header' or 'footer'")
    branding_mod.delete_logo(kind)
    return redirect(f"{_branding_section_for(kind)}?msg={kind}+logo+removed")


# Toolkit (validation probes) -------------------------------------------------

@app.get("/admin/toolkit", response_class=HTMLResponse)
def admin_toolkit_page(request: Request):
    return templates.TemplateResponse(
        "admin/toolkit.html",
        ctx(request, probes=toolkit_mod.list_probes()),
    )


# API tokens -----------------------------------------------------------------
#
# Issuance/revocation page for the OUI-format REST API tokens. The actual
# enforcement (header parsing, IP whitelisting, last-used tracking) lives
# in app/api.py; this is just the management surface so an admin can mint
# and retire keys without dropping into SQL.

# ---- Theme preference (Dark / Light) -------------------------------------
# Each authenticated user owns a single theme string on their users row
# ('dark' or 'light'). The toggle page is intentionally lightweight: a
# small form with two options and a Save button. We POST rather than GET-
# toggle so a CSRF token is required and the action shows up in the audit
# log of any reverse proxy that logs only POST mutations.

@app.get("/theme", response_class=HTMLResponse)
def theme_page(request: Request, msg: str = ""):
    """Render the theme preference page. Unauthenticated visitors are
    redirected to login; the page itself only shows the current choice
    + a save form."""
    user = current_user(request)
    if not user:
        return redirect("/login?next=/theme")
    return templates.TemplateResponse(
        "theme.html",
        ctx(request, msg=msg, current_theme=_resolve_user_theme(user)))


@app.post("/theme")
def theme_save(request: Request,
                theme: str = Form("dark"),
                csrf_token: str = Form("")):
    """Persist the user's theme choice. Validates against the enum so a
    tampered form value cannot smuggle SQL or non-enum text into the
    column. CSRF-checked via the standard helper."""
    user = current_user(request)
    if not user:
        return redirect("/login?next=/theme")
    check_csrf(request, csrf_token)
    choice = (theme or "").strip().lower()
    if choice not in ("dark", "light"):
        choice = "dark"
    db.execute("UPDATE users SET theme=%s WHERE id=%s",
                (choice, user.get("id")))
    return redirect("/theme?msg=theme+saved")


@app.get("/admin/api-tokens", response_class=HTMLResponse)
def admin_api_tokens_page(request: Request, msg: str = "",
                          new_token: str = ""):
    """List existing tokens. `new_token`, when present, is the
    just-minted plaintext value; we render it once (and only once) so
    the operator can copy it. It's never persisted server-side beyond
    the SHA-256 hash."""
    return templates.TemplateResponse(
        "admin/api_tokens.html",
        ctx(request, tokens=api_mod.list_tokens(),
            msg=msg, new_token=new_token),
    )


@app.post("/admin/api-tokens")
def admin_api_tokens_create(request: Request,
                            label: str = Form(""),
                            allowed_ips: str = Form(""),
                            notes: str = Form("")):
    """Mint a new token. Returns straight to the listing page with
    `new_token` set to the freshly-minted plaintext so the operator
    can copy it once. Refuses to issue a token without at least one
    whitelisted IP — fail-closed by design (a token usable from
    everywhere is too dangerous to mint by accident)."""
    me = current_user(request) or {}
    parsed = api_mod.parse_allowed_ips(allowed_ips)
    if not parsed:
        return redirect("/admin/api-tokens?msg=allowed_ips+required+%28token+would+be+unusable%29")
    _tid, plaintext = api_mod.create_token(
        label=label, allowed_ips=allowed_ips,
        created_by_user_id=me.get("id"), notes=notes,
    )
    return redirect(f"/admin/api-tokens?new_token={plaintext}&msg=token+created+%E2%80%94+copy+it+now")


@app.post("/admin/api-tokens/{tid}/disable")
def admin_api_tokens_disable(tid: int):
    api_mod.update_token(tid, disabled=True)
    return redirect("/admin/api-tokens?msg=token+disabled")


@app.post("/admin/api-tokens/{tid}/enable")
def admin_api_tokens_enable(tid: int):
    api_mod.update_token(tid, disabled=False)
    return redirect("/admin/api-tokens?msg=token+enabled")


@app.post("/admin/api-tokens/{tid}/update")
def admin_api_tokens_update(tid: int,
                            label: str = Form(""),
                            allowed_ips: str = Form(""),
                            notes: str = Form("")):
    """Patch label / IP whitelist / notes on an existing token. The
    token secret itself is never editable; revoke + reissue if
    rotation is needed."""
    api_mod.update_token(tid, label=label, allowed_ips=allowed_ips, notes=notes)
    return redirect("/admin/api-tokens?msg=token+updated")


@app.post("/admin/api-tokens/{tid}/delete")
def admin_api_tokens_delete(tid: int):
    api_mod.delete_token(tid)
    return redirect("/admin/api-tokens?msg=token+deleted")


# Database backup & restore --------------------------------------------------
#
# Settings → Database. Lets an administrator dump the live MariaDB to a
# gzipped .sql archive and restore from one. The heavy lifting (running
# mariadb-dump / mariadb client, streaming through gzip) lives in
# dbops_mod — this section is just the routes and the template wiring.

@app.get("/admin/database", response_class=HTMLResponse)
def admin_database_page(request: Request, msg: str = ""):
    """Render the backup / restore landing page. Shows the list of
    existing dumps with size + age, plus the buttons that trigger the
    backup / upload-and-restore flows."""
    return templates.TemplateResponse(
        "admin/database.html",
        ctx(request,
            backups=dbops_mod.list_backups(),
            max_restore_bytes=dbops_mod.MAX_RESTORE_BYTES,
            msg=msg),
    )


@app.post("/admin/database/backup")
def admin_database_backup_create():
    """Run mariadb-dump → gzip into a fresh file under /data/backups.
    The user gets redirected back to the page with a success/error
    message. We deliberately do NOT stream the dump straight to the
    browser — saving server-side first means a half-finished download
    still leaves us with a usable file, and the page can show the size
    + offer a re-download."""
    fname = dbops_mod.make_backup_filename()
    result = dbops_mod.write_backup(fname)
    if not result.get("ok"):
        # urlencode the error so query-string parsing on the redirect
        # target doesn't choke on '+' / '&' inside the message.
        from urllib.parse import quote_plus
        return redirect("/admin/database?msg=backup+failed:+"
                        + quote_plus(result.get("error", "unknown error")))
    size_mb = round(result["size_bytes"] / (1024 * 1024), 2)
    return redirect(
        f"/admin/database?msg=backup+saved:+{result['filename']}+"
        f"({size_mb}+MB,+{result['elapsed_seconds']}s)")


@app.get("/admin/database/backup/{filename}")
def admin_database_backup_download(filename: str):
    """Download a previously-created dump. The filename is validated
    against the canonical backup pattern so this can't be coerced into
    a path-traversal read of /data."""
    safe = dbops_mod._safe_filename(filename)
    if not safe:
        raise HTTPException(400, "invalid backup filename")
    target = (dbops_mod.BACKUPS_DIR / safe).resolve()
    backups_dir = dbops_mod.BACKUPS_DIR.resolve()
    if not str(target).startswith(str(backups_dir)) or not target.exists():
        raise HTTPException(404)
    return FileResponse(
        str(target),
        media_type="application/gzip",
        filename=safe,
    )


@app.post("/admin/database/backup/{filename}/delete")
def admin_database_backup_delete(filename: str):
    """Remove a dump from /data/backups. Validated through dbops so a
    crafted filename can't escape the backups directory."""
    if not dbops_mod.delete_backup(filename):
        return redirect("/admin/database?msg=delete+failed:+invalid+or+missing+file")
    return redirect("/admin/database?msg=backup+deleted")


@app.post("/admin/database/restore")
async def admin_database_restore(file: UploadFile = File(...)):
    """Stream the uploaded SQL (or gzipped SQL) into the mariadb client.
    Auto-detects gzip from the file's first two bytes; the .sql.gz
    extension is the conventional hint but not load-bearing — a plain
    .sql also works.

    The upload is processed in chunks via UploadFile.read(N) so the
    request body never needs to fit in memory. Total bytes are capped
    by dbops.MAX_RESTORE_BYTES."""
    fname = (file.filename or "").lower()
    forced_gzip = None
    if fname.endswith(".sql.gz") or fname.endswith(".gz"):
        forced_gzip = True
    elif fname.endswith(".sql"):
        forced_gzip = False

    async def chunks():
        # 1 MB at a time — same trade-off as the backup writer: large
        # enough that python overhead is negligible, small enough that
        # a multi-GB upload doesn't sit in RAM.
        while True:
            data = await file.read(1024 * 1024)
            if not data:
                break
            yield data

    # dbops.restore_from_stream wants a sync iterator. Drain the async
    # generator into a list of in-memory chunks isn't acceptable for
    # multi-GB inputs, so adapt with a small queue + thread.
    import asyncio, queue, threading
    q: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=4)
    result_holder = {}

    def worker():
        def sync_chunks():
            while True:
                item = q.get()
                if item is None:
                    return
                yield item
        result_holder["r"] = dbops_mod.restore_from_stream(
            sync_chunks(), is_gzip=forced_gzip)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        async for c in chunks():
            await asyncio.to_thread(q.put, c)
    finally:
        await asyncio.to_thread(q.put, None)
    await asyncio.to_thread(t.join)
    result = result_holder.get("r") or {"ok": False,
                                        "error": "restore worker did not run"}
    if not result.get("ok"):
        from urllib.parse import quote_plus
        return redirect("/admin/database?msg=restore+failed:+"
                        + quote_plus(result.get("error", "unknown error")))
    elapsed = result.get("elapsed_seconds", "?")
    return redirect(
        f"/admin/database?msg=restore+complete+(elapsed+{elapsed}s)")


# SCA database admin ----------------------------------------------------------
#
# Surfaces the cached vulnerability inventory, observed-package list, and
# scanner overlay versions; lets admins trigger an immediate refresh and
# add manual cache overrides. The refresh button spawns
# scripts/update_scanners.run() on a worker thread so the request returns
# in milliseconds while the long download proceeds in the background.

import sca as sca_mod
from scripts import update_scanners as updater_mod


@app.get("/admin/sca", response_class=HTMLResponse)
def admin_sca_page(request: Request, msg: str = ""):
    """Render the SCA admin landing page."""
    interval_h = 24
    sig_max_age = 7
    try:
        r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                         ("sca_update_interval_hours",))
        if r and (r.get("value") or "").strip():
            interval_h = int(float(r["value"]))
        r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                         ("sca_signature_max_age_days",))
        if r and (r.get("value") or "").strip():
            sig_max_age = int(float(r["value"]))
    except Exception:
        pass
    last_at = ""
    try:
        r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                         ("sca_last_updated_at",))
        if r:
            last_at = r.get("value") or ""
    except Exception:
        pass
    # Recent packages list — bound to keep the page fast even after
    # thousands of assessments have populated the cache.
    # PyMySQL runs the query through Python's % formatting even with an
    # empty args tuple — every literal % in SQL has to be escaped %%.
    packages = db.query(
        "SELECT p.ecosystem, p.name, p.version, p.last_seen, "
        "       (SELECT COUNT(*) FROM sca_vulnerabilities v "
        "         WHERE v.ecosystem=p.ecosystem AND v.package_name=p.name "
        "           AND NOT (v.source='llm' AND IFNULL(v.cve_id,'')='' "
        "                    AND v.summary LIKE 'no known%%')) AS vuln_count "
        "FROM sca_packages p "
        "ORDER BY p.last_seen DESC LIMIT 100"
    )
    vulns = db.query(
        "SELECT * FROM sca_vulnerabilities "
        "WHERE NOT (source='llm' AND IFNULL(cve_id,'')='' "
        "          AND summary LIKE 'no known%%') "
        "ORDER BY fetched_at DESC LIMIT 50"
    )
    log_path = Path("/data/logs/sca_update.log")
    recent_log = ""
    if log_path.is_file():
        try:
            with open(log_path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 8192))
                recent_log = fh.read().decode("utf-8", "replace")
        except OSError:
            pass
    return templates.TemplateResponse(
        "admin/sca.html",
        ctx(request,
            msg=msg,
            stats=sca_mod.stats(),
            packages=packages,
            vulns=vulns,
            interval_hours=interval_h,
            sig_max_age_days=sig_max_age,
            last_updated_at=last_at,
            recent_log=recent_log,
            updater_status=updater_mod.status()),
    )


@app.get("/admin/sca/log", response_class=PlainTextResponse)
def admin_sca_log(tail: int = 4096):
    """Plain-text log tail for the SSE-ish polling fetch in sca.html.
    Caps the read window so a runaway log file can't OOM the page."""
    log_path = Path("/data/logs/sca_update.log")
    if not log_path.is_file():
        return PlainTextResponse("", status_code=200)
    tail = max(256, min(int(tail or 4096), 65536))
    try:
        with open(log_path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail))
            data = fh.read().decode("utf-8", "replace")
        return PlainTextResponse(data, status_code=200)
    except OSError:
        return PlainTextResponse("(log read error)", status_code=200)


@app.post("/admin/sca/update")
def admin_sca_update(scope: str = Form("all"),
                     csrf_token: str = Form("")):
    """Kick off a refresh on a daemon thread. Returns immediately so
    the admin doesn't sit on a 5-minute request — the SSE log tail in
    sca.html shows live progress."""
    # csrf check is enforced by the standard pattern when present;
    # the form ships csrf_token from the rendered context.
    if scope not in ("all", "scanners", "sca"):
        return redirect("/admin/sca?msg=invalid+scope")
    import threading
    def _bg():
        try:
            updater_mod.run(scope=scope,
                            log_path=Path("/data/logs/sca_update.log"))
        except Exception as e:
            print(f"[admin/sca/update] {e!r}", flush=True)
    threading.Thread(target=_bg, name=f"sca-update-admin-{scope}",
                     daemon=True).start()
    from urllib.parse import quote_plus
    return redirect("/admin/sca?msg=" + quote_plus(
        f"refresh started ({scope}) — see live log below"))


@app.post("/admin/sca/vuln")
def admin_sca_vuln_add(
    ecosystem: str = Form(...),
    package_name: str = Form(...),
    vulnerable_range: str = Form(...),
    cve_id: str = Form(""),
    ghsa_id: str = Form(""),
    severity: str = Form("medium"),
    cvss: str = Form(""),
    summary: str = Form(""),
    description: str = Form(""),
    fixed_version: str = Form(""),
    references: str = Form(""),
    csrf_token: str = Form(""),
):
    """Insert a manual cache row. The lock flag is set on insert so
    later automatic refreshes don't overwrite the admin's value."""
    refs = [u.strip() for u in (references or "").splitlines() if u.strip()]
    new_id = sca_mod.upsert_vuln(
        ecosystem.strip(), package_name.strip(),
        vulnerable_range=vulnerable_range.strip(),
        cve_id=(cve_id.strip() or None),
        ghsa_id=(ghsa_id.strip() or None),
        severity=severity.strip().lower(),
        cvss=(cvss.strip() or None),
        summary=summary.strip(),
        description=description.strip(),
        fixed_version=(fixed_version.strip() or None),
        references=refs,
        source="manual",
    )
    # Lock the row so automatic refreshes can't blow it away. upsert_vuln
    # already short-circuits when is_locked=1, but a brand-new row needs
    # the explicit flag set after insert.
    db.execute("UPDATE sca_vulnerabilities SET is_locked=1 WHERE id=%s",
               (new_id,))
    return redirect("/admin/sca?msg=manual+entry+added+(locked)")


@app.get("/admin/sca/config", response_class=HTMLResponse)
def admin_sca_config(request: Request, msg: str = ""):
    rows = db.query(
        "SELECT `key`, value FROM config "
        "WHERE `key` IN ('sca_update_interval_hours','sca_signature_max_age_days') "
        "ORDER BY `key`")
    return templates.TemplateResponse(
        "admin/sca.html",
        ctx(request, msg=msg or "Edit values inline; submit each form to save.",
            stats=sca_mod.stats(),
            packages=[], vulns=[],
            interval_hours=int(float(next((r["value"] for r in rows
                                            if r["key"] == "sca_update_interval_hours"
                                            and r.get("value")), 24))),
            sig_max_age_days=int(float(next((r["value"] for r in rows
                                              if r["key"] == "sca_signature_max_age_days"
                                              and r.get("value")), 7))),
            last_updated_at="",
            recent_log="",
            updater_status=updater_mod.status()),
    )


# Reports ---------------------------------------------------------------------

@app.post("/assessment/{aid}/report")
def assessment_report_generate(aid: int):
    """Generate a fresh PDF report for an assessment. Synchronous in v1 —
    big assessments may take 5–15 s. Returns a redirect to the assessment
    detail page so the new file shows up in the report list."""
    a = db.query_one("SELECT id FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    try:
        path = reports_mod.generate(aid)
    except Exception as e:
        return redirect(f"/assessment/{aid}?msg=report+failed:+{type(e).__name__}")
    if not path:
        return redirect(f"/assessment/{aid}?msg=no+data+to+report")
    return redirect(f"/assessment/{aid}?msg=report+ready:+{path.name}")


# Filename pattern is enforced both here (request-time) and inside
# reports.delete_report() (storage-time). reports.REPORT_FILENAME_RE is
# the single source of truth.
@app.get("/assessment/{aid}/report/{filename}")
def assessment_report_download(aid: int, filename: str):
    """Serve a generated report. Strict regex on filename + path-resolve
    check inside reports.REPORTS_DIR/<aid>/ so the route can't be coerced
    into serving anything outside the per-assessment directory."""
    if not reports_mod.REPORT_FILENAME_RE.match(filename):
        raise HTTPException(400, "invalid report name")
    rdir = (reports_mod.REPORTS_DIR / str(int(aid))).resolve()
    target = (rdir / filename).resolve()
    if not str(target).startswith(str(rdir)):
        raise HTTPException(403)
    if not target.exists():
        raise HTTPException(404)
    return FileResponse(str(target), media_type="application/pdf",
                        filename=filename)


@app.post("/assessment/{aid}/report/{filename}/delete")
def assessment_report_delete(aid: int, filename: str):
    """Remove a generated PDF report file. Same strict filename validation
    as the download route."""
    if not reports_mod.REPORT_FILENAME_RE.match(filename):
        raise HTTPException(400, "invalid report name")
    a = db.query_one("SELECT id FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    if not reports_mod.delete_report(aid, filename):
        return redirect(f"/assessment/{aid}?msg=report+not+found")
    return redirect(f"/assessment/{aid}?msg=report+deleted")


# Finding detail + enrichment ------------------------------------------------

@app.get("/finding/{fid}", response_class=HTMLResponse)
def finding_detail(request: Request, fid: int):
    """Per-finding view: enrichment guidance, ticket export, and the
    Challenge / False-Positive workflow. The view is read-only for
    non-admin users; the action buttons render disabled in that case.

    Shares the panel-context builder with the workspace fragment so
    the embedded Reproduce-&-verify partial sees the same `io`
    (Validate / Test eligibility, captured request/response, indicator)
    on this page as it does in the workspace."""
    f = db.query_one(
        "SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    panel = _finding_panel_context(f)
    # Decode validation_evidence (stored as JSON when a probe ran). This
    # is full-detail-only — the workspace panel doesn't render it.
    validation = None
    if f.get("validation_evidence"):
        try:
            validation = json.loads(f["validation_evidence"])
        except Exception:
            validation = {"raw": f["validation_evidence"][:2000]}
    return templates.TemplateResponse(
        "finding_detail.html",
        ctx(request, validation=validation, **panel),
    )


@app.get("/finding/{fid}/export")
def finding_export(fid: int, format: str = "jira"):
    """Render a ticket-ready body for paste into Jira / ServiceNow / GitHub.
    Supported formats: jira, servicenow, markdown, github, csv."""
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    e = None
    if f.get("enrichment_id"):
        e = db.query_one(
            "SELECT * FROM finding_enrichment WHERE id = %s",
            (f["enrichment_id"],))
    if not e:
        raise HTTPException(404, "no enrichment available for this finding")
    ctype, body = enrichment_mod.render_export(e, f, format)
    return PlainTextResponse(body, media_type=ctype)


@app.post("/admin/finding/{fid}/enrichment")
def admin_finding_enrichment_save(
    request: Request,
    fid: int,
    owasp_category: str = Form(""),
    cwe: str = Form(""),
    description_long: str = Form(""),
    impact: str = Form(""),
    remediation_long: str = Form(""),
    remediation_steps: str = Form(""),     # one step per line
    code_example: str = Form(""),
    references: str = Form(""),             # one URL per line
    user_story: str = Form(""),
    suggested_priority: str = Form(""),
    notes: str = Form(""),
):
    """Admin: edit (or create-on-the-fly) enrichment for this finding's type.
    The edit applies to the *signature*, so every other finding of the same
    type — past, present, future — picks up the same content. Edits set
    source='manual' + is_locked=1, so future automatic enrichment will not
    overwrite them."""
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    user = current_user(request) or {}
    steps_list = [s.strip() for s in remediation_steps.splitlines() if s.strip()]
    refs_list = [r.strip() for r in references.splitlines() if r.strip()]
    edits = {
        "owasp_category": owasp_category.strip() or None,
        "cwe": cwe.strip() or None,
        "description_long": description_long,
        "impact": impact,
        "remediation_long": remediation_long,
        "remediation_steps": json.dumps(steps_list),
        "code_example": code_example,
        "references_json": json.dumps(refs_list),
        "user_story": user_story,
        "suggested_priority": suggested_priority.strip() or None,
        "notes": notes,
    }
    if f.get("enrichment_id"):
        enrichment_mod.update_manual(f["enrichment_id"], edits, user.get("id"))
        eid = f["enrichment_id"]
    else:
        # Build a manual stub bound to this finding's signature, then point
        # the finding row at it.
        stub_input = dict(edits)
        stub_input["remediation_steps"] = steps_list
        stub_input["references"] = refs_list
        eid = enrichment_mod.create_manual_stub(f, stub_input, user.get("id"))
        db.execute("UPDATE findings SET enrichment_id = %s WHERE id = %s",
                   (eid, f["id"]))
    # Also rebuild the bug-report body + jira summary so they reflect edits.
    e_row = db.query_one("SELECT * FROM finding_enrichment WHERE id = %s", (eid,))
    payload = {
        "description_long": e_row.get("description_long") or "",
        "impact": e_row.get("impact") or "",
        "remediation_long": e_row.get("remediation_long") or "",
        "remediation_steps": json.loads(e_row.get("remediation_steps") or "[]"),
        "code_example": e_row.get("code_example") or "",
        "references": json.loads(e_row.get("references_json") or "[]"),
        "user_story": e_row.get("user_story") or "",
        "owasp_category": e_row.get("owasp_category") or "",
    }
    db.execute(
        "UPDATE finding_enrichment SET bug_report_md = %s, jira_summary = %s "
        "WHERE id = %s",
        (enrichment_mod.build_bug_report_md(f, payload),
         enrichment_mod.build_jira_summary(f, payload),
         eid),
    )
    return redirect(f"/finding/{fid}?msg=enrichment+saved")


@app.post("/admin/finding/{fid}/enrichment/unlock")
def admin_finding_enrichment_unlock(fid: int):
    """Clear the manual lock so the next assessment with an LLM endpoint
    will re-enrich this finding type from scratch."""
    f = db.query_one("SELECT enrichment_id FROM findings WHERE id = %s", (fid,))
    if not f or not f.get("enrichment_id"):
        raise HTTPException(404)
    db.execute(
        "UPDATE finding_enrichment SET is_locked = 0 WHERE id = %s",
        (f["enrichment_id"],))
    return redirect(f"/finding/{fid}?msg=unlocked")


# ---- Validation workflow (Challenge / Mark False Positive / Reopen) -------
#
# Three small POST routes that act on a single finding's state:
#
#   /finding/{id}/challenge       — runs the toolkit probe mapped by
#       toolkit.find_probe_for_finding(). Stores the JSON verdict in
#       findings.validation_evidence and updates validation_status to
#       'validated' / 'inconclusive' / 'false_positive' / 'errored'
#       depending on the probe's verdict.
#
#   /finding/{id}/false_positive  — analyst override: marks the finding as
#       a confirmed false positive. Optional reason is stored in
#       validation_evidence so the audit trail records *why*. Sets both
#       findings.status='false_positive' (excludes from score) and
#       validation_status='false_positive' (excludes from re-validation).
#
#   /finding/{id}/reopen          — undo a false-positive mark. Clears
#       validation_status back to 'unvalidated' and restores status='open'.
#
# All three require admin (the global middleware already enforces this on
# any POST). Probes are read-only by manifest, so re-running Challenge on
# the same finding is safe.

def _resolve_challenge_cookie(finding: dict,
                              manual_cookie: str = "") -> tuple[Optional[str], dict]:
    """Resolve the session cookie to use when challenging this finding.

    Order of preference:
      1. A manually-pasted cookie (textarea on the Challenge form).
      2. Live form login using the assessment's stored creds + login_url.
         Done in-memory by auth.form_login_cookie(); the password never
         leaves this function's frame.
      3. None — probe runs anonymously, same as before.

    Returns (cookie_header_or_None, diagnostics_dict). The diagnostics
    dict is what gets persisted into validation_evidence — it never
    contains the cookie value, only metadata about how it was obtained
    (cookie names, login response status, etc.)."""
    if manual_cookie and manual_cookie.strip():
        return manual_cookie.strip(), {"source": "manual-paste",
                                       "redacted": auth_mod.redact_cookie(manual_cookie.strip())}
    # Need the assessment's creds to attempt auto-login.
    a = db.query_one(
        "SELECT id, creds_username, creds_password, login_url "
        "FROM assessments WHERE id = %s", (finding.get("assessment_id"),))
    if not a or not (a.get("creds_username")
                     and a.get("creds_password")
                     and a.get("login_url")):
        return None, {"source": "anonymous",
                      "reason": "no manual cookie + no stored credentials "
                                "+ login_url on assessment"}
    result = auth_mod.form_login_cookie(
        a["login_url"], a["creds_username"], a["creds_password"])
    if not result.get("ok"):
        return None, {"source": "anonymous",
                      "reason": "form_login_cookie failed",
                      "login_error": result.get("error"),
                      "login_diagnostics": result.get("diagnostics") or {}}
    diagnostics = {
        "source": "form-login",
        "redacted_cookie": auth_mod.redact_cookie(result["cookie"]),
        "login_diagnostics": result.get("diagnostics") or {},
    }
    return result["cookie"], diagnostics


def _run_finding_probe(finding: dict, probe: dict,
                       cookie: Optional[str] = None,
                       extra: Optional[dict] = None) -> dict:
    """Thin wrapper around toolkit.build_finding_config + run_probe.

    Kept as a function so existing callers (and the route signatures)
    don't need to be touched, but the actual config setup now lives in
    toolkit.build_finding_config so the bulk Challenge runner shares
    one source of truth. See that helper for what gets populated and
    why."""
    config = toolkit_mod.build_finding_config(
        finding, probe, cookie=cookie, extra=extra)
    return toolkit_mod.run_probe(
        probe["name"], config, timeout=toolkit_mod.probe_timeout(probe))


# Verdict→status mapping moved to toolkit.verdict_to_status so the bulk
# Challenge runner shares the same logic. This thin alias preserves the
# existing call sites in this file without forcing them to import a
# different name.
_verdict_to_status = toolkit_mod.verdict_to_status


@app.post("/finding/{fid}/challenge")
def finding_challenge(fid: int, cookie: str = Form("")):
    """Run the matched validation probe against this finding's evidence
    URL. Authentication is preserved automatically:

      * if the form's `cookie` field is filled in, that cookie is used;
      * else if the assessment has stored creds + login_url, we do a
        live form login here, in-memory, and use the resulting cookie;
      * else the probe runs anonymously.

    The cookie value is redacted before being saved to
    validation_evidence — only the cookie *names* are recorded, plus
    diagnostics about how the session was obtained."""
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    probe = toolkit_mod.find_probe_for_finding(f)
    if not probe:
        return redirect(f"/finding/{fid}?msg=no+probe+matches+this+finding")
    if not f.get("evidence_url"):
        return redirect(
            f"/finding/{fid}?msg=cannot+challenge+%E2%80%94+no+evidence+URL")

    session_cookie, auth_diag = _resolve_challenge_cookie(f, manual_cookie=cookie)
    verdict = _run_finding_probe(f, probe, cookie=session_cookie)

    # Strip any echoed cookie value from the verdict before persisting.
    if isinstance(verdict, dict):
        verdict.setdefault("auth", {}).update(auth_diag)
        # The audit log may have echoed the Cookie header; sanitise.
        for entry in verdict.get("audit_log") or []:
            if "headers" in entry:
                entry["headers"].pop("Cookie", None)

    new_status = _verdict_to_status(verdict)
    # When the probe is confident the finding is a false positive, flip
    # findings.status to 'false_positive' too — the analyst shouldn't have
    # to click a second button to suppress something the probe already
    # disproved. (Symmetrically, a 'validated' verdict does NOT auto-flip
    # status to 'confirmed' — confirmation is intentionally a human step
    # so the analyst reads the evidence before triaging upward.)
    new_finding_status = ("false_positive" if new_status == "false_positive"
                          else None)
    if new_finding_status:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s, status = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000],
             new_finding_status, fid),
        )
    else:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000], fid),
        )
    # Surface the verdict's summary as a tail on the redirect message so
    # the analyst sees *why* on the same page they came from. urlencode
    # the summary so it survives the round-trip; clamp the total msg
    # length so a verbose probe summary can't blow past sane URL bounds.
    from urllib.parse import quote_plus
    summary_tail = (verdict.get("summary") or "").strip()
    if summary_tail and len(summary_tail) > 240:
        summary_tail = summary_tail[:240] + "…"
    msg = f"challenge result: {new_status}"
    if summary_tail:
        msg += f" — {summary_tail}"
    return redirect(f"/finding/{fid}?msg={quote_plus(msg)}")


@app.post("/finding/{fid}/validate")
def finding_validate_inline(fid: int):
    """JSON sibling of /finding/<id>/challenge for the assessment-workspace
    'Validate' button. Runs the matched probe IF (and only if) it is
    declared `safety_class: read-only`, then returns the verdict as JSON
    so the workspace modal can render it inline.

    Persisting the verdict matches the challenge endpoint exactly, so a
    Validate run on the workspace shows up on the standalone /finding/<id>
    page just like a Challenge would.

    Refuses (HTTP 409) for probes whose safety class is anything other
    than read-only — any 'probe' or 'destructive' validation must go
    through the explicit Challenge form so the analyst sees the budget
    and confirms first.
    """
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    probe = toolkit_mod.find_probe_for_finding(f)
    if not probe:
        return JSONResponse(
            {"ok": False, "error": "no_probe",
             "message": "No validation probe matches this finding's signature."},
            status_code=409)
    if probe.get("safety_class") != "read-only":
        return JSONResponse(
            {"ok": False, "error": "not_safe",
             "message": (f"Probe '{probe.get('name')}' is classified "
                         f"'{probe.get('safety_class')}'. Use the Challenge "
                         "form on the full detail page so the budget and "
                         "scope are visible before it runs.")},
            status_code=409)
    if not (f.get("evidence_url") or "").strip():
        return JSONResponse(
            {"ok": False, "error": "no_url",
             "message": "Finding has no evidence URL to test against."},
            status_code=409)

    # No manual cookie override on the inline path — the workspace button
    # is meant to be one-click. The standalone Challenge form is still
    # the right place when authenticated session replay is needed.
    session_cookie, auth_diag = _resolve_challenge_cookie(f, manual_cookie="")
    verdict = _run_finding_probe(f, probe, cookie=session_cookie)

    if isinstance(verdict, dict):
        verdict.setdefault("auth", {}).update(auth_diag)
        for entry in verdict.get("audit_log") or []:
            if "headers" in entry:
                entry["headers"].pop("Cookie", None)

    new_status = _verdict_to_status(verdict)
    new_finding_status = ("false_positive" if new_status == "false_positive"
                          else None)
    if new_finding_status:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s, status = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000],
             new_finding_status, fid),
        )
    else:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000], fid),
        )

    # Hand the modal a stable, lightweight payload. We pass through the
    # parts the analyst actually reads (verdict, summary, hits, request
    # round-trip) and skip the bulky catalog metadata.
    audit = verdict.get("audit_log") or []
    last_req = audit[-1] if audit else {}
    return JSONResponse({
        "ok": bool(verdict.get("ok", True)),
        "validated": verdict.get("validated"),
        "confidence": verdict.get("confidence"),
        "summary": verdict.get("summary") or "",
        "remediation": verdict.get("remediation") or "",
        "severity_uplift": verdict.get("severity_uplift"),
        "status": new_status,
        "probe": probe.get("name"),
        "evidence": verdict.get("evidence") or {},
        "audit": [{
            "method": e.get("method"),
            "url":    e.get("url"),
            "status": e.get("status"),
            "size":   e.get("size"),
        } for e in audit[:10]],
        "last_status": last_req.get("status"),
        "error": verdict.get("error"),
    })


@app.post("/finding/{fid}/challenge_inline")
def finding_challenge_inline(request: Request, fid: int):
    """JSON sibling of /finding/<id>/challenge for the workspace 'Challenge'
    button. Runs the matched probe IF it isn't classified `destructive`
    (those still require the standalone form so an analyst types the
    confirmation), then returns the verdict as JSON so the workspace
    modal can render it inline.

    The difference from /validate is the safety gate: /validate refuses
    anything not 'read-only' (one-click semantics), while this endpoint
    accepts 'read-only' AND 'probe' classes — which covers the auth
    probes (auth_sql_login_bypass, auth_default_admin_credentials) that
    POST a single login attempt with a non-mutating payload. Admin role
    is required because a probe-class run still issues live HTTP traffic
    against the target.
    """
    user = current_user(request) or {}
    if user.get("role") not in ("admin", "superadmin"):
        return JSONResponse(
            {"ok": False, "error": "forbidden",
             "message": "Challenge runs require admin role."},
            status_code=403)
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    probe = toolkit_mod.find_probe_for_finding(f)
    if not probe:
        return JSONResponse(
            {"ok": False, "error": "no_probe",
             "message": "No validation probe matches this finding's signature."},
            status_code=409)
    if probe.get("safety_class") == "destructive":
        return JSONResponse(
            {"ok": False, "error": "not_safe",
             "message": (f"Probe '{probe.get('name')}' is classified "
                         "'destructive'. Use the Challenge form on the "
                         "full detail page so the budget and scope are "
                         "visible before it runs.")},
            status_code=409)
    if not (f.get("evidence_url") or "").strip():
        return JSONResponse(
            {"ok": False, "error": "no_url",
             "message": "Finding has no evidence URL to test against."},
            status_code=409)

    session_cookie, auth_diag = _resolve_challenge_cookie(f, manual_cookie="")
    verdict = _run_finding_probe(f, probe, cookie=session_cookie)

    if isinstance(verdict, dict):
        verdict.setdefault("auth", {}).update(auth_diag)
        for entry in verdict.get("audit_log") or []:
            if "headers" in entry:
                entry["headers"].pop("Cookie", None)

    new_status = _verdict_to_status(verdict)
    new_finding_status = ("false_positive" if new_status == "false_positive"
                          else None)
    if new_finding_status:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s, status = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000],
             new_finding_status, fid),
        )
    else:
        db.execute(
            "UPDATE findings SET validation_status = %s, "
            "validation_probe = %s, validation_run_at = NOW(), "
            "validation_evidence = %s WHERE id = %s",
            (new_status, probe["name"][:64],
             json.dumps(verdict, default=str)[:65000], fid),
        )

    audit = verdict.get("audit_log") or []
    last_req = audit[-1] if audit else {}
    return JSONResponse({
        "ok": bool(verdict.get("ok", True)),
        "validated": verdict.get("validated"),
        "confidence": verdict.get("confidence"),
        "summary": verdict.get("summary") or "",
        "remediation": verdict.get("remediation") or "",
        "severity_uplift": verdict.get("severity_uplift"),
        "status": new_status,
        "probe": probe.get("name"),
        "evidence": verdict.get("evidence") or {},
        "audit": [{
            "method": e.get("method"),
            "url":    e.get("url"),
            "status": e.get("status"),
            "size":   e.get("size"),
        } for e in audit[:10]],
        "last_status": last_req.get("status"),
        "error": verdict.get("error"),
    })


@app.get("/finding/{fid}/challenge_llm/preview")
def finding_challenge_llm_preview(request: Request, fid: int):
    """Preview step of the Challenge-with-LLM flow. Returns the
    resolved fidelity prompt (system + user) for the named finding,
    without sending it to the model. The workspace modal renders the
    user prompt in an editable textarea so the analyst can review (and
    optionally tweak) the exact text the model will see before paying
    for a real call. Admin-gated to mirror the POST handler."""
    user = current_user(request) or {}
    if user.get("role") not in ("admin", "superadmin"):
        return JSONResponse(
            {"ok": False, "error": "forbidden",
             "message": "Challenge with LLM requires admin role."},
            status_code=403)
    f = db.query_one("SELECT id FROM findings WHERE id=%s", (fid,))
    if not f:
        raise HTTPException(404)
    import enhanced_ai as _eai
    result = _eai.build_single_finding_fidelity_prompt(fid)
    if not result.get("ok"):
        return JSONResponse(result, status_code=409)
    return JSONResponse(result)


@app.post("/finding/{fid}/challenge_llm")
async def finding_challenge_llm(request: Request, fid: int):
    """LLM-driven re-grade of a single finding, used by the workspace
    'Challenge with LLM' button on enhanced_ai_testing rows (and any
    other source_tool the analyst wants the model to re-evaluate).

    Loads the finding's assessment context, runs the configured fidelity
    prompt as a one-element batch, persists the verdict via the same
    `_apply_fidelity_verdicts` path the bulk pass uses, and returns the
    decoded verdict so the frontend can show it inline next to the
    button. Admin role required because each call spends LLM budget;
    the assessment's enhanced_ai_budget cap is NOT consulted here
    (single-finding cost is a few cents at most, and the analyst
    explicitly initiated it).

    Optional JSON body field `user_prompt` overrides the rendered user
    prompt — the workspace modal sends back the (possibly edited) text
    from the preview step. The system prompt is NOT overrideable
    because changing it would break verdict-schema parsing."""
    user = current_user(request) or {}
    if user.get("role") not in ("admin", "superadmin"):
        return JSONResponse(
            {"ok": False, "error": "forbidden",
             "message": "Challenge with LLM requires admin role."},
            status_code=403)
    f = db.query_one("SELECT id, assessment_id FROM findings WHERE id=%s",
                       (fid,))
    if not f:
        raise HTTPException(404)
    a = db.query_one(
        "SELECT llm_endpoint_id FROM assessments WHERE id=%s",
        (f["assessment_id"],))
    if not a:
        return JSONResponse(
            {"ok": False, "error": "no_assessment"}, status_code=404)
    # Resolve the same endpoint the original orchestrator pass used,
    # falling back to the system default if the assessment didn't pin
    # one. Mirrors scripts/orchestrator.py:_resolve_endpoint precedence.
    ep = None
    if a.get("llm_endpoint_id"):
        ep = db.query_one("SELECT * FROM llm_endpoints WHERE id=%s",
                           (a["llm_endpoint_id"],))
    if not ep:
        ep = db.query_one(
            "SELECT * FROM llm_endpoints WHERE is_default=1 LIMIT 1")
    if not ep:
        ep = db.query_one(
            "SELECT * FROM llm_endpoints ORDER BY id LIMIT 1")
    if not ep:
        return JSONResponse(
            {"ok": False, "error": "no_endpoint",
             "message": "No LLM endpoint configured."}, status_code=409)

    # Optional user_prompt override carried in the JSON body. The
    # modal preview step shows the analyst the rendered prompt and
    # lets them edit before clicking Run; the edited text comes back
    # here. application/x-www-form-urlencoded isn't supported because
    # FastAPI's request.form() parses the whole body and we need to
    # be tolerant of empty bodies (button click without preview).
    user_prompt_override = None
    try:
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            payload = await request.json()
            user_prompt_override = (payload or {}).get("user_prompt")
    except Exception:
        user_prompt_override = None

    import enhanced_ai as _eai
    result = _eai.run_single_finding_fidelity(
        fid, ep, user_prompt_override=user_prompt_override)
    if not result.get("ok"):
        return JSONResponse(result, status_code=409)
    return JSONResponse(result)


@app.post("/finding/{fid}/run_probe")
async def finding_run_probe(request: Request, fid: int):
    """Live HTTP probe used by the 'Test' buttons that the workspace
    injects next to each curl command in an AI finding's "To Reproduce"
    block. Sends ONE read-only request against ONE URL and returns the
    response (status, headers, body excerpt) plus a host-echo comparison
    badge so the analyst sees immediately whether the probe hit a real
    endpoint or just the host's default error envelope.

    Hard safety guards:
      - admin role required
      - method MUST be GET or HEAD; anything else is rejected
      - URL host MUST match the assessment's fqdn (no scope creep)
      - request runs with no cookies, no auth, no custom headers
      - 10-second timeout
      - 4 KB body excerpt cap

    The echo comparison reuses spa_fallback.Fingerprinter against the
    same host signature the orchestrator's enhanced_ai pass would have
    populated — so a 502 + 11 755-byte body that matches the host's
    cached echo is flagged as 'ECHO — likely FP' before the analyst
    has to eyeball it."""
    user = current_user(request) or {}
    if user.get("role") not in ("admin", "superadmin"):
        return JSONResponse(
            {"ok": False, "error": "forbidden",
             "message": "Live probe requires admin role."},
            status_code=403)
    f = db.query_one("SELECT id, assessment_id FROM findings WHERE id=%s",
                       (fid,))
    if not f:
        raise HTTPException(404)
    a = db.query_one("SELECT fqdn FROM assessments WHERE id=%s",
                       (f["assessment_id"],))
    if not a:
        return JSONResponse(
            {"ok": False, "error": "no_assessment"}, status_code=404)
    fqdn = (a.get("fqdn") or "").strip().lower()

    # Parse the JSON body. Reject anything malformed; the frontend
    # always sends application/json with method + url keys.
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            {"ok": False, "error": "bad_json"}, status_code=400)
    method = (payload.get("method") or "GET").upper().strip()
    url = (payload.get("url") or "").strip()

    if method not in ("GET", "HEAD"):
        return JSONResponse(
            {"ok": False, "error": "method_not_allowed",
             "message": f"Only GET and HEAD are allowed; got {method}."},
            status_code=400)
    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse(
            {"ok": False, "error": "bad_url",
             "message": "URL must start with http:// or https://"},
            status_code=400)

    # Scope check. Strict equality against the assessment's fqdn (with
    # an optional port stripped) — no subdomain wildcards, no bare-IP
    # bypass. The fqdn column is the single source of truth for scope.
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host != fqdn:
        return JSONResponse(
            {"ok": False, "error": "out_of_scope",
             "message": f"URL host '{host}' is outside this assessment's "
                         f"scope (fqdn='{fqdn}'). Only the captured FQDN "
                         f"can be probed live."},
            status_code=400)

    # Run the probe. urllib.request, no redirects, self-signed certs
    # tolerated, 10s ceiling. The probe sends NO cookies, NO auth, NO
    # custom headers other than UA — anything else would be implicit
    # state injection that an analyst hasn't asked for.
    import time as _time
    import ssl as _ssl
    import urllib.request as _urlreq
    import urllib.error as _urlerr
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):
            return None

    opener = _urlreq.build_opener(
        _urlreq.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )
    req = _urlreq.Request(
        url, method=method,
        headers={"User-Agent": "nextgen-dast/probe (+https://hackrange.com)",
                  "Accept": "*/*"})
    t0 = _time.monotonic()
    status = 0
    body = b""
    headers_out: dict[str, str] = {}
    err_text = None
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            body = resp.read(4096)
            headers_out = {k: v for k, v in resp.headers.items()}
    except _urlerr.HTTPError as he:
        status = he.code
        try:
            body = he.read(4096) or b""
        except Exception:
            body = b""
        try:
            headers_out = {k: v for k, v in (he.headers or {}).items()}
        except Exception:
            headers_out = {}
    except Exception as e:
        err_text = f"{e!r}"
    ms = round((_time.monotonic() - t0) * 1000)

    if err_text:
        return JSONResponse({
            "ok": False, "error": "transport_failed",
            "message": err_text, "ms": ms,
        }, status_code=502)

    # Decode body for the response. Don't crash on binary — escape and
    # truncate. The first 4 KB is enough to spot the host echo or a
    # real banner; anything larger goes to a "see full response" link
    # the analyst can copy out of the curl invocation.
    try:
        body_text = body.decode("utf-8", errors="replace")
    except Exception:
        body_text = "<binary response, %d bytes>" % len(body)

    # Echo comparison. Probe the host once (cached for the request
    # process lifetime), look up the signature, compare status + body
    # hash against the cached echo. Robust to a freshly-booted process
    # that hasn't seen this host before.
    import spa_fallback
    import hashlib as _hash
    fp = spa_fallback.Fingerprinter()
    fp.probe_host(f"{parsed.scheme}://{host}")
    sig = fp.host_signature(host) or fp.host_signature(
        f"{parsed.scheme}://{host}")
    echo_match = False
    if sig:
        body_hash = _hash.sha256(body).hexdigest()
        echo_match = (status == sig.get("status")
                      and body_hash in set(sig.get("signatures") or []))

    # Best-effort highlight: if the finding's llm_evidence looks like a
    # quoted body string (long, contains characters typical of HTML /
    # JSON / banners), grep for it in the body. The frontend wraps any
    # match with a <mark> tag. URL-only evidence (just a path) gets
    # skipped to avoid a tautological match.
    raw = {}
    f_full = db.query_one(
        "SELECT raw_data, evidence_url, source_tool, status, "
        "validation_status FROM findings WHERE id=%s", (fid,))
    if f_full and f_full.get("raw_data"):
        try:
            raw = json.loads(f_full["raw_data"])
        except Exception:
            raw = {}
    evidence_str = (raw.get("llm_evidence") or "").strip()
    highlight = None
    if (evidence_str and len(evidence_str) >= 30
            and not evidence_str.startswith(("GET ", "HEAD ", "POST "))
            and "://" not in evidence_str):
        # Looks like a body / banner / envelope quote, not a URL line.
        highlight = evidence_str[:200]

    # Deterministic auto-FP. When the live probe matches the host's
    # echo signature AND the URL we just probed is one the finding
    # itself cited (either evidence_url or a URL parsed out of
    # raw_data.llm_evidence), the path-existence claim that motivated
    # the finding is refuted by the host's own response: every path on
    # this vhost returns the same body. Auto-flip the finding to
    # false_positive — same audit shape as the analyst-override path,
    # tagged so a reviewer can tell it came from a probe rather than a
    # manual decision. We deliberately DO NOT auto-flip on echo_match
    # alone if the probed URL doesn't match the finding's URL: a
    # finding about XSS at /search?q= cited /admin as an unrelated
    # example would not be refuted by an echo on /admin.
    auto_flipped_fp = False
    if echo_match and f_full:
        candidate_urls = []
        if (f_full.get("evidence_url") or "").strip():
            candidate_urls.append(f_full["evidence_url"].strip())
        # raw_data.llm_evidence often carries a "<count>x GET <url>"
        # form. Pick the first URL out of it.
        if evidence_str and "://" in evidence_str:
            import re as _re
            m = _re.search(r"https?://[^\s'\"`)<>|]+", evidence_str)
            if m:
                candidate_urls.append(m.group(0))
        # URL-equality is path-loose: if the probed URL's host+path
        # matches any candidate URL's host+path (ignoring query
        # string), we count it as a self-probe. Avoids missing the
        # match when the curl in the reproduction block adds a
        # ?refresh=0 the original finding didn't carry.
        from urllib.parse import urlsplit as _split
        probed = _split(url)
        probed_key = f"{probed.scheme}://{probed.hostname}{probed.path}"
        for cu in candidate_urls:
            try:
                cs = _split(cu)
                if (probed.hostname == cs.hostname
                        and (probed.path or "/") == (cs.path or "/")):
                    auto_flipped_fp = True
                    break
            except Exception:
                continue
        # Only flip if the finding isn't already in a settled state.
        # Idempotent on repeat probes; doesn't clobber an analyst's
        # explicit "Re-open" / "Mark validated" decision.
        if (auto_flipped_fp
                and (f_full.get("status") or "open") == "open"):
            audit = {
                "kind": "live-probe-echo-match",
                "user": (current_user(request) or {}).get("username"),
                "reason": ("Live probe at " + url + " returned the host's "
                            "echo signature (status="
                            + str(status) + ", body matches cached "
                            "echo body hash). Path-existence claim is "
                            "refuted by the host's path-agnostic "
                            "response."),
                "echo_signature": (
                    {"status": sig.get("status"),
                      "size": sig.get("size")}
                    if sig else None),
                "probed_url": url,
                "set_at": datetime.now(timezone.utc).isoformat(),
            }
            db.execute(
                "UPDATE findings SET status='false_positive', "
                "validation_status='false_positive', "
                "validation_probe='live_probe_echo_match', "
                "validation_run_at=NOW(), "
                "validation_evidence=%s WHERE id=%s",
                (json.dumps(audit, default=str)[:65000], fid))
        else:
            # We matched the URL but the finding was already settled;
            # surface that to the UI but don't write the row.
            auto_flipped_fp = False

    return JSONResponse({
        "ok": True,
        "status": status,
        "content_length": int(headers_out.get("Content-Length") or len(body)),
        "ms": ms,
        "headers": headers_out,
        "body_excerpt": body_text,
        "body_truncated": len(body) >= 4096,
        "echo_match": echo_match,
        "echo_signature": (
            {"status": sig.get("status"), "size": sig.get("size")}
            if sig else None),
        "highlight": highlight,
        "scope": {"fqdn": fqdn, "method": method, "url": url},
        "auto_flipped_fp": auto_flipped_fp,
    })


@app.post("/finding/{fid}/false_positive")
def finding_mark_false_positive(request: Request, fid: int,
                                reason: str = Form("")):
    """Analyst override: confirms this finding is a false positive. The
    optional `reason` is stored alongside the timestamp + acting user so
    audits can reconstruct *why* a finding was suppressed."""
    f = db.query_one("SELECT id FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    user = current_user(request) or {}
    payload = {
        "kind": "analyst-override",
        "user": user.get("username"),
        "reason": (reason or "").strip()[:2000] or None,
        "set_at": datetime.now(timezone.utc).isoformat(),
    }
    db.execute(
        "UPDATE findings SET status = 'false_positive', "
        "validation_status = 'false_positive', "
        "validation_run_at = NOW(), validation_evidence = %s "
        "WHERE id = %s",
        (json.dumps(payload), fid),
    )
    return redirect(f"/finding/{fid}?msg=marked+false+positive")


@app.post("/assessment/{aid}/challenge_all")
def assessment_challenge_all(aid: int):
    """Bulk-challenge: spawn the standalone runner so it works through every
    eligible finding (open, unvalidated, severity ≥ low, has a probe
    matched) without holding the web request open for the duration. The
    UI's existing /assessment/{id}/status polling reflects progress via
    the assessments.current_step field."""
    a = db.query_one("SELECT id FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    log_path = LOGS_DIR / f"challenge_all_{aid}.log"
    log_fh = open(log_path, "ab", buffering=0)
    subprocess.Popen(
        ["python", "-m", "scripts.challenge_runner", str(aid)],
        stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True, cwd="/app",
    )
    return redirect(f"/assessment/{aid}?msg=challenge+all+started")


# ---- Workspace partials + bulk actions -------------------------------------

@app.get("/finding/{fid}/panel", response_class=HTMLResponse)
def finding_panel_fragment(request: Request, fid: int):
    """Detail-pane HTML fragment, swapped into the workspace via fetch.
    Standalone (no layout chrome) so it slots straight into #fw-detail."""
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    return templates.TemplateResponse(
        "finding_panel.html",
        ctx(request, **_finding_panel_context(f)),
    )


@app.get("/finding/{fid}/aside", response_class=HTMLResponse)
def finding_aside_fragment(request: Request, fid: int):
    """Right-rail (AT A GLANCE + actions) HTML fragment for the workspace."""
    f = db.query_one("SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    return templates.TemplateResponse(
        "_finding_aside.html",
        ctx(request, **_finding_panel_context(f)),
    )


@app.post("/finding/{fid}/status")
def finding_set_status(fid: int, status: str = Form(...)):
    """Set findings.status to fixed (Resolve) or accepted_risk (Archive).
    Other statuses are rejected so the route can't be coerced into
    arbitrary state changes."""
    if status not in ("fixed", "accepted_risk", "open"):
        raise HTTPException(400, f"invalid status {status!r}")
    f = db.query_one("SELECT id, assessment_id FROM findings WHERE id = %s",
                     (fid,))
    if not f:
        raise HTTPException(404)
    db.execute("UPDATE findings SET status = %s WHERE id = %s",
               (status, fid))
    return redirect(f"/assessment/{f['assessment_id']}#finding-{fid}")


@app.post("/assessment/{aid}/findings/bulk")
async def assessment_findings_bulk(request: Request, aid: int):
    """Bulk-action endpoint for the workspace toolbar.

    Body: form-data with `action` in {resolve, archive, delete} and one
    or more `finding_ids` entries. All targeted findings must belong to
    THIS assessment — we filter by assessment_id in the SQL so a forged
    list of foreign ids cannot mutate other assessments' rows.
    """
    a = db.query_one("SELECT id FROM assessments WHERE id = %s", (aid,))
    if not a:
        raise HTTPException(404)
    form = await request.form()
    action = (form.get("action") or "").strip().lower()
    raw_ids = form.getlist("finding_ids")
    ids: list[int] = []
    for v in raw_ids:
        try:
            ids.append(int(v))
        except (TypeError, ValueError):
            continue
    if not ids:
        return JSONResponse({"ok": True, "affected": 0})
    placeholders = ",".join(["%s"] * len(ids))
    if action == "resolve":
        n = db.execute(
            f"UPDATE findings SET status = 'fixed' "
            f"WHERE assessment_id = %s AND id IN ({placeholders})",
            [aid, *ids])
    elif action == "archive":
        n = db.execute(
            f"UPDATE findings SET status = 'accepted_risk' "
            f"WHERE assessment_id = %s AND id IN ({placeholders})",
            [aid, *ids])
    elif action == "delete":
        n = db.execute(
            f"DELETE FROM findings "
            f"WHERE assessment_id = %s AND id IN ({placeholders})",
            [aid, *ids])
    else:
        raise HTTPException(400, f"unknown action {action!r}")
    return JSONResponse({"ok": True, "action": action,
                         "requested": len(ids), "affected": n or len(ids)})


@app.post("/finding/{fid}/reopen")
def finding_reopen(fid: int):
    """Undo a false-positive mark. Returns the finding to the open pool
    so it counts toward the score and re-appears in regenerated reports."""
    f = db.query_one("SELECT id FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    db.execute(
        "UPDATE findings SET status = 'open', "
        "validation_status = 'unvalidated', validation_evidence = NULL, "
        "validation_run_at = NULL, validation_probe = NULL WHERE id = %s",
        (fid,),
    )
    return redirect(f"/finding/{fid}?msg=reopened")


@app.get("/branding/logo/{kind}")
def branding_logo_serve(kind: str):
    """Public — needed so the login page and the report can show the logo
    without an active session."""
    p = branding_mod.get_logo_path(kind)
    if not p:
        raise HTTPException(404)
    return FileResponse(str(p), media_type=branding_mod.get_content_type(p.name))


@app.get("/health")
def health():
    return {"ok": True, "proxy_pid": proxy_pid(), "db_ok": db.healthy()}
