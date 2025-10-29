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

    if any(path.startswith(p) for p in ADMIN_PATHS) and user.get("role") != "admin":
        return JSONResponse({"error": "admin only"}, status_code=403)

    if request.method in ("POST", "PUT", "DELETE", "PATCH") \
            and user.get("role") != "admin" \
            and not any(path.startswith(p) for p in READONLY_WRITE_OK):
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
        "is_admin": (user.get("role") == "admin") if user else False,
        # csrf_token is rendered into the hidden field of every form that
        # POSTs to a CSRF-protected endpoint. Empty string when the user
        # is not logged in (templates handle that case themselves).
        "csrf_token": (user or {}).get("csrf", ""),
        "brand": brand,
        "web": web_theme,
        **extra,
    }


def _dashboard_data(trend_filter: Optional[str] = None) -> dict:
    """Aggregate the metrics shown on the / overview page.

    Returns a dict with severity counts, finished-assessment metrics, a
    findings-by-day series for the trend chart (last 30 days), the
    top-risk targets, the unresolved-by-age breakdown, the resolved-by-
    age breakdown, and a recent-activity list. All queries skip
    triaged findings (false-positive, fixed, accepted_risk) so the
    dashboard mirrors what's actually actionable.

    `trend_filter`, when set, restricts JUST the trend chart's series
    to assessments whose fqdn or application_id matches the substring.
    The filter intentionally does not propagate to the KPI strip /
    targets / age matrices -- the typeahead is a per-card lens, not a
    global filter.

    Falls back to a zeroed-out dict when the DB isn't reachable so the
    page still renders during a database outage."""
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

    # Findings-by-day for the last 30 days, broken down by severity.
    # Info severity is excluded from the chart series (high-volume /
    # low-signal noise that flattens the criticals visually). The other
    # dashboard surfaces still surface info totals.
    days = [(date.today() - timedelta(days=i)).isoformat()
            for i in range(29, -1, -1)]
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
        f"  AND created_at > NOW() - INTERVAL 30 DAY "
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

    # Top 6 targets ranked by their most recent live risk score (the
    # post-triage value, computed above). a.risk_score is preserved on
    # the row for PDF report regeneration but no longer drives the
    # dashboard ordering or the displayed number.
    target_rows = db.query(
        "SELECT a.fqdn, a.application_id, a.id, "
        "       a.total_findings, a.finished_at "
        "FROM assessments a "
        "JOIN (SELECT fqdn, MAX(id) AS mid FROM assessments "
        "      WHERE status='done' GROUP BY fqdn) t "
        "  ON a.id = t.mid")
    for t in target_rows:
        t["risk_score"] = live_per_aid.get(t["id"])
    targets = sorted(
        target_rows,
        key=lambda t: (-(t["risk_score"] or 0),
                       -(t["finished_at"].timestamp() if t.get("finished_at")
                         and hasattr(t["finished_at"], "timestamp") else 0)),
    )[:6]

    # Unresolved findings broken down by age bucket. Triaged rows
    # (false-positive, resolved, archived) are excluded so the matrix
    # matches the actionable list.
    sev_order = ("critical", "high", "medium", "low", "info")
    ages = {">30 days": {s: 0 for s in sev_order},
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

    # Resolved findings broken down by age bucket. Counterpart to the
    # `ages` matrix: shows what the team has cleared (status fixed or
    # accepted_risk), bucketed by the original finding's age. Useful
    # for measuring backlog burndown -- "we resolved this many old
    # criticals." Aged on created_at because the schema doesn't track
    # status_changed_at.
    resolved_ages = {">30 days": {s: 0 for s in sev_order},
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

    recent = db.query(
        "SELECT id, fqdn, application_id, status, total_findings, "
        "       profile, created_at, finished_at "
        "FROM assessments ORDER BY id DESC LIMIT 6")
    # Decorate recent rows with live open-findings count + risk score
    # so the dashboard matches the /assessments listing. total_findings
    # on the row is the orchestrator's scan-time count and goes stale
    # the moment the analyst triages anything.
    if recent:
        rec_ids = [r["id"] for r in recent]
        ph = ",".join(["%s"] * len(rec_ids))
        rec_findings: dict[int, list[dict]] = {aid: [] for aid in rec_ids}
        for f in db.query(
                f"SELECT assessment_id, severity, status, validation_status "
                f"FROM findings WHERE assessment_id IN ({ph})",
                rec_ids):
            rec_findings.setdefault(f["assessment_id"], []).append(f)
        for r in recent:
            fs = rec_findings.get(r["id"], [])
            r["open_findings"] = sum(
                1 for f in fs
                if (f.get("status") or "open") not in EXCLUDED_FROM_SCORE)
            r["risk_score"] = (live_per_aid.get(r["id"])
                               if r["id"] in live_per_aid
                               else _live_risk_score(fs))

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
                  "filter_matched": filter_matched},
        "targets": targets,
        "ages": ages,
        "resolved_ages": resolved_ages,
        "recent": recent,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request, trend: str = ""):
    """Overview dashboard. `trend` query-param filters the trend chart's
    series by FQDN or application_id substring; the rest of the
    dashboard ignores it."""
    data = _dashboard_data(trend_filter=trend)
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
        ctx(request, endpoints=endpoints, msg=msg, db_ok=db.healthy()),
    )


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
    return templates.TemplateResponse(
        "assess.html",
        ctx(request, endpoints=endpoints, user_agents=uas, recent=recent),
    )


@app.post("/assess")
def assess_start(
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
            })
        except ValueError as e:
            raise HTTPException(400, str(e))
        return redirect(f"/schedule/{sid}")

    aid = db.execute(
        """INSERT INTO assessments
           (fqdn, scan_http, scan_https, profile, llm_tier, llm_endpoint_id,
            user_agent_id, creds_username, creds_password, login_url,
            application_id, keep_only_latest, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'queued')""",
        (fqdn,
         1 if scan_http else 0,
         1 if scan_https else 0,
         profile, llm_tier, llm_endpoint_id_i,
         user_agent_id_i,
         creds_username or None,
         creds_password or None,
         login_url or None,
         application_id,
         keep_flag),
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
def assessments_list(request: Request):
    rows: list[dict] = []
    if db.healthy():
        rows = db.query("SELECT id, fqdn, application_id, profile, llm_tier, "
                        "status, total_findings, created_at, finished_at "
                        "FROM assessments ORDER BY id DESC LIMIT 100")
        # Decorate each row with the LIVE open-findings count and risk
        # score (post-triage). assessments.total_findings is the value
        # the orchestrator wrote at scan time and never re-derives, so
        # it goes stale the moment an analyst marks anything as
        # false_positive / fixed / accepted_risk. One query pulls the
        # findings we need across every row in the page.
        if rows:
            ids = [r["id"] for r in rows]
            placeholders = ",".join(["%s"] * len(ids))
            findings_by_aid: dict[int, list[dict]] = {aid: [] for aid in ids}
            for f in db.query(
                    f"SELECT assessment_id, severity, status, validation_status "
                    f"FROM findings WHERE assessment_id IN ({placeholders})",
                    ids):
                findings_by_aid.setdefault(f["assessment_id"], []).append(f)
            for r in rows:
                fs = findings_by_aid.get(r["id"], [])
                r["open_findings"] = sum(
                    1 for f in fs
                    if (f.get("status") or "open") not in EXCLUDED_FROM_SCORE)
                r["risk_score"] = _live_risk_score(fs)
    return templates.TemplateResponse("assessments.html",
                                      ctx(request, assessments=rows))


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
):
    """Apply edits from the schedule detail form. Empty strings are
    forwarded to schedules_mod.update which normalizes them to NULL for
    nullable columns; the cron expression is re-validated there."""
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


def _finding_test_tls(finding: dict, parsed) -> JSONResponse:
    """Verify a testssl-source finding by re-checking the live TLS
    posture. For cert-shape check IDs (see _CERT_FAST_TESTSSL_IDS) we
    short-circuit to a direct TLS handshake — sub-second instead of the
    ~30s a narrow testssl.sh -S run takes. Anything outside that set
    falls through to the existing testssl.sh path below.

    The testssl.sh path is bounded by:
      * subprocess timeout (90s — narrow flags finish in <30s typical),
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

    # Fast path: cert-shape IDs answered from the leaf cert.
    if testssl_id in _CERT_FAST_TESTSSL_IDS:
        return _finding_test_cert_fast(host, port, testssl_id, finding)

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
            timeout=90.0, check=False,
        )
        proc_stdout = proc.stdout or ""
        proc_stderr = proc.stderr or ""
        proc_rc = proc.returncode
    except _subprocess.TimeoutExpired:
        return JSONResponse({
            "ok": False, "error": "tls_timeout",
            "message": ("testssl.sh timed out after 90s. Try the manual "
                        "Challenge form on the full detail page if you "
                        "need a deeper run."),
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
    users_mod.set_role(uid, role)
    target = users_mod.get_by_id(uid)
    audit_mod.log_event(
        "role_changed",
        actor=audit_mod.actor_from_user(current_user(request)),
        target=audit_mod.actor_from_user(target),
        ip=client_ip(request),
        extra={"new_role": role},
    )
    return redirect("/admin/users?msg=role+updated")


@app.post("/admin/users/{uid}/disabled")
def admin_users_disabled(request: Request, uid: int,
                         disabled: str = Form(""),
                         csrf_token: str = Form("")):
    check_csrf(request, csrf_token)
    is_disabled = bool(disabled)
    users_mod.set_disabled(uid, is_disabled)
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
    users_mod.delete(uid)
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
    """Construct a probe config from the finding's evidence URL and
    invoke toolkit.run_probe. Returns the probe's verdict dict (always —
    errors are captured into the 'error' key, never raised).

    If a cookie is provided, it travels to the probe via stdin JSON only
    — not argv (which would be visible in `ps aux`). The probe's
    SafeClient sends it as a `Cookie:` header on every request."""
    from urllib.parse import urlparse
    url = finding.get("evidence_url") or ""
    # Wapiti (and a couple of other tools) emit findings with a path-
    # only evidence_url like "/login.php". urllib rejects those as
    # "unknown url type", and the probe errors before sending its first
    # request. Resolve to an absolute URL using the owning assessment's
    # FQDN + scheme. Prefer https when the assessment scanned both;
    # fall back to http if that's the only scheme tested.
    if url.startswith("/"):
        aid = finding.get("assessment_id")
        if aid:
            a = db.query_one("SELECT fqdn, scan_http, scan_https "
                             "FROM assessments WHERE id = %s", (aid,))
            if a and a.get("fqdn"):
                scheme = "https" if a.get("scan_https") else (
                    "http" if a.get("scan_http") else "https")
                url = f"{scheme}://{a['fqdn']}{url}"
    parsed = urlparse(url)
    # Lock the probe to the host of the finding so it cannot wander.
    scope = [parsed.hostname] if parsed.hostname else []
    config = {
        "url": url,
        "method": (finding.get("evidence_method") or "GET").upper(),
        "scope": scope,
        "max_requests": int(probe.get("request_budget_max") or 30),
        "max_rps": 5.0,
        "dry_run": False,
        # Pass the finding's title and raw_data through so probes that
        # need source-tool-specific context (the testssl test id, the
        # nuclei matcher name, the wapiti vulnerable parameter, ...)
        # can extract it without the analyst typing it. Probes that
        # don't know about these keys silently absorb them via the
        # unknown-key path in Probe._config_from_stdin.
        "title": finding.get("title") or "",
        "raw_data": finding.get("raw_data") or "",
    }
    # Probes whose manifest declares requires_post need the destructive-
    # method gate opened so the SafeClient will accept their POSTs. The
    # gate is gated by the *manifest*, not by the caller, so a forged
    # finding row cannot trigger destructive operations on a probe that
    # didn't opt in.
    if probe.get("requires_post"):
        config["allow_destructive"] = True
    if cookie:
        config["cookie"] = cookie  # picked up by SafeClient via Probe._build_client
    # Pass the assessment's username (NOT password) into the config so
    # identity-aware probes (e.g. admin_exposure) can detect when the
    # username is reflected in a response body. The probes hash it
    # before storing in evidence so the credential never lands in the
    # persisted verdict in the clear. Probes that don't know about
    # `auth_username` ignore it via the unknown-key path in
    # Probe._config_from_stdin.
    aid = finding.get("assessment_id")
    if aid:
        a = db.query_one(
            "SELECT creds_username FROM assessments WHERE id = %s", (aid,))
        if a and (a.get("creds_username") or "").strip():
            config["auth_username"] = a["creds_username"].strip()
    if extra:
        config.update(extra)
    # Per-probe timeout = its typical budget × 2 seconds (worst case),
    # clamped to 120s so a stuck request can't hang the web request.
    typical = int(probe.get("request_budget_typical") or 12)
    timeout = min(120.0, max(30.0, typical * 2.0))
    return toolkit_mod.run_probe(probe["name"], config, timeout=timeout)


def _verdict_to_status(verdict: dict) -> str:
    """Map a probe verdict into the findings.validation_status enum.
    The probe schema uses validated=True/False/None; we collapse that
    plus 'ok' / 'error' into the four enum values supported by the DB.

    Distinguish a real crash (subprocess exception, safety violation —
    `error` field is set) from a soft refusal (probe ran cleanly but
    decided it could not produce a verdict — `ok=False`, `error=None`).
    Soft refusals map to 'inconclusive' so the analyst sees a neutral
    badge rather than a red 'errored' state for a probe that simply
    didn't have the inputs it needed."""
    if verdict.get("error"):
        return "errored"
    if not verdict.get("ok", True):
        # Soft refusal — surface as inconclusive. The probe's own
        # summary string carries the WHY ("--param is required",
        # "no candidate endpoints found", etc.) for the analyst.
        return "inconclusive"
    v = verdict.get("validated")
    if v is True:
        return "validated"
    if v is False:
        # A confident "no" from the probe — treat as a false positive on
        # the original scanner finding.
        if (verdict.get("confidence") or 0) >= 0.8:
            return "false_positive"
        return "inconclusive"
    return "inconclusive"


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
    if user.get("role") != "admin":
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
