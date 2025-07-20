# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Pentest proxy + scanner UI.

- Manages a mitmdump subprocess in reverse-proxy mode for intercept logging.
- Launches wapiti / nikto scans against configurable targets.
- Serves a small Jinja2 web UI on 127.0.0.1:8888.
"""
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
import auth as auth_mod
import branding as branding_mod
import cleanup as cleanup_mod
import db
import enrichment as enrichment_mod
import llm as llm_mod
import reports as reports_mod
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
    container's PID namespace — typically because the pentest-proxy container
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
            await asyncio.sleep(60)

    task = asyncio.create_task(sweeper())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Pentest Proxy", root_path=ROOT_PATH, lifespan=lifespan)
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
    bottoms = [0.0] * n_pts
    bands: list[dict] = []
    if max_total > 0:
        for sev_name in ("low", "medium", "high", "critical"):
            tops = [bottoms[i] + series[sev_name][i] for i in range(n_pts)]
            top_points = [(round(i * step, 2),
                           round(chart_h - (tops[i] / max_total) * chart_h, 2))
                          for i in range(n_pts)]
            bot_points = [(round(i * step, 2),
                           round(chart_h - (bottoms[i] / max_total) * chart_h, 2))
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

    aid = db.execute(
        """INSERT INTO assessments
           (fqdn, scan_http, scan_https, profile, llm_tier, llm_endpoint_id,
            user_agent_id, creds_username, creds_password, login_url,
            application_id, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'queued')""",
        (fqdn,
         1 if scan_http else 0,
         1 if scan_https else 0,
         profile, llm_tier, llm_endpoint_id_i,
         user_agent_id_i,
         creds_username or None,
         creds_password or None,
         login_url or None,
         application_id),
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
    if sev not in ("", "critical", "high", "medium", "low", "info"):
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
        # Status tabs
        st = f.get("status") or "open"
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
    """Build the variables the finding_panel.html / _finding_aside.html
    partials expect: f, e (enrichment), repro (reproduction block),
    probe (matched validation probe). Tolerant of f=None — used as the
    empty-state path."""
    if not f:
        return {"f": None, "e": None, "repro": None, "probe": None}
    e = None
    if f.get("enrichment_id"):
        e = db.query_one(
            "SELECT * FROM finding_enrichment WHERE id = %s",
            (f["enrichment_id"],))
        if e:
            try:
                e["steps"] = json.loads(e.get("remediation_steps") or "[]")
            except Exception:
                e["steps"] = []
    repro = reports_mod._repro_for(f)
    probe = toolkit_mod.find_probe_for_finding(f)
    return {"f": f, "e": e, "repro": repro, "probe": probe}


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
    payload = {"id": user["id"], "username": user["username"],
               "role": user["role"]}
    cookie = sessions.sign(payload)
    response.set_cookie(
        key=sessions.COOKIE_NAME, value=cookie,
        max_age=sessions.DEFAULT_TTL,
        path=ROOT_PATH or "/",
        httponly=True, secure=True, samesite="strict",
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "", error: str = ""):
    # Already logged in? Send them on.
    cookie = request.cookies.get(sessions.COOKIE_NAME)
    if sessions.verify(cookie):
        return RedirectResponse(next or f"{ROOT_PATH}/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "base": ROOT_PATH, "next": next, "error": error},
    )


@app.post("/login")
def login_submit(request: Request,
                 username: str = Form(...),
                 password: str = Form(...),
                 next: str = Form("")):
    u = users_mod.authenticate(username, password)
    if not u:
        return RedirectResponse(
            f"{ROOT_PATH}/login?error=Invalid+credentials"
            + (f"&next={next}" if next else ""),
            status_code=303,
        )
    target = next if next.startswith(ROOT_PATH or "/") else f"{ROOT_PATH}/"
    response = RedirectResponse(target, status_code=303)
    _set_session_cookie(response, u)
    return response


@app.post("/logout")
def logout():
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
):
    username = username.strip()
    if not re.match(r"^[A-Za-z0-9_.\-]{2,64}$", username):
        raise HTTPException(400, "username must be 2–64 chars, [A-Za-z0-9_.-]")
    if role not in users_mod.ROLES:
        raise HTTPException(400, "invalid role")
    if users_mod.get_by_username(username):
        return redirect(f"/admin/users?msg=user+already+exists")
    pw = password.strip() or users_mod.gen_password()
    users_mod.create(username, pw, role)
    msg = f"created+{username}+pw={pw}"
    return redirect(f"/admin/users?msg={msg}")


@app.post("/admin/users/{uid}/role")
def admin_users_set_role(uid: int, role: str = Form(...)):
    if role not in users_mod.ROLES:
        raise HTTPException(400, "invalid role")
    users_mod.set_role(uid, role)
    return redirect("/admin/users?msg=role+updated")


@app.post("/admin/users/{uid}/disabled")
def admin_users_disabled(uid: int, disabled: str = Form("")):
    users_mod.set_disabled(uid, bool(disabled))
    return redirect("/admin/users?msg=disabled+updated")


@app.post("/admin/users/{uid}/password")
def admin_users_password(uid: int, password: str = Form("")):
    pw = password.strip() or users_mod.gen_password()
    users_mod.set_password(uid, pw)
    return redirect(f"/admin/users?msg=password+for+%23{uid}+set+to+{pw}")


@app.post("/admin/users/{uid}/delete")
def admin_users_delete(request: Request, uid: int):
    me = current_user(request) or {}
    if int(uid) == int(me.get("id", -1)):
        raise HTTPException(400, "cannot delete the account you're logged in as")
    users_mod.delete(uid)
    return redirect("/admin/users?msg=deleted")


@app.post("/me/password")
def me_password(request: Request,
                current_password: str = Form(...),
                new_password: str = Form(...)):
    me = current_user(request) or {}
    u = users_mod.get_by_id(me.get("id", 0))
    if not u or not users_mod.authenticate(u["username"], current_password):
        raise HTTPException(403, "current password incorrect")
    if len(new_password) < 8:
        raise HTTPException(400, "new password must be ≥ 8 characters")
    users_mod.set_password(u["id"], new_password)
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
        "pdf_sev_critical": pdf_sev_critical,
        "pdf_sev_high": pdf_sev_high,
        "pdf_sev_medium": pdf_sev_medium,
        "pdf_sev_low": pdf_sev_low,
        "pdf_sev_info": pdf_sev_info,
    })
    return redirect("/admin/branding/pdf?msg=pdf+branding+saved")


@app.post("/admin/branding/logo/{kind}")
async def admin_branding_logo_upload(kind: str, file: UploadFile = File(...)):
    if kind not in branding_mod.ALLOWED_KINDS:
        raise HTTPException(400, "kind must be 'header' or 'footer'")
    data = await file.read()
    result = branding_mod.save_logo(kind, data)
    if not result.get("ok"):
        return redirect(f"/admin/branding?msg=upload+failed:+{result.get('error','?')}")
    return redirect(f"/admin/branding?msg={kind}+logo+saved")


@app.post("/admin/branding/logo/{kind}/delete")
def admin_branding_logo_delete(kind: str):
    if kind not in branding_mod.ALLOWED_KINDS:
        raise HTTPException(400, "kind must be 'header' or 'footer'")
    branding_mod.delete_logo(kind)
    return redirect(f"/admin/branding?msg={kind}+logo+removed")


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
    non-admin users; the action buttons render disabled in that case."""
    f = db.query_one(
        "SELECT * FROM findings WHERE id = %s", (fid,))
    if not f:
        raise HTTPException(404)
    e = None
    if f.get("enrichment_id"):
        e = db.query_one(
            "SELECT * FROM finding_enrichment WHERE id = %s",
            (f["enrichment_id"],))
    if e:
        try:
            e["steps"] = json.loads(e.get("remediation_steps") or "[]")
        except Exception:
            e["steps"] = []
        try:
            e["references"] = json.loads(e.get("references_json") or "[]")
        except Exception:
            e["references"] = []
    # Probe matched by title / OWASP / CWE — None if no validation tool fits.
    # The template uses this to decide whether to render the Challenge button.
    probe = toolkit_mod.find_probe_for_finding(f)
    # Decode validation_evidence (stored as JSON when a probe ran).
    validation = None
    if f.get("validation_evidence"):
        try:
            validation = json.loads(f["validation_evidence"])
        except Exception:
            validation = {"raw": f["validation_evidence"][:2000]}
    return templates.TemplateResponse(
        "finding_detail.html",
        ctx(request, f=f, e=e, probe=probe, validation=validation),
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
    plus 'ok' / 'error' into the four enum values supported by the DB."""
    if not verdict.get("ok", True) or verdict.get("error"):
        return "errored"
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
    return redirect(f"/finding/{fid}?msg=challenge+result%3A+{new_status}")


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
