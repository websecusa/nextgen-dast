#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Run a complete assessment for an `assessments` row.

Spawned by the web UI as a detached subprocess:
    python -m scripts.orchestrator <assessment_id>

For each (scheme, host) target it:
  1. Runs the per-profile tool set
  2. After each tool: parses its artifacts → inserts findings rows
  3. Updates the assessment status / current_step throughout
  4. (next pass) calls LLM consolidation

Profiles:
  quick      — testssl, nuclei (selected tags)
  standard   — testssl, nuclei (broad), nikto (light), wapiti (default modules)
  thorough   — standard + wapiti -m all + sqlmap on detected wapiti paths
"""
from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, "/app")
import db                              # noqa: E402
import enrichment as enrichment_mod    # noqa: E402
from findings import parse_scan        # noqa: E402
import useragent as ua_mod             # noqa: E402


def _resolve_endpoint(endpoint_id: Optional[int]) -> Optional[dict]:
    """Pick the LLM endpoint to use for enrichment. Falls back to default."""
    if endpoint_id:
        row = db.query_one("SELECT * FROM llm_endpoints WHERE id=%s", (endpoint_id,))
        if row:
            return row
    row = db.query_one("SELECT * FROM llm_endpoints WHERE is_default=1 LIMIT 1")
    if row:
        return row
    return db.query_one("SELECT * FROM llm_endpoints ORDER BY id LIMIT 1")

SCANS_DIR = Path("/data/scans")


def now():
    """Return naive UTC datetime — pymysql binds this directly to MariaDB DATETIME."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def update(aid: int, **fields):
    if not fields:
        return
    sets = ", ".join(f"{k} = %s" for k in fields)
    params = list(fields.values()) + [aid]
    db.execute(f"UPDATE assessments SET {sets} WHERE id = %s", params)


def append_scan_id(aid: int, scan_id: str) -> None:
    row = db.query_one("SELECT scan_ids FROM assessments WHERE id = %s", (aid,))
    ids = (row.get("scan_ids") or "").split(",") if row.get("scan_ids") else []
    ids = [s for s in ids if s] + [scan_id]
    db.execute("UPDATE assessments SET scan_ids = %s WHERE id = %s",
               (",".join(ids), aid))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def new_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


# ---- tool runners -----------------------------------------------------------

def _wrap_with_proxy(scan_dir: Path, scanner_cmd: list[str]) -> tuple[list[str], int]:
    port = free_port()
    return (["/app/scripts/run_scan.sh", str(scan_dir), str(port), "--"]
            + scanner_cmd, port)


def run_tool(tool: str, target: str, profile: str,
             auth_args: Optional[list[str]] = None,
             user_agent: Optional[str] = None) -> str:
    auth_args = auth_args or []
    ua_args = ua_mod.flags_for(tool, user_agent)
    scan_id = new_scan_id()
    sdir = SCANS_DIR / scan_id
    sdir.mkdir(parents=True, exist_ok=True)
    out = sdir / "output.log"

    # Allocate the per-scan mitmdump port up-front so we can pass explicit
    # --proxy / -useproxy flags into the scanner command. Most scanners need
    # the explicit flag — env vars alone aren't honored (esp. Perl/nikto).
    port = 0 if tool == "testssl" else free_port()
    proxy_url = f"http://127.0.0.1:{port}" if port else ""

    if tool == "testssl":
        cmd = ["testssl.sh", "--jsonfile", str(sdir / "report.json"),
               "--quiet", "--color", "0", "--warnings", "off", target]
    elif tool == "nuclei":
        if profile == "quick":
            tags = "exposure,misconfig,cve,default-login"
        elif profile == "thorough":
            tags = "exposure,misconfig,cve,default-login,token-spray,ssrf,lfi,sqli,xss,xxe,redirect,fileupload,tech"
        else:
            tags = "exposure,misconfig,cve,default-login,token-spray,ssrf,tech"
        cmd = ["nuclei", "-target", target,
               "-jsonl-export", str(sdir / "report.jsonl"),
               "-disable-update-check", "-no-color", "-silent",
               "-severity", "info,low,medium,high,critical",
               "-tags", tags,
               "-rl", "20", "-c", "20", "-timeout", "10",
               "-proxy", proxy_url]
    elif tool == "nikto":
        flags = "x6" if profile == "quick" else ("x6789ab" if profile == "thorough" else "x69")
        cmd = ["nikto", "-h", target,
               "-output", str(sdir / "report.html"), "-Format", "htm",
               "-ask", "no", "-nointeractive", "-Tuning", flags,
               "-useproxy", proxy_url]
    elif tool == "wapiti":
        rep = sdir / "report"
        # Curated module set — drop `buster` (path-bruteforce, wandered to
        # parent domain and crashed a#3) and skip others that are pure noise
        # against modern apps. `-m all` is opt-in via the (future) "deep"
        # toggle, not the default for `thorough`.
        modules = ("sql,timesql,xss,permanentxss,ssrf,xxe,exec,file,csrf,"
                   "redirect,upload,crlf,htaccess,htp,backup,cookieflags,"
                   "csp,http_headers,https_redirect,methods,wapp,wp_enum,"
                   "log4shell,shellshock,spring4shell,takeover")
        # subdomain scope keeps it on the target, doesn't follow the
        # registered base domain into siblings.
        cmd = ["wapiti", "-u", target, "-f", "json",
               "-o", str(rep / "report.json"),
               "--flush-session", "--verbose", "1",
               "--scope", "subdomain", "-p", proxy_url,
               "-m", modules,
               # Hard caps: per-attack 30 min, total scan 4 h.
               "--max-attack-time", "1800",
               "--max-scan-time", "14400"]
        cmd += auth_args
    elif tool == "sqlmap":
        cmd = ["sqlmap", "-u", target, "--batch", "--random-agent",
               "--output-dir", str(sdir / "sqlmap"),
               "--level", "2", "--risk", "2", "--smart",
               "--proxy", proxy_url]
    else:
        raise ValueError(f"unknown tool {tool}")

    cmd += ua_args
    if port:
        proxied_cmd = ["/app/scripts/run_scan.sh", str(sdir), str(port), "--"] + cmd
    else:
        proxied_cmd = cmd

    fh = open(out, "ab", buffering=0)
    fh.write(f"$ {' '.join(shlex.quote(c) for c in proxied_cmd)}\n".encode())
    proc = subprocess.Popen(proxied_cmd, stdout=fh, stderr=subprocess.STDOUT,
                            start_new_session=True)
    meta = {
        "id": scan_id, "tool": tool, "target": target,
        "extra": "", "auth_profile": None, "auth_warning": None,
        "cmd": proxied_cmd, "pid": proc.pid,
        "status": "running",
        "started_at": now(), "finished_at": None,
        "proxy_port": port,
    }
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    proc.wait()
    meta["status"] = "finished" if proc.returncode == 0 else "error"
    meta["finished_at"] = now()
    meta["exit_code"] = proc.returncode
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    return scan_id


# ---- finding ingestion ------------------------------------------------------

def _dedup_key(f: dict) -> tuple:
    """Findings collapse on this key — same tool, same OWASP class, same
    title, same URL ⇒ one row with seen_count incremented."""
    return (f["source_tool"], f.get("owasp_category") or "",
            (f.get("title") or "")[:500],
            (f.get("evidence_url") or "")[:1000])


def insert_findings(assessment_id: int, scan_id: str, tool: str,
                    endpoint: Optional[dict] = None) -> int:
    """Group raw parser output by dedup key, insert one row per group with a
    seen_count. Then fold into existing findings already in the DB by
    incrementing seen_count when a row matching the key is already present
    for this assessment.

    Each new finding is also enriched (static catalog → LLM → stub) and its
    enrichment_id stamped on the row. The cache means a given finding type
    is enriched at most once across the whole DB."""
    sdir = SCANS_DIR / scan_id
    groups: dict[tuple, dict] = {}
    for f in parse_scan(tool, sdir):
        key = _dedup_key(f)
        existing = groups.get(key)
        if existing is None:
            f["_count"] = 1
            groups[key] = f
        else:
            existing["_count"] += 1

    n = 0
    for f in groups.values():
        key = _dedup_key(f)
        # resolve enrichment up-front. Cache hit is one SELECT; miss runs
        # static lookup (free) and only then optionally hits the LLM.
        try:
            enrichment_id = enrichment_mod.get_or_create(f, endpoint)
        except Exception:
            enrichment_id = None
        # Is this finding already in the assessment from a previous scan?
        prior = db.query_one(
            "SELECT id, seen_count, enrichment_id FROM findings "
            "WHERE assessment_id=%s AND source_tool=%s "
            "  AND IFNULL(owasp_category,'') = %s "
            "  AND title = %s AND IFNULL(evidence_url,'') = %s LIMIT 1",
            (assessment_id, key[0], key[1], key[2], key[3]),
        )
        if prior:
            # Bump seen_count, and backfill enrichment_id if it was missing.
            if prior.get("enrichment_id") is None and enrichment_id is not None:
                db.execute(
                    "UPDATE findings SET seen_count = seen_count + %s, "
                    "enrichment_id = %s WHERE id=%s",
                    (f["_count"], enrichment_id, prior["id"]),
                )
            else:
                db.execute(
                    "UPDATE findings SET seen_count = seen_count + %s WHERE id=%s",
                    (f["_count"], prior["id"]),
                )
        else:
            db.execute(
                "INSERT INTO findings "
                "(assessment_id, source_tool, source_scan_id, severity, "
                " owasp_category, cwe, cvss, title, description, "
                " evidence_url, evidence_method, remediation, raw_data, "
                " enrichment_id, seen_count) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (assessment_id, f["source_tool"], scan_id, f["severity"],
                 f.get("owasp_category"), f.get("cwe"), f.get("cvss"),
                 (f.get("title") or "")[:500],
                 f.get("description") or "",
                 (f.get("evidence_url") or "")[:1000],
                 (f.get("evidence_method") or "")[:16],
                 f.get("remediation") or "",
                 json.dumps(f.get("raw_data"), default=str),
                 enrichment_id,
                 f["_count"]),
            )
            n += 1
    return n


# ---- profile plans ----------------------------------------------------------

def plan_for_profile(profile: str) -> list[str]:
    if profile == "quick":
        return ["testssl", "nuclei"]
    if profile == "thorough":
        return ["testssl", "nuclei", "nikto", "wapiti"]
    return ["testssl", "nuclei", "nikto", "wapiti"]  # standard


# ---- main -------------------------------------------------------------------

MIN_FREE_GB = 10


def _free_gb(path: str = "/data") -> float:
    import shutil
    return shutil.disk_usage(path).free / (1024 ** 3)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: orchestrator.py <assessment_id>", file=sys.stderr)
        return 2
    aid = int(sys.argv[1])

    a = db.query_one("SELECT * FROM assessments WHERE id = %s", (aid,))
    if not a:
        print(f"no such assessment {aid}", file=sys.stderr)
        return 1

    free = _free_gb()
    if free < MIN_FREE_GB:
        msg = (f"Refusing to start: only {free:.1f} GB free in /data "
               f"(minimum {MIN_FREE_GB} GB). Delete some assessments first.")
        update(aid, status="error", error_text=msg, finished_at=now())
        print(msg, file=sys.stderr)
        return 1

    update(aid, status="running", started_at=now(), worker_pid=os.getpid())

    schemes = []
    if a.get("scan_http"):
        schemes.append("http")
    if a.get("scan_https"):
        schemes.append("https")

    profile = a.get("profile") or "standard"
    plan = plan_for_profile(profile)

    user_agent: Optional[str] = None
    if a.get("user_agent_id"):
        ua_row = db.query_one("SELECT user_agent FROM user_agents WHERE id=%s",
                              (a["user_agent_id"],))
        user_agent = ua_row["user_agent"] if ua_row else None
    if not user_agent:
        ua_row = db.query_one("SELECT user_agent FROM user_agents WHERE is_default=1 LIMIT 1")
        user_agent = ua_row["user_agent"] if ua_row else None

    auth_args: list[str] = []
    if a.get("creds_username") and a.get("creds_password"):
        login_url = (a.get("login_url") or "").strip()
        creds = f"{a['creds_username']}%{a['creds_password']}"
        if login_url:
            # form-based POST login
            auth_args = ["--form-cred", creds, "--form-url", login_url]
        else:
            # fall back to HTTP basic auth — wapiti's --auth-method only
            # accepts basic/digest/ntlm, never "post"
            auth_args = ["--auth-user", a["creds_username"],
                         "--auth-password", a["creds_password"],
                         "--auth-method", "basic"]

    # resolve the LLM endpoint once for the whole assessment. Used only on
    # cache misses, so most assessments cost nothing extra here.
    enrich_endpoint = (_resolve_endpoint(a.get("llm_endpoint_id"))
                       if a.get("llm_tier") != "none" else None)

    total_findings = 0
    try:
        # testssl is TLS-only — runs once against the hostname (not per scheme)
        if "testssl" in plan and a.get("scan_https"):
            target = f"https://{a['fqdn']}"
            update(aid, current_step=f"testssl → {target}")
            scan_id = run_tool("testssl", target, profile,
                               user_agent=user_agent)
            append_scan_id(aid, scan_id)
            total_findings += insert_findings(aid, scan_id, "testssl",
                                              endpoint=enrich_endpoint)
            update(aid, total_findings=total_findings)

        for scheme in schemes:
            target = f"{scheme}://{a['fqdn']}"
            for tool in plan:
                if tool == "testssl":
                    continue  # already handled
                update(aid, current_step=f"{tool} → {target}")
                use_auth = (tool == "wapiti")  # only wapiti supports our auth
                scan_id = run_tool(tool, target, profile,
                                   auth_args=auth_args if use_auth else [],
                                   user_agent=user_agent)
                append_scan_id(aid, scan_id)
                added = insert_findings(aid, scan_id, tool,
                                        endpoint=enrich_endpoint)
                total_findings += added
                update(aid, total_findings=total_findings)
        update(aid, current_step="ingestion complete",
               status="consolidating")
        # LLM consolidation pass goes here in the next iteration.
        # For now we simply mark done.
        update(aid, status="done", current_step="done", finished_at=now())
    except Exception as e:
        update(aid, status="error", error_text=f"{type(e).__name__}: {e}",
               finished_at=now())
        raise


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: orchestrator.py <assessment_id>", file=sys.stderr)
        sys.exit(2)
    run(int(sys.argv[1]))