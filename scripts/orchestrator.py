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
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, "/app")
import db                              # noqa: E402
import enrichment as enrichment_mod    # noqa: E402
from findings import parse_scan        # noqa: E402
import useragent as ua_mod             # noqa: E402
import consolidation                   # noqa: E402
import cleanup as cleanup_mod          # noqa: E402  — keep_only_latest dedupe
from scripts import challenge_runner   # noqa: E402  — auto-validate pass


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


def detach_scan_id(aid: int, scan_id: str) -> None:
    """Remove `scan_id` from assessments.scan_ids. Used when a scanner
    fails to start or crashes before producing usable output, so the
    orphan sweep can reclaim its now-empty scan dir on the next pass."""
    row = db.query_one("SELECT scan_ids FROM assessments WHERE id = %s", (aid,))
    if not row:
        return
    ids = (row.get("scan_ids") or "").split(",") if row.get("scan_ids") else []
    ids = [s for s in ids if s and s != scan_id]
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
             aid: int,
             auth_args: Optional[list[str]] = None,
             user_agent: Optional[str] = None) -> str:
    auth_args = auth_args or []
    ua_args = ua_mod.flags_for(tool, user_agent)
    scan_id = new_scan_id()
    sdir = SCANS_DIR / scan_id
    sdir.mkdir(parents=True, exist_ok=True)
    # Register ownership of this scan dir with the assessment BEFORE the
    # scanner spawns. If we delay this until run_tool returns (as we used
    # to), a long-running scanner like wapiti can race the periodic
    # orphan sweep in app/cleanup.py: the sweep reads assessments.scan_ids,
    # sees no owner for this fresh dir, and rmtree's it mid-scan — which
    # then crashes the post-wait meta.json rewrite below. Registering
    # up-front closes that window. detach_scan_id() rolls it back if
    # spawning or the scan itself raises before we can finalise meta.json.
    append_scan_id(aid, scan_id)
    try:
        return _run_tool_inner(tool, target, profile, scan_id, sdir,
                               auth_args, ua_args)
    except BaseException:
        detach_scan_id(aid, scan_id)
        raise


def _run_tool_inner(tool: str, target: str, profile: str,
                    scan_id: str, sdir: Path,
                    auth_args: list[str], ua_args: list[str]) -> str:
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
        # Wapiti's JSON report writer opens the output path directly with
        # open(...,"w") and does not create the parent directory. Pre-create
        # it here so the scan does not crash after several minutes of work
        # while emitting the final report.
        rep.mkdir(parents=True, exist_ok=True)
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
    elif tool == "dalfox":
        # dalfox is XSS-focused; speedy single-URL crawl + payload fuzz.
        # JSON output to report.json so findings.parse_dalfox can ingest it.
        # --silence suppresses the banner; --no-spinner keeps the log clean.
        # --skip-bav and --skip-mining-dom keep the scan bounded against
        # large SPAs (Juice Shop's bundle.js takes a long time to mine).
        cmd = ["dalfox", "url", target,
               "--format", "json",
               "--output", str(sdir / "report.json"),
               "--silence", "--no-spinner",
               "--proxy", proxy_url,
               "--skip-bav", "--skip-mining-dom",
               "--worker", "10",
               "--timeout", "10"]
    elif tool == "ffuf":
        # Content discovery — find admin panels, .git/.env leaks, backup
        # files, etc. that crawlers miss because they're not linked. Uses
        # the curated common.txt wordlist baked into the image at
        # /opt/wordlists/web-content.txt.
        #
        # Filtering: -mc 200,301,302,401,403 keeps real-content-or-protected
        # responses; -fs 0 drops empty bodies. -ac (auto-calibrate) learns
        # the host's wildcard 200 fingerprint and filters those out so a
        # site that returns 200 for everything doesn't flood findings.
        # Rate-limited to be polite (40 req/s) and capped at 4 minutes so
        # ffuf can't run away on a slow target.
        target_ffuf = target.rstrip("/") + "/FUZZ"
        cmd = ["ffuf", "-u", target_ffuf,
               "-w", "/opt/wordlists/web-content.txt",
               "-of", "json",
               "-o", str(sdir / "report.json"),
               "-mc", "200,301,302,401,403",
               "-fs", "0",
               "-ac",
               "-t", "20",
               "-rate", "40",
               "-timeout", "10",
               "-maxtime", "240",
               "-x", proxy_url,
               "-s"]
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
                    endpoint: Optional[dict] = None,
                    target: Optional[str] = None) -> int:
    """Group raw parser output by dedup key, insert one row per group with a
    seen_count. Then fold into existing findings already in the DB by
    incrementing seen_count when a row matching the key is already present
    for this assessment.

    Each new finding is also enriched (static catalog → LLM → stub) and its
    enrichment_id stamped on the row. The cache means a given finding type
    is enriched at most once across the whole DB.

    `target` is the scheme://host the scanner ran against. It is used as a
    last-resort default for `evidence_url` so that downstream validation
    probes always have a URL to test against. Nikto's "/"-rooted findings,
    in particular, ship without a URL at all — without this fallback, the
    Challenge button in the UI would refuse to run any probe on them."""
    sdir = SCANS_DIR / scan_id
    groups: dict[tuple, dict] = {}
    for f in parse_scan(tool, sdir):
        # Default the evidence URL to the scan target before deduping, so
        # two findings with the same title but originally-empty URLs
        # collapse correctly and the inserted row carries something the
        # validation pipeline can use.
        #
        # Parsers may also return a path-only URL (e.g. Nikto yields
        # "/vendor/composer/installed.json") — resolve those against the
        # target so the analyst's reproduction curl points at the right
        # full URL instead of just the bare host.
        if target:
            current = (f.get("evidence_url") or "").strip()
            if not current:
                f["evidence_url"] = target
            elif current.startswith("/"):
                from urllib.parse import urljoin
                f["evidence_url"] = urljoin(target, current)
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
#
# Each profile is a list of "tool" identifiers run in order. Most are real
# scanner subprocesses (handled by run_tool); 'enhanced_testing' is a
# synthetic identifier for the in-process probe-pass dispatched by
# run_enhanced_testing(). Premium is the only profile that includes it.

def plan_for_profile(profile: str) -> list[str]:
    # Software Composition Analysis runs in every profile — retire.js
    # against discovered JS, plus OSV-Scanner against any exposed
    # manifest / lockfile, plus an LLM gap-fill for packages with no
    # local cache hit. Cheap (~30 s for most targets) and catches the
    # outdated-component class that the traditional scanners miss.
    #
    # Where ffuf is part of the profile (thorough / premium), it must
    # run BEFORE sca so SCA can crawl ffuf's discovered paths in
    # addition to its built-in seed list. quick / standard have no
    # ffuf, so SCA falls back to the seed list alone.
    if profile == "quick":
        return ["sca", "testssl", "nuclei"]
    if profile == "thorough":
        return ["ffuf", "sca", "testssl", "nuclei", "nikto", "wapiti"]
    if profile == "premium":
        # Everything thorough does, plus sqlmap + dalfox + the
        # high-fidelity probe pass that targets bugs the traditional
        # tools systematically miss.
        return ["ffuf", "sca", "testssl", "nuclei", "nikto", "wapiti",
                "sqlmap", "dalfox", "enhanced_testing"]
    return ["sca", "testssl", "nuclei", "nikto", "wapiti"]  # standard


# ---- SCA dispatch -----------------------------------------------------------
#
# 'sca' is a synthetic tool just like 'enhanced_testing': not a single
# scanner subprocess but a multi-pass in-process runner (manifest hunt +
# retire.js + osv-scanner + LLM augmentation). Implemented in
# scripts/sca_runner.py; wraps the same scan_dir / meta.json / register-
# up-front pattern as run_tool so the orphan sweeper treats it identically.

def run_sca(target: str, profile: str, aid: int) -> str:
    scan_id = new_scan_id()
    sdir = SCANS_DIR / scan_id
    sdir.mkdir(parents=True, exist_ok=True)
    append_scan_id(aid, scan_id)
    try:
        return _run_sca_inner(target, scan_id, sdir, aid)
    except BaseException:
        detach_scan_id(aid, scan_id)
        raise


def _run_sca_inner(target: str, scan_id: str, sdir: Path,
                   aid: int) -> str:
    from scripts import sca_runner  # local import: keeps cold-start light
    log = sdir / "output.log"
    log_fh = open(log, "ab", buffering=0)
    log_fh.write(f"$ sca_runner --target {target}\n".encode())
    started = now()
    try:
        summary = sca_runner.run(target, sdir, assessment_id=aid,
                                 use_llm=True)
    except Exception as e:
        # Don't crash the whole assessment because the SCA pass failed —
        # log the error, mark the meta.json status as 'error', and let
        # the rest of the profile run.
        log_fh.write(f"sca_runner crashed: {type(e).__name__}: {e}\n".encode())
        summary = {"target": target, "error": f"{type(e).__name__}: {e}"}
        meta_status = "error"
    else:
        log_fh.write(json.dumps(summary, indent=2, default=str).encode())
        log_fh.write(b"\n")
        meta_status = "finished"

    meta = {
        "id": scan_id, "tool": "sca", "target": target, "extra": "",
        "auth_profile": None, "auth_warning": None,
        "cmd": ["sca_runner", target],
        "pid": None, "status": meta_status,
        "started_at": started, "finished_at": now(),
        "exit_code": 0 if meta_status == "finished" else 2,
        "summary": summary,
    }
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    log_fh.close()
    return scan_id


# ---- enhanced_testing dispatch ---------------------------------------------
#
# Walks /app/enhanced_testing/probes/, runs each probe against the target
# via the Probe `--stdin` JSON entry point, and writes one verdict JSON
# per probe to <scan_dir>/verdicts/<probe>.json. The findings parser
# (findings.parse_enhanced_testing) reads those files.

ENHANCED_DIR = Path("/app/enhanced_testing")

# Probes that legitimately need POST/PUT (e.g. login). The safety
# framework refuses non-GET unless allow_destructive=True. Listing them
# here is the explicit audit trail of "yes, this probe is allowed to
# issue non-GET requests; here's why."
_PROBES_NEEDING_POST = {
    "auth_default_admin_credentials":  "generic-default login attempts (POST)",
    "auth_vendor_default_credentials": "vendor-specific login attempts "
                                       "(POST/Basic auth across Tomcat, "
                                       "WordPress, Jenkins, Grafana, "
                                       "phpMyAdmin, JBoss, Adminer, Kibana)",
    "auth_sql_login_bypass":           "SQL injection on login form (POST)",
    "auth_nosql_login_bypass":         "NoSQL operator-injection on login (POST)",
    # ----- Round-3 critical batch -------------------------------------
    "ssrf_profile_image_url":          "register/login + POST profile-image URL",
    "xxe_file_upload":                 "multipart POST with XML external-entity payload",
    "deserialization_b2b_eval":        "POST IIFE to /b2b/v2/orders to confirm eval",
    "deserialization_b2b_sandbox_escape": "POST sandbox-escape Function() payload",
    "authz_role_mass_assignment":      "POST /api/Users with role=admin",
    "authz_basket_idor_walk":          "register/login then walk basket ids",
    "authz_basket_manipulation":       "register/login + POST BasketItems with foreign BasketId",
    "auth_oauth_password_from_email":  "POST base64(email) to login endpoint",
    # ----- Round-4 high-authz batch -----------------------------------
    "authz_feedback_userid_assignment": "register/login + POST /api/Feedbacks with foreign UserId",
    "authz_feedback_delete":            "DELETE /api/Feedbacks/<id> (gated by --allow-destroy)",
    "authz_product_review_edit":        "PATCH foreign review (gated by --allow-destroy)",
    "authz_address_idor_walk":          "register/login then walk address ids",
    "authz_basket_checkout_arbitrary":  "POST checkout on victim basket (gated)",
    "authz_order_history_view_all":     "register/login + GET order-history",
    "authz_method_override_admin":      "POST + X-HTTP-Method-Override: PATCH (gated)",
    "authz_deluxe_membership_tamper":   "PATCH own role to deluxe (gated)",
    "authz_user_email_change_other":    "PUT foreign user's email (gated)",
    # ----- Round-5 authn / session batch ------------------------------
    "auth_password_reset_weak_question": "POST reset-password with security-question answer",
    "auth_jwt_no_expiration":            "register/login + replay tampered JWT",
    "auth_logout_does_not_invalidate":   "register/login + GET/POST /logout + replay",
    # ----- Round-6 injection batch ------------------------------------
    "nosql_review_dos_where":            "PATCH reviews with $where time-delay",
    "redos_b2b_orderlines":              "PATCH /b2b orderLinesData with backtracking payload",
    "prototype_pollution_user_patch":    "PUT /api/Users with __proto__ payload (gated)",
    "ssti_pug_username":                 "PUT username with Pug interpolation (gated)",
    "xss_stored_lastloginip":            "register/login + GET /rest/saveLoginIp with iframe",
    # ----- Round-8 medium batch ---------------------------------------
    "auth_username_enum_timing":         "POST timing-statistical login probe",
    "auth_no_brute_force_lockout":       "POST 20 failed logins (gated by trial count)",
    "config_session_cookie_flags":       "POST trigger login + inspect Set-Cookie",
    "auth_password_change_no_current":   "GET/POST change-password without current (gated)",
    "info_graphql_endpoint":             "POST introspection query to /graphql",
}


def _enhanced_probe_files() -> list[Path]:
    pdir = ENHANCED_DIR / "probes"
    if not pdir.is_dir():
        return []
    return sorted(p for p in pdir.glob("*.py")
                  if not p.name.startswith("_"))


def run_enhanced_testing(target: str, profile: str, aid: int) -> str:
    """Run every probe under enhanced_testing/probes against `target`.
    One verdict file per probe is written under
    /data/scans/<scan_id>/verdicts/. Returns the synthetic scan_id.

    Like run_tool, the scan_id is registered with the assessment up-front
    so the orphan sweeper in app/cleanup.py cannot rmtree this dir while
    probes are still running."""
    scan_id = new_scan_id()
    sdir = SCANS_DIR / scan_id
    (sdir / "verdicts").mkdir(parents=True, exist_ok=True)
    append_scan_id(aid, scan_id)
    try:
        return _run_enhanced_testing_inner(target, scan_id, sdir)
    except BaseException:
        detach_scan_id(aid, scan_id)
        raise


def _run_enhanced_testing_inner(target: str, scan_id: str, sdir: Path) -> str:
    log = sdir / "output.log"
    log_fh = open(log, "ab", buffering=0)

    parsed = urllib.parse.urlparse(target) if target else None
    scope = [parsed.hostname] if (parsed and parsed.hostname) else []

    probes = _enhanced_probe_files()
    log_fh.write(f"$ enhanced_testing pass against {target} "
                 f"({len(probes)} probes)\n".encode())

    summary = {"target": target, "probes_run": 0,
               "validated": 0, "refuted": 0,
               "inconclusive": 0, "errored": 0,
               "results": []}

    for probe_path in probes:
        probe_name = probe_path.stem
        log_fh.write(f"\n--- {probe_name} ---\n".encode())
        cfg = {
            "url": target,
            "method": "GET",
            "scope": scope,
            "max_requests": 60,
            "max_rps": 5.0,
            "dry_run": False,
            "allow_destructive": probe_name in _PROBES_NEEDING_POST,
        }
        try:
            proc = subprocess.run(
                [sys.executable, str(probe_path), "--stdin"],
                input=json.dumps(cfg).encode(),
                capture_output=True,
                timeout=180,
                check=False,
            )
            out = proc.stdout.decode("utf-8", "replace")
            verdict = json.loads(out) if out.strip().startswith("{") else {
                "ok": False, "error": "non-JSON probe output",
                "stdout": out[:1000],
                "stderr": proc.stderr.decode("utf-8", "replace")[:1000],
            }
        except Exception as e:
            verdict = {"ok": False,
                       "error": f"{type(e).__name__}: {e}"}

        # Write one file per probe so the parser can read them
        # independently and so the analyst can inspect any single
        # probe's evidence by name.
        (sdir / "verdicts" / f"{probe_name}.json").write_text(
            json.dumps(verdict, indent=2, default=str))

        summary["probes_run"] += 1
        if not verdict.get("ok", True) or verdict.get("error"):
            summary["errored"] += 1
        elif verdict.get("validated") is True:
            summary["validated"] += 1
        elif verdict.get("validated") is False:
            summary["refuted"] += 1
        else:
            summary["inconclusive"] += 1
        summary["results"].append({
            "probe": probe_name,
            "validated": verdict.get("validated"),
            "confidence": verdict.get("confidence"),
            "summary": (verdict.get("summary") or "")[:200],
        })
        log_fh.write(
            f"  {probe_name}: validated={verdict.get('validated')} "
            f"conf={verdict.get('confidence')}\n".encode())

    (sdir / "summary.json").write_text(json.dumps(summary, indent=2))
    meta = {
        "id": scan_id, "tool": "enhanced_testing",
        "target": target, "extra": "",
        "auth_profile": None, "auth_warning": None,
        "cmd": ["enhanced_testing", target],
        "pid": None, "status": "finished",
        "started_at": now(), "finished_at": now(),
        "exit_code": 0,
        "probes_run": summary["probes_run"],
        "validated": summary["validated"],
    }
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    log_fh.close()
    return scan_id


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
            # run_tool / run_enhanced_testing register the scan_id with
            # the assessment internally (before spawning), so we don't
            # call append_scan_id here anymore — doing so would double-add.
            scan_id = run_tool("testssl", target, profile, aid=aid,
                               user_agent=user_agent)
            total_findings += insert_findings(aid, scan_id, "testssl",
                                              endpoint=enrich_endpoint,
                                              target=target)
            update(aid, total_findings=total_findings)

        for scheme in schemes:
            target = f"{scheme}://{a['fqdn']}"
            for tool in plan:
                if tool == "testssl":
                    continue  # already handled
                if tool == "enhanced_testing":
                    # Synthetic "tool" — run the in-process probe pass.
                    # Premium-only; runs once per scheme so probes can
                    # exercise both http and https surfaces if the
                    # assessment opted into both.
                    update(aid, current_step=f"enhanced_testing → {target}")
                    scan_id = run_enhanced_testing(target, profile, aid=aid)
                    added = insert_findings(aid, scan_id, "enhanced_testing",
                                            endpoint=enrich_endpoint,
                                            target=target)
                    total_findings += added
                    update(aid, total_findings=total_findings)
                    continue
                if tool == "sca":
                    # Software Composition Analysis — manifest hunt +
                    # retire.js + osv-scanner + LLM augmentation. Runs
                    # once per scheme so https-only and http-only paths
                    # are both inspected; the LLM cache de-dupes
                    # repeated lookups across schemes.
                    update(aid, current_step=f"sca → {target}")
                    scan_id = run_sca(target, profile, aid=aid)
                    added = insert_findings(aid, scan_id, "sca",
                                            endpoint=enrich_endpoint,
                                            target=target)
                    total_findings += added
                    update(aid, total_findings=total_findings)
                    continue
                update(aid, current_step=f"{tool} → {target}")
                use_auth = (tool == "wapiti")  # only wapiti supports our auth
                scan_id = run_tool(tool, target, profile, aid=aid,
                                   auth_args=auth_args if use_auth else [],
                                   user_agent=user_agent)
                added = insert_findings(aid, scan_id, tool,
                                        endpoint=enrich_endpoint,
                                        target=target)
                total_findings += added
                update(aid, total_findings=total_findings)
        update(aid, current_step="ingestion complete",
               status="consolidating")
        # Basic-tier roll-up: ask the LLM to produce an executive summary,
        # an overall risk score, and a top-priorities list from the
        # deduplicated findings. Per-flow deep analysis (advanced tier)
        # will hook in here as well in a follow-up. A failure in this
        # pass must NOT lose the underlying findings — log the error and
        # still mark the assessment done so the user can recover.
        if a.get("llm_tier") in ("basic", "advanced"):
            update(aid, current_step="consolidating: roll-up + exec summary")
            try:
                cres = consolidation.run(aid, enrich_endpoint)
                if not cres.get("ok"):
                    update(aid, error_text=(
                        f"consolidation failed: {cres.get('error')}"
                    ))
            except Exception as e:
                update(aid, error_text=f"consolidation crashed: {e!r}")
        # Automatic post-scan validation pass: re-run every read-only
        # toolkit probe against its matched findings to catch obvious
        # false positives before the analyst opens the assessment. A
        # high-confidence "not reproduced" verdict auto-flips the
        # finding to status=false_positive; everything else is left
        # for human triage. We deliberately fence this in a try/except
        # so a flaky probe (timeout, target down, etc.) cannot mark
        # the whole assessment as errored — the scan results are
        # already persisted at this point.
        update(aid, current_step="auto_validate: starting")
        try:
            challenge_runner.run(aid, safe_only=True)
        except Exception as e:
            update(aid, error_text=f"auto_validate crashed: {e!r}")
        update(aid, status="done", current_step="done", finished_at=now())

        # Auto-dedupe pass. If this assessment was created with
        # keep_only_latest=1 (one-off /assess form, REST API, or carried
        # through from a scan_schedules row), every other completed
        # assessment for the same FQDN gets marked status='deleting' and
        # the lifespan sweeper tears it down asynchronously. Fenced in a
        # try/except so a dedupe failure can never roll back the 'done'
        # status we just wrote.
        try:
            n = cleanup_mod.dedupe_for_fqdn(aid)
            if n:
                print(f"[orchestrator] keep_only_latest: marked {n} prior "
                      f"assessment(s) for deletion", flush=True)
        except Exception as e:
            print(f"[orchestrator] dedupe pass failed: {e!r}", flush=True)
    except Exception as e:
        update(aid, status="error", error_text=f"{type(e).__name__}: {e}",
               finished_at=now())
        raise


if __name__ == "__main__":
    # main() validates argv and reads the assessment_id itself,
    # so we just propagate its exit code.
    sys.exit(main())