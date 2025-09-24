#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
SCA stage runner — invoked by the orchestrator for every assessment.

Four passes per target:

  1. Manifest hunt — request well-known exposed paths
       (/package.json, /yarn.lock, /composer.json, /Gemfile.lock,
        /requirements.txt, /go.mod, /pom.xml, /Pipfile.lock,
        /.git/config, /Gemfile, /pnpm-lock.yaml)
     and persist any 200-OK responses under
     <scan_dir>/sca/manifests/.

  2. JS library scan — fetch the target's HTML, extract every
     <script src=...> and <link rel="modulepreload" href=...>, then
     run retire.js against the discovered JS URLs. This is the path
     that catches the jQuery / Angular / Bootstrap CVE class.

  3. Lockfile audit — for each manifest the hunt retrieved, run
     osv-scanner --lockfile=...; for npm/yarn/pnpm specifically also
     try the matching native audit tool when both manifest + lockfile
     are present.

  4. LLM gap-fill — for any (ecosystem, name, version) we identified
     but no DB row matched, ask app/sca.py for an augment lookup.
     Cached negative answers short-circuit the LLM call.

Findings + observed packages are written to:
  <scan_dir>/sca/findings.json    — array of normalized finding dicts
  <scan_dir>/sca/packages.json    — array of {ecosystem,name,version,
                                              source_url, detection_method}

The orchestrator then calls findings.parse_sca() to ingest them.

CLI:
  python -m scripts.sca_runner --target https://host:port [--scan-dir DIR]
                               [--assessment-id N] [--no-llm]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, "/app")
try:
    import sca as sca_mod  # noqa: E402
    import db as _db  # noqa: E402
except Exception:
    sca_mod = None  # type: ignore[assignment]
    _db = None  # type: ignore[assignment]


# ---- well-known manifest paths (per ecosystem) ------------------------------
#
# Each entry maps a URL path under the target root to the (ecosystem, kind)
# that osv-scanner expects when it sees the file. `kind` lets us distinguish
# manifests (which describe declared deps) from lockfiles (which pin
# resolved versions) — osv-scanner needs the lockfile flavor to do anything
# useful, so manifest-only ecosystems (a bare requirements.txt without a
# lock) are downgraded to "best-effort" mode.

MANIFEST_PATHS: list[tuple[str, str, str]] = [
    # path,                          ecosystem,    kind
    ("/package.json",                "npm",        "manifest"),
    ("/package-lock.json",           "npm",        "lockfile"),
    ("/yarn.lock",                   "npm",        "lockfile"),
    ("/pnpm-lock.yaml",              "npm",        "lockfile"),
    ("/composer.json",               "Packagist",  "manifest"),
    ("/composer.lock",               "Packagist",  "lockfile"),
    ("/Gemfile",                     "RubyGems",   "manifest"),
    ("/Gemfile.lock",                "RubyGems",   "lockfile"),
    ("/requirements.txt",            "PyPI",       "lockfile"),
    ("/Pipfile",                     "PyPI",       "manifest"),
    ("/Pipfile.lock",                "PyPI",       "lockfile"),
    ("/poetry.lock",                 "PyPI",       "lockfile"),
    ("/go.mod",                      "Go",         "lockfile"),
    ("/go.sum",                      "Go",         "lockfile"),
    ("/pom.xml",                     "Maven",      "manifest"),
    ("/Cargo.toml",                  "crates.io",  "manifest"),
    ("/Cargo.lock",                  "crates.io",  "lockfile"),
    # dotfile leaks worth grabbing for posterity even though osv-scanner
    # cannot consume them; we surface the leak as its own finding.
    ("/.git/config",                 "git",        "leak"),
    ("/.env",                        "env",        "leak"),
]

# Cap how many JS URLs we feed to retire.js per target. Each URL is one
# HTTP fetch — be polite.
MAX_JS_URLS = 30
# Default per-request timeout. Targets behind misbehaving WAFs sometimes
# stall; bound the runner instead of hanging the whole assessment.
HTTP_TIMEOUT_S = 15
# Cap on bytes we read from any one response. Manifests are small; JS
# files can be huge but we only need the first ~2 MB for retire's
# version-string fingerprint to work.
MAX_BYTES = 2_000_000


# ---- HTTP helpers -----------------------------------------------------------

class _UA:
    """Best-effort default User-Agent. Overridable via constructor for
    callers that want to mirror the assessment's chosen UA."""
    DEFAULT = "nextgen-dast-sca/1.0 (authorized SCA scanner)"


def _fetch(url: str, *, ua: str = _UA.DEFAULT,
           timeout: float = HTTP_TIMEOUT_S) -> Optional[tuple[int, bytes, dict]]:
    """Minimal urllib fetch that returns (status, body, headers) or None
    on network failure. Caps body size to MAX_BYTES so a misbehaving
    target can't OOM the runner."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                body = body[:MAX_BYTES]
            return (resp.status, body,
                    {k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BYTES + 1)[:MAX_BYTES]
        except Exception:
            body = b""
        return (e.code, body, {})
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        return None


# ---- manifest hunt ----------------------------------------------------------

def _looks_like_html(body: bytes, headers: dict) -> bool:
    """Heuristic: SPA frameworks serve a wildcard /index.html for unknown
    paths. We don't want to mistake that for a legit /package.json. Reject
    when the response is text/html or starts with the usual HTML
    boilerplate."""
    ctype = (headers.get("content-type") or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype:
        return True
    head = body[:128].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def hunt_manifests(target: str, save_dir: Path) -> list[dict]:
    """Try every well-known manifest path against `target`. Save every
    hit to <save_dir>/<basename> and return one descriptor per hit:

        {"path": "/package.json",
         "url": "https://host/package.json",
         "ecosystem": "npm",
         "kind": "manifest",
         "saved_to": "/data/scans/.../sca/manifests/package.json",
         "bytes": 1234}
    """
    save_dir.mkdir(parents=True, exist_ok=True)
    hits: list[dict] = []
    base = target.rstrip("/")
    for path, eco, kind in MANIFEST_PATHS:
        url = base + path
        result = _fetch(url)
        if not result:
            continue
        status, body, headers = result
        if status != 200 or not body:
            continue
        if _looks_like_html(body, headers):
            continue
        # Save under a deterministic name so a re-run overwrites the prior
        # download cleanly. The leading slash from path is stripped so we
        # don't get directory-escape behavior.
        local_name = path.lstrip("/").replace("/", "_") or "root"
        out_path = save_dir / local_name
        try:
            out_path.write_bytes(body)
        except OSError:
            continue
        hits.append({
            "path": path, "url": url,
            "ecosystem": eco, "kind": kind,
            "saved_to": str(out_path),
            "bytes": len(body),
        })
    return hits


# ---- JS URL discovery -------------------------------------------------------

_SCRIPT_SRC_RE = re.compile(
    rb"""<\s*(?:script|link)[^>]*?(?:src|href)\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def discover_js_urls(target: str) -> list[str]:
    """Fetch the target's root HTML and extract every <script src=...>
    and <link rel=modulepreload href=...> URL pointing at a JS asset.
    Returns an absolute-URL list capped at MAX_JS_URLS."""
    result = _fetch(target)
    if not result:
        return []
    status, body, _ = result
    if status >= 400 or not body:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for m in _SCRIPT_SRC_RE.finditer(body):
        ref = m.group(1).decode("utf-8", "replace").strip()
        if not ref or ref.startswith(("data:", "javascript:", "mailto:")):
            continue
        absolute = urllib.parse.urljoin(target, ref)
        # Skip non-JS assets — modulepreload may also link to fonts etc.
        if not (absolute.split("?", 1)[0].endswith(".js") or
                "/js/" in absolute or "/static/" in absolute):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        urls.append(absolute)
        if len(urls) >= MAX_JS_URLS:
            break
    return urls


# ---- retire.js wrapper ------------------------------------------------------

def _retire_signature_path() -> Optional[str]:
    """Prefer the on-disk overlay refreshed by update_scanners.py; fall
    back to the baseline shipped in the image."""
    overlay = Path("/data/sca/retire/jsrepository.json")
    baseline = Path("/opt/sca/retire/jsrepository.json")
    if overlay.is_file() and overlay.stat().st_size > 1000:
        return str(overlay)
    if baseline.is_file():
        return str(baseline)
    return None


def run_retire(js_urls: Iterable[str], scan_dir: Path) -> list[dict]:
    """Invoke retire.js once per URL (it doesn't support batching from
    the command line). Returns a list of {url, component, version,
    vulnerabilities[]} dicts — one per detected library, multiple per URL
    if the file bundles several frameworks. Failures are logged to
    <scan_dir>/sca/retire.log and skipped silently in the return value."""
    retire_bin = "/usr/bin/retire"
    if not Path(retire_bin).is_file():
        # retire is installed via npm -g; resolve the actual location.
        proc = subprocess.run(["which", "retire"], capture_output=True, text=True)
        retire_bin = proc.stdout.strip() or "retire"
    sig_arg: list[str] = []
    sig_path = _retire_signature_path()
    if sig_path:
        sig_arg = ["--jsrepo", sig_path]

    log_path = scan_dir / "sca" / "retire.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "ab", buffering=0)

    findings: list[dict] = []
    for url in js_urls:
        # Download into a temp file — retire.js scans paths, not URLs.
        result = _fetch(url)
        if not result:
            log_fh.write(f"[skip] could not fetch {url}\n".encode())
            continue
        status, body, _ = result
        if status >= 400 or not body:
            continue
        # Stable temp path so re-runs overwrite, and so the path
        # in the audit log matches what an analyst would re-scan.
        tmp = scan_dir / "sca" / "js" / urllib.parse.quote(url, safe="")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        try:
            tmp.write_bytes(body)
        except OSError:
            continue

        # retire 5.x dropped the legacy --js flag — the binary now scans
        # JS by default and only takes --path. Keeping --exitwith 0 so a
        # detection doesn't make us read a non-zero exit as a failure.
        cmd = [retire_bin, "--outputformat", "json",
               "--exitwith", "0",
               "--path", str(tmp)] + sig_arg
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=60)
        except subprocess.TimeoutExpired:
            log_fh.write(f"[timeout] {url}\n".encode())
            continue
        log_fh.write(f"$ {' '.join(cmd)}\n".encode())
        log_fh.write((proc.stdout or "")[:2000].encode() + b"\n")
        if proc.returncode not in (0, 13):  # 13 = vulnerabilities found
            log_fh.write(f"[exit {proc.returncode}] {proc.stderr[:400]}\n".encode())
        # retire emits one JSON object — top-level is a list of file results,
        # each with .results[] of detected components.
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            log_fh.write(b"[parse-error] non-JSON stdout\n")
            continue
        for file_entry in data.get("data", []) or []:
            for comp in file_entry.get("results", []) or []:
                findings.append({
                    "url": url,
                    "component": comp.get("component") or "",
                    "version": comp.get("version") or "",
                    "vulnerabilities": comp.get("vulnerabilities") or [],
                })
    log_fh.close()
    return findings


# ---- osv-scanner wrapper ----------------------------------------------------

def _osv_scanner_bin() -> str:
    overlay = Path("/data/scanners/osv-scanner/osv-scanner")
    if overlay.is_file():
        return str(overlay)
    return "osv-scanner"


def run_osv_scanner(manifest_hits: list[dict], scan_dir: Path) -> list[dict]:
    """Run osv-scanner against each retrieved manifest/lockfile and
    return the list of vulnerable-package entries. Findings are grouped
    by (ecosystem, name, version) so the parser can emit one row per
    (package, vuln) tuple."""
    out: list[dict] = []
    if not manifest_hits:
        return out
    log_path = scan_dir / "sca" / "osv.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "ab", buffering=0)
    bin_path = _osv_scanner_bin()
    for hit in manifest_hits:
        if hit.get("kind") == "leak":
            continue
        cmd = [bin_path, "--format=json",
               f"--lockfile={hit['saved_to']}"]
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=120)
        except subprocess.TimeoutExpired:
            log_fh.write(f"[timeout] {hit['saved_to']}\n".encode())
            continue
        log_fh.write(f"$ {' '.join(cmd)}\n".encode())
        log_fh.write((proc.stdout or "")[:2000].encode() + b"\n")
        stdout = proc.stdout or ""
        if not stdout.strip():
            continue
        # osv-scanner prepends a "Scanned ... file and found N packages"
        # banner to stdout. Strip everything before the first '{' so the
        # downstream JSON parser doesn't choke.
        first_brace = stdout.find("{")
        if first_brace > 0:
            stdout = stdout[first_brace:]
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            continue
        # osv-scanner emits a top-level {"results":[{packages:[{package,
        # vulnerabilities}]}]} structure.
        for r in data.get("results", []) or []:
            for pkg in r.get("packages", []) or []:
                pkg_info = pkg.get("package", {}) or {}
                for v in pkg.get("vulnerabilities", []) or []:
                    out.append({
                        "ecosystem": pkg_info.get("ecosystem") or hit["ecosystem"],
                        "name": pkg_info.get("name") or "",
                        "version": pkg_info.get("version") or "",
                        "manifest_url": hit["url"],
                        "vulnerability": v,
                    })
    log_fh.close()
    return out


# ---- normalization ----------------------------------------------------------

def _severity_from_vuln(vuln: dict) -> str:
    """Pick a severity label from an OSV record. OSV stores severity
    under .severity[] (CVSS) and .database_specific.severity (textual).
    Fall back to the highest-CVSS class we can derive."""
    sev = ((vuln.get("database_specific") or {}).get("severity") or "").lower()
    if sev in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if sev == "moderate" else sev
    # Try CVSS vectors
    for s in vuln.get("severity") or []:
        score = s.get("score") or ""
        # Score may be a base score or a CVSS3 vector — handle both
        m = re.search(r"(\d+\.\d+)", str(score))
        if m:
            try:
                base = float(m.group(1))
            except ValueError:
                continue
            if base >= 9.0:
                return "critical"
            if base >= 7.0:
                return "high"
            if base >= 4.0:
                return "medium"
            if base > 0:
                return "low"
    return "medium"  # OSV doesn't ship "info"-class vulns


def _retire_severity(vuln: dict) -> str:
    sev = (vuln.get("severity") or "medium").lower()
    if sev in ("critical", "high", "medium", "low", "info"):
        return sev
    return "medium"


def _normalize_retire_finding(rf: dict, target_url: str) -> Iterable[dict]:
    """One retire.js result -> 0..N normalized finding dicts."""
    component = rf.get("component") or ""
    version = rf.get("version") or ""
    vulns = rf.get("vulnerabilities") or []
    if not vulns:
        # An identified-but-clean library is not a finding, but we still
        # want to surface it as a low-severity "outdated component" line
        # if the version is detectably old. The decision of what counts
        # as outdated is left to the LLM augmentation pass.
        return
    for v in vulns:
        cves = v.get("identifiers", {}).get("CVE") or []
        cve = cves[0] if cves else None
        sev = _retire_severity(v)
        title = (f"{component} {version}: "
                 f"{(v.get('summary') or v.get('identifiers',{}).get('summary') or '').strip() or 'known vulnerability'}")
        yield {
            "source_tool": "sca",
            "severity": sev,
            "title": title[:500],
            "description": (
                f"{component}@{version} matched a retire.js signature.\n\n"
                f"Range: {v.get('below') or v.get('atOrAbove') or '(any)'}\n"
                f"Identifiers: " + ", ".join(
                    [str(c) for c in cves]
                    + [str(g) for g in v.get('identifiers', {}).get('githubID', [])]
                    + [str(s) for s in v.get('identifiers', {}).get('summary', [])
                       if isinstance(s, str)]
                )
            ),
            "owasp_category": "A06:2021-Vulnerable_and_Outdated_Components",
            "cwe": "1104",
            "cvss": None,
            "evidence_url": rf.get("url") or target_url,
            "evidence_method": "GET",
            "remediation": (
                f"Upgrade {component} to a patched release "
                f"(see {', '.join(v.get('info') or [])[:200]})."),
            "raw_data": {
                "detector": "retire.js",
                "component": component,
                "version": version,
                "vulnerability": v,
            },
            "_sca_pkg": {
                "ecosystem": "npm",
                "name": component,
                "version": version,
                "source_url": rf.get("url") or target_url,
                "detection_method": "retire",
                "matched_cves": cves,
            },
        }


def _normalize_osv_finding(rec: dict) -> dict:
    v = rec.get("vulnerability") or {}
    name = rec.get("name") or "(unknown)"
    version = rec.get("version") or "(unknown)"
    cves = v.get("aliases") or []
    cve = next((c for c in cves if c.startswith("CVE-")), None)
    summary = (v.get("summary") or v.get("details") or "").strip()
    sev = _severity_from_vuln(v)
    return {
        "source_tool": "sca",
        "severity": sev,
        "title": f"{name} {version}: {summary or v.get('id', 'OSV vulnerability')}"[:500],
        "description": (
            f"{name}@{version} ({rec.get('ecosystem')}) is affected by "
            f"{v.get('id') or cve or 'an OSV record'}.\n\n"
            f"{(v.get('details') or '')[:1500]}"),
        "owasp_category": "A06:2021-Vulnerable_and_Outdated_Components",
        "cwe": "1104",
        "cvss": None,
        "evidence_url": rec.get("manifest_url"),
        "evidence_method": "GET",
        "remediation": (
            f"Upgrade {name} to a patched release. "
            f"OSV record: {v.get('id') or cve}."),
        "raw_data": {
            "detector": "osv-scanner",
            "ecosystem": rec.get("ecosystem"),
            "package": {"name": name, "version": version},
            "vulnerability": v,
        },
        "_sca_pkg": {
            "ecosystem": rec.get("ecosystem") or "",
            "name": name,
            "version": version,
            "source_url": rec.get("manifest_url"),
            "detection_method": "lockfile",
            "matched_cves": cves,
        },
    }


def _leak_finding(hit: dict) -> dict:
    """Turn a /.git/config or /.env exposure into its own finding."""
    return {
        "source_tool": "sca",
        "severity": "high",
        "title": f"Sensitive file exposed: {hit['path']}",
        "description": (
            f"The target served {hit['path']} ({hit['bytes']} bytes). "
            f"This file commonly contains source-control or environment "
            f"secrets and must not be web-accessible."),
        "owasp_category": "A05:2021-Security_Misconfiguration",
        "cwe": "538",
        "cvss": None,
        "evidence_url": hit["url"],
        "evidence_method": "GET",
        "remediation": (
            "Block access to dotfiles and version-control metadata at the "
            "web server / CDN layer, or move them outside the document root."),
        "raw_data": {
            "detector": "manifest-hunt",
            "leak": hit,
        },
    }


def _leaked_manifest_finding(hit: dict) -> dict:
    return {
        "source_tool": "sca",
        "severity": "low",
        "title": f"Build manifest exposed: {hit['path']}",
        "description": (
            f"{hit['path']} is reachable on the public web. While not "
            f"itself a secret, it discloses dependency names and versions "
            f"that materially help an attacker pick exploits. The SCA "
            f"runner used the file to enumerate vulnerable libraries; "
            f"see other findings on this scan for details."),
        "owasp_category": "A05:2021-Security_Misconfiguration",
        "cwe": "200",
        "cvss": None,
        "evidence_url": hit["url"],
        "evidence_method": "GET",
        "remediation": (
            f"Block access to {hit['path']} at the web server or remove "
            f"it from the deployed artifact."),
        "raw_data": {
            "detector": "manifest-hunt",
            "manifest": hit,
        },
    }


# ---- LLM augmentation hook --------------------------------------------------

def _llm_endpoint_for(assessment_id: Optional[int]) -> Optional[dict]:
    if _db is None or assessment_id is None:
        return None
    try:
        a = _db.query_one("SELECT llm_endpoint_id, llm_tier "
                          "FROM assessments WHERE id=%s", (assessment_id,))
        if not a or a.get("llm_tier") == "none":
            return None
        if a.get("llm_endpoint_id"):
            row = _db.query_one("SELECT * FROM llm_endpoints WHERE id=%s",
                                (a["llm_endpoint_id"],))
            if row:
                return row
        return _db.query_one("SELECT * FROM llm_endpoints "
                             "WHERE is_default=1 LIMIT 1")
    except Exception:
        return None


def augment_with_llm(packages: list[dict], assessment_id: Optional[int],
                     scan_dir: Path) -> list[dict]:
    """For each (eco, name, version) tuple that has not already produced
    a finding, ask the LLM cache layer if anything matches. Returns
    additional findings to merge."""
    if sca_mod is None:
        return []
    endpoint = _llm_endpoint_for(assessment_id)
    extra: list[dict] = []
    log_path = scan_dir / "sca" / "llm.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "ab", buffering=0)
    try:
        for pkg in packages:
            eco, name, ver = pkg.get("ecosystem"), pkg.get("name"), pkg.get("version")
            if not (eco and name and ver):
                continue
            try:
                vulns = sca_mod.lookup_or_augment(eco, name, ver,
                                                  endpoint=endpoint)
            except Exception as e:
                log_fh.write(f"[err] {eco} {name}@{ver}: {e!r}\n".encode())
                continue
            if not vulns:
                continue
            for v in vulns:
                extra.append({
                    "source_tool": "sca",
                    "severity": (v.get("severity") or "medium"),
                    "title": (f"{name} {ver}: "
                              f"{v.get('summary') or v.get('cve_id') or 'cached vulnerability'}")[:500],
                    "description": (v.get("description") or v.get("summary") or "")[:2000],
                    "owasp_category": "A06:2021-Vulnerable_and_Outdated_Components",
                    "cwe": "1104",
                    "cvss": v.get("cvss"),
                    "evidence_url": pkg.get("source_url"),
                    "evidence_method": "GET",
                    "remediation": (
                        f"Upgrade {name} past {v.get('vulnerable_range') or '(any)'}."
                        + (f" Fixed in {v.get('fixed_version')}."
                           if v.get("fixed_version") else "")),
                    "raw_data": {
                        "detector": f"sca-cache:{v.get('source')}",
                        "ecosystem": eco,
                        "package": {"name": name, "version": ver},
                        "cached_vuln": {
                            k: v.get(k) for k in (
                                "cve_id", "ghsa_id", "summary",
                                "vulnerable_range", "fixed_version",
                                "source", "references_json")
                        },
                    },
                    "_sca_pkg": {
                        "ecosystem": eco, "name": name, "version": ver,
                        "source_url": pkg.get("source_url"),
                        "detection_method": pkg.get("detection_method"),
                        "matched_cves": [v.get("cve_id")] if v.get("cve_id") else [],
                    },
                })
    finally:
        log_fh.close()
    return extra


# ---- orchestrator entry point ----------------------------------------------

def run(target: str, scan_dir: Path, *,
        assessment_id: Optional[int] = None,
        use_llm: bool = True) -> dict:
    """Run all four SCA passes against `target` and write the artifacts
    the orchestrator expects under <scan_dir>/sca/.

    Returns a summary dict suitable for meta.json."""
    sca_dir = scan_dir / "sca"
    sca_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "target": target,
        "manifests_found": 0,
        "js_urls_scanned": 0,
        "retire_findings": 0,
        "osv_findings": 0,
        "llm_augment_findings": 0,
        "packages_observed": 0,
    }

    # Pass 1 — manifest hunt
    manifest_hits = hunt_manifests(target, sca_dir / "manifests")
    summary["manifests_found"] = len(manifest_hits)

    # Pass 2 — JS library scan via retire.js
    js_urls = discover_js_urls(target)
    summary["js_urls_scanned"] = len(js_urls)
    retire_results = run_retire(js_urls, scan_dir) if js_urls else []
    summary["retire_findings"] = sum(1 for r in retire_results
                                     if r.get("vulnerabilities"))

    # Pass 3 — OSV-Scanner over each retrieved manifest / lockfile
    osv_results = run_osv_scanner(manifest_hits, scan_dir)
    summary["osv_findings"] = len(osv_results)

    # Build the normalized finding list + the package observation list.
    findings: list[dict] = []
    packages: list[dict] = []
    seen_pkg: set[tuple] = set()

    for hit in manifest_hits:
        if hit.get("kind") == "leak":
            findings.append(_leak_finding(hit))
        else:
            findings.append(_leaked_manifest_finding(hit))

    for rf in retire_results:
        for f in _normalize_retire_finding(rf, target):
            findings.append(f)
            pkg = f.pop("_sca_pkg", None)
            if pkg:
                key = (pkg["ecosystem"], pkg["name"], pkg["version"])
                if key not in seen_pkg:
                    seen_pkg.add(key)
                    packages.append(pkg)

    for rec in osv_results:
        f = _normalize_osv_finding(rec)
        findings.append(f)
        pkg = f.pop("_sca_pkg", None)
        if pkg:
            key = (pkg["ecosystem"], pkg["name"], pkg["version"])
            if key not in seen_pkg:
                seen_pkg.add(key)
                packages.append(pkg)

    # Pass 4 — LLM augmentation for packages with no DB / scanner hit yet.
    if use_llm and packages:
        for f in augment_with_llm(packages, assessment_id, scan_dir):
            findings.append(f)
            f.pop("_sca_pkg", None)
            summary["llm_augment_findings"] += 1

    summary["packages_observed"] = len(packages)

    (sca_dir / "findings.json").write_text(
        json.dumps(findings, indent=2, default=str))
    (sca_dir / "packages.json").write_text(
        json.dumps(packages, indent=2, default=str))
    (sca_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str))

    # Persist observed packages into the global SCA cache + the per-
    # assessment audit table so the report renderer can show them later.
    if sca_mod is not None and assessment_id is not None:
        for pkg in packages:
            try:
                sca_mod.record_package(pkg["ecosystem"], pkg["name"],
                                       pkg["version"])
                sca_mod.record_assessment_package(
                    assessment_id, pkg["ecosystem"], pkg["name"], pkg["version"],
                    source_url=pkg.get("source_url"),
                    detection_method=pkg.get("detection_method") or "unknown",
                    matched_cves=pkg.get("matched_cves") or [],
                )
            except Exception:
                pass

    return summary


# ---- CLI --------------------------------------------------------------------

def _cli() -> int:
    ap = argparse.ArgumentParser(description="SCA stage runner")
    ap.add_argument("--target", required=True,
                    help="Scheme + host of the target (e.g. https://app.example.com)")
    ap.add_argument("--scan-dir", default="./sca-scan",
                    help="Where to write findings.json / packages.json / summary.json")
    ap.add_argument("--assessment-id", type=int,
                    help="Assessment id (enables DB writes + LLM augmentation)")
    ap.add_argument("--no-llm", action="store_true",
                    help="Disable the LLM augmentation pass")
    args = ap.parse_args()

    summary = run(args.target, Path(args.scan_dir),
                  assessment_id=args.assessment_id,
                  use_llm=not args.no_llm)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
