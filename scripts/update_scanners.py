#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Update scanner binaries, scanner template / signature databases, and the
SCA vulnerability cache.

Two ways to invoke:

  CLI (manual / system cron):
    python -m scripts.update_scanners --all
    python -m scripts.update_scanners --scanners
    python -m scripts.update_scanners --sca
    python -m scripts.update_scanners --tool nuclei-templates
    python -m scripts.update_scanners --status

  Programmatic (FastAPI sweeper / admin button):
    from scripts import update_scanners
    update_scanners.run(scope="all", log_path=Path("/data/logs/sca_update.log"))

Design rules:

  - All overlays land in /data/scanners/<tool>/ and /data/sca/. The
    image's baseline binaries / templates are NEVER modified, so a
    fresh registry pull always works offline. The orchestrator and
    sca_runner prefer the overlay only when present and newer.

  - One log file per run is appended to /data/logs/sca_update.log so
    the admin "Update now" page can tail the current pass via SSE.

  - Each step is independent; one feed failing must not stop the rest.
    Errors are recorded in the log and surfaced on the admin page but
    never raised back to the orchestrator.

  - Network-required steps degrade gracefully when offline: the call
    logs "skipped (no network)" and the local cache continues to be
    served from the last successful refresh.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, "/app")
try:
    import db  # noqa: E402  — only available when running inside the container
except Exception:
    db = None  # type: ignore[assignment]


# ---- paths ------------------------------------------------------------------

SCANNER_OVERLAY = Path("/data/scanners")
SCA_DIR = Path("/data/sca")
RETIRE_SIG = SCA_DIR / "retire" / "jsrepository.json"
OSV_DB_DIR = SCA_DIR / "osv-db"
DEFAULT_LOG = Path("/data/logs/sca_update.log")

# Tools managed by this updater. Each entry describes how to refresh that
# tool's *artifact* (binary, template tree, signature DB). The keys here
# are the names the admin UI and the --tool flag accept.
TOOLS: dict[str, dict] = {
    # ---- scanner binaries (GitHub releases) -------------------------------
    "nuclei": {
        "kind": "github_binary",
        "repo": "projectdiscovery/nuclei",
        # asset hint substrings; the linux/amd64 zip is always tagged this way
        "asset_hints": ("linux", ".zip"),
        "extract": "zip",
        "binary": "nuclei",
        "overlay": SCANNER_OVERLAY / "nuclei",
    },
    "dalfox": {
        "kind": "github_binary",
        "repo": "hahwul/dalfox",
        "asset_hints": ("linux", ".tar.gz"),
        "extract": "tar.gz",
        "binary": "dalfox",
        "overlay": SCANNER_OVERLAY / "dalfox",
    },
    "ffuf": {
        "kind": "github_binary",
        "repo": "ffuf/ffuf",
        "asset_hints": ("linux", ".tar.gz"),
        "extract": "tar.gz",
        "binary": "ffuf",
        "overlay": SCANNER_OVERLAY / "ffuf",
    },
    "osv-scanner": {
        "kind": "github_binary",
        "repo": "google/osv-scanner",
        # OSV ships a bare ELF (no archive) — keep the hint loose so the
        # arch-specific asset matches whichever naming they use.
        "asset_hints": ("linux",),
        "extract": "raw",
        "binary": "osv-scanner",
        "overlay": SCANNER_OVERLAY / "osv-scanner",
    },
    # ---- git-managed scanner trees ----------------------------------------
    "nuclei-templates": {
        "kind": "git_repo",
        "url": "https://github.com/projectdiscovery/nuclei-templates.git",
        "path": Path("/root/nuclei-templates"),
    },
    "nikto": {
        "kind": "git_repo",
        "url": "https://github.com/sullo/nikto.git",
        "path": Path("/opt/nikto"),
    },
    "testssl": {
        "kind": "git_repo",
        "url": "https://github.com/drwetter/testssl.sh.git",
        "path": Path("/opt/testssl"),
    },
    # ---- pip-installed scanners (overlay venv) ----------------------------
    "wapiti": {
        "kind": "pip_overlay",
        "package": "wapiti3",
        "binary": "wapiti",
    },
    # ---- sqlmap dev branch (preferred over apt baseline when present) -----
    "sqlmap-dev": {
        "kind": "git_repo",
        "url": "https://github.com/sqlmapproject/sqlmap.git",
        "path": SCANNER_OVERLAY / "sqlmap-dev",
    },
    # ---- SCA databases ----------------------------------------------------
    "retire-signatures": {
        "kind": "url_file",
        "url": "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json",
        "dest": RETIRE_SIG,
    },
    "osv-db-npm":      {"kind": "osv_zip", "ecosystem": "npm"},
    "osv-db-pypi":     {"kind": "osv_zip", "ecosystem": "PyPI"},
    "osv-db-rubygems": {"kind": "osv_zip", "ecosystem": "RubyGems"},
    "osv-db-maven":    {"kind": "osv_zip", "ecosystem": "Maven"},
    "osv-db-go":       {"kind": "osv_zip", "ecosystem": "Go"},
    "osv-db-packagist":{"kind": "osv_zip", "ecosystem": "Packagist"},
    "osv-db-nuget":    {"kind": "osv_zip", "ecosystem": "NuGet"},
    "osv-db-cargo":    {"kind": "osv_zip", "ecosystem": "crates.io"},
}

# Logical groups exposed via --scanners / --sca for ergonomics.
SCANNER_KEYS = ["nuclei", "dalfox", "ffuf", "osv-scanner",
                "nuclei-templates", "nikto", "testssl",
                "wapiti", "sqlmap-dev"]
SCA_KEYS = ["retire-signatures",
            "osv-db-npm", "osv-db-pypi", "osv-db-rubygems",
            "osv-db-maven", "osv-db-go", "osv-db-packagist",
            "osv-db-nuget", "osv-db-cargo"]


# ---- log helpers ------------------------------------------------------------

class _Logger:
    """Tee writes to stdout AND to the rolling log file. SSE consumers
    poll the file; CLI users see the same output live."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self.log_path = log_path or DEFAULT_LOG
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.log_path, "a", buffering=1, encoding="utf-8")

    def line(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out = f"[{ts}] {msg}"
        print(out, flush=True)
        try:
            self._fh.write(out + "\n")
        except Exception:
            pass

    def header(self, msg: str) -> None:
        self.line("=" * 60)
        self.line(msg)
        self.line("=" * 60)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ---- shared helpers ---------------------------------------------------------

def _arch() -> str:
    """Map dpkg arch string to the GitHub-release naming convention."""
    try:
        out = subprocess.check_output(["dpkg", "--print-architecture"]).decode().strip()
    except Exception:
        out = "amd64"
    return "amd64" if out == "x86_64" else out


def _http_get_json(url: str, timeout: int = 30) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "nextgen-dast-updater/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


def _pick_release_asset(repo: str, hint_substrings: tuple[str, ...]) -> Optional[tuple[str, str]]:
    """Return (tag, asset_url) for the latest release asset whose name
    contains every substring in `hint_substrings`. Lets us track
    upstream asset-naming churn (e.g. dalfox 2.11 used
    dalfox_2.11.0_linux_amd64.tar.gz, 2.12+ uses dalfox-linux-amd64.tar.gz)
    without having to ship a per-version format template."""
    data = _http_get_json(f"https://api.github.com/repos/{repo}/releases/latest")
    if not data:
        return None
    tag = data.get("tag_name") or ""
    for asset in data.get("assets", []) or []:
        name = (asset.get("name") or "").lower()
        if all(h.lower() in name for h in hint_substrings):
            return tag[1:] if tag.startswith("v") else tag, asset.get("browser_download_url")
    return None


def _http_download(url: str, dest: Path, timeout: int = 120) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "nextgen-dast-updater/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
            shutil.copyfileobj(resp, fh)
        tmp.replace(dest)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        return False


def _latest_github_release(repo: str) -> Optional[str]:
    """Return the tag of the latest release, with leading 'v' stripped."""
    data = _http_get_json(f"https://api.github.com/repos/{repo}/releases/latest")
    if not data:
        return None
    tag = data.get("tag_name") or ""
    return tag[1:] if tag.startswith("v") else tag


def _current_overlay_version(overlay_dir: Path) -> Optional[str]:
    """Read /data/scanners/<tool>/VERSION if it exists."""
    f = overlay_dir / "VERSION"
    if f.is_file():
        try:
            return f.read_text().strip()
        except OSError:
            return None
    return None


# ---- per-kind handlers ------------------------------------------------------

def _update_github_binary(name: str, spec: dict, log: _Logger) -> dict:
    repo = spec["repo"]
    overlay: Path = spec["overlay"]
    overlay.mkdir(parents=True, exist_ok=True)

    arch = _arch()
    # Bake the arch into the hint substrings so we always pick the asset
    # that matches our host CPU.
    hints = tuple(list(spec["asset_hints"]) + [arch])
    picked = _pick_release_asset(repo, hints)
    if not picked:
        log.line(f"  {name}: skipped (could not find linux/{arch} asset on latest release)")
        return {"name": name, "ok": False, "skipped": True,
                "reason": "no matching asset (offline or upstream renamed)"}
    latest, asset_url = picked

    current = _current_overlay_version(overlay)
    if current == latest:
        log.line(f"  {name}: already at {latest} (no change)")
        return {"name": name, "ok": True, "version": latest, "changed": False}

    asset_name = asset_url.rsplit("/", 1)[-1]
    download_to = overlay / "_download" / asset_name
    log.line(f"  {name}: downloading {asset_name} (overlay was {current or 'baseline'})")
    if not _http_download(asset_url, download_to):
        log.line(f"  {name}: download failed for {asset_url}")
        return {"name": name, "ok": False, "reason": "download failed"}

    bin_dest = overlay / spec["binary"]
    extract = spec["extract"]
    try:
        if extract == "zip":
            import zipfile
            with zipfile.ZipFile(download_to) as zf:
                # Pull just the named binary out of the archive (releases
                # bundle README / LICENSE alongside the binary; we only
                # need the executable).
                with zf.open(spec["binary"]) as src, open(bin_dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        elif extract == "tar.gz":
            import tarfile
            with tarfile.open(download_to, "r:gz") as tf:
                # Try the canonical name first; fall back to the largest
                # regular file in the archive (handles upstream renames
                # like dalfox 2.12 shipping the binary as
                # `dalfox-linux-amd64` instead of `dalfox`).
                regulars = [m for m in tf.getmembers() if m.isfile()]
                member = next((m for m in regulars
                               if m.name == spec["binary"] or
                               m.name.endswith("/" + spec["binary"])), None)
                if not member and regulars:
                    member = max(regulars, key=lambda m: m.size)
                if not member:
                    raise RuntimeError(f"no extractable file in archive")
                f = tf.extractfile(member)
                if not f:
                    raise RuntimeError("could not read binary from archive")
                with open(bin_dest, "wb") as dst:
                    shutil.copyfileobj(f, dst)
        elif extract == "raw":
            shutil.copyfile(download_to, bin_dest)
        else:
            raise RuntimeError(f"unknown extract type: {extract}")
        bin_dest.chmod(0o755)
    except Exception as e:
        log.line(f"  {name}: extract failed: {e!r}")
        return {"name": name, "ok": False, "reason": f"extract failed: {e}"}
    finally:
        # Even on failure, drop the download to keep /data lean.
        try:
            download_to.unlink()
        except OSError:
            pass

    (overlay / "VERSION").write_text(latest + "\n")
    log.line(f"  {name}: installed {latest} -> {bin_dest}")
    return {"name": name, "ok": True, "version": latest, "changed": True,
            "binary": str(bin_dest)}


def _update_git_repo(name: str, spec: dict, log: _Logger) -> dict:
    path: Path = spec["path"]
    if not (path / ".git").is_dir():
        # First-time clone (sqlmap-dev only takes this branch normally;
        # the others ship pre-cloned in the image).
        path.parent.mkdir(parents=True, exist_ok=True)
        log.line(f"  {name}: cloning {spec['url']}")
        proc = subprocess.run(
            ["git", "clone", "--depth=1", spec["url"], str(path)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            log.line(f"  {name}: clone failed — {proc.stderr.strip()[:300]}")
            return {"name": name, "ok": False, "reason": "clone failed"}
        log.line(f"  {name}: cloned to {path}")
        return {"name": name, "ok": True, "changed": True}

    # Determine the remote default branch (may be `main` or `master`).
    head_ref = "origin/HEAD"
    show = subprocess.run(
        ["git", "-C", str(path), "remote", "show", "origin"],
        capture_output=True, text=True, timeout=15,
    )
    branch = "main"
    for line in (show.stdout or "").splitlines():
        line = line.strip()
        if line.lower().startswith("head branch:"):
            branch = line.split(":", 1)[1].strip()
            break

    log.line(f"  {name}: git fetch + reset --hard origin/{branch} on {path}")
    fetch = subprocess.run(
        ["git", "-C", str(path), "fetch", "--depth=1", "--force",
         "origin", branch],
        capture_output=True, text=True,
    )
    if fetch.returncode != 0:
        log.line(f"  {name}: fetch failed — {fetch.stderr.strip()[:300]}")
        return {"name": name, "ok": False, "reason": "fetch failed"}
    # Read the prior HEAD so we can report whether anything actually changed.
    prior = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    reset = subprocess.run(
        ["git", "-C", str(path), "reset", "--hard", f"origin/{branch}"],
        capture_output=True, text=True,
    )
    if reset.returncode != 0:
        # Reset is normally infallible after a clean fetch — surface the
        # raw error if it still fails so the operator can intervene.
        log.line(f"  {name}: reset failed — {reset.stderr.strip()[:300]}")
        return {"name": name, "ok": False, "reason": "reset failed"}
    after = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    changed = (prior != after)
    summary = (reset.stdout or "").strip().splitlines()
    log.line(f"  {name}: {summary[0] if summary else after[:12]}")
    return {"name": name, "ok": True, "changed": changed,
            "head": after[:12]}


def _update_pip_overlay(name: str, spec: dict, log: _Logger) -> dict:
    """Install / upgrade a pip-managed scanner into a venv overlay so the
    image's pinned baseline is preserved. Falls back to a no-op if the
    venv module isn't usable in this Python install."""
    venv_dir = SCANNER_OVERLAY / "pyvenv"
    if not (venv_dir / "bin" / "python").is_file():
        log.line(f"  {name}: creating overlay venv at {venv_dir}")
        try:
            subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
        except subprocess.CalledProcessError as e:
            log.line(f"  {name}: venv creation failed: {e}")
            return {"name": name, "ok": False, "reason": "venv create failed"}
    pip = venv_dir / "bin" / "pip"
    log.line(f"  {name}: pip install -U {spec['package']}")
    proc = subprocess.run(
        [str(pip), "install", "-U", "--no-cache-dir", spec["package"]],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        log.line(f"  {name}: pip failed — {proc.stderr.strip()[:300]}")
        return {"name": name, "ok": False, "reason": "pip install failed"}
    # Resolve the actual installed version so the admin page can show it.
    show = subprocess.run(
        [str(pip), "show", spec["package"]], capture_output=True, text=True,
    )
    ver = ""
    for line in (show.stdout or "").splitlines():
        if line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
            break
    log.line(f"  {name}: {spec['package']}=={ver or '?'}")
    return {"name": name, "ok": True, "version": ver, "changed": True,
            "binary": str(venv_dir / "bin" / spec["binary"])}


def _update_url_file(name: str, spec: dict, log: _Logger) -> dict:
    dest: Path = spec["dest"]
    log.line(f"  {name}: downloading {spec['url']}")
    if _http_download(spec["url"], dest):
        log.line(f"  {name}: saved to {dest}")
        return {"name": name, "ok": True, "changed": True, "path": str(dest)}
    log.line(f"  {name}: download failed (kept previous copy)")
    return {"name": name, "ok": False, "reason": "download failed"}


def _update_osv_zip(name: str, spec: dict, log: _Logger) -> dict:
    """Refresh one ecosystem zip from osv-vulnerabilities.storage.googleapis.com.
    OSV publishes zip dumps at predictable per-ecosystem URLs; we cache them
    under /data/sca/osv-db/<ecosystem>/."""
    eco = spec["ecosystem"]
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
    target = OSV_DB_DIR / eco / "all.zip"
    log.line(f"  {name}: downloading OSV dump for {eco}")
    if not _http_download(url, target, timeout=300):
        log.line(f"  {name}: download failed (will keep prior cache if any)")
        return {"name": name, "ok": False, "reason": "download failed"}
    # OSV dumps are JSON-per-vuln; extract so app/sca.py can mmap them
    # without spawning unzip on every lookup.
    import zipfile
    extract_dir = OSV_DB_DIR / eco / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    # Wipe stale entries so deleted/withdrawn vulns disappear from cache.
    for old in extract_dir.glob("*.json"):
        try:
            old.unlink()
        except OSError:
            pass
    try:
        with zipfile.ZipFile(target) as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        log.line(f"  {name}: zip corrupt, kept download for retry")
        return {"name": name, "ok": False, "reason": "bad zip"}
    n = sum(1 for _ in extract_dir.glob("*.json"))
    log.line(f"  {name}: extracted {n} vuln records for {eco}")
    return {"name": name, "ok": True, "ecosystem": eco, "count": n,
            "changed": True}


# ---- dispatcher -------------------------------------------------------------

KIND_HANDLERS = {
    "github_binary": _update_github_binary,
    "git_repo":      _update_git_repo,
    "pip_overlay":   _update_pip_overlay,
    "url_file":      _update_url_file,
    "osv_zip":       _update_osv_zip,
}


def _run_one(name: str, log: _Logger) -> dict:
    spec = TOOLS.get(name)
    if not spec:
        log.line(f"  {name}: unknown tool")
        return {"name": name, "ok": False, "reason": "unknown tool"}
    handler = KIND_HANDLERS.get(spec["kind"])
    if not handler:
        log.line(f"  {name}: unknown kind {spec['kind']!r}")
        return {"name": name, "ok": False, "reason": "unknown kind"}
    try:
        return handler(name, spec, log)
    except Exception as e:
        # Per-tool failure must NOT propagate — other tools still need
        # to run, and the sweeper must finish so the next 24h tick fires.
        log.line(f"  {name}: handler crashed: {type(e).__name__}: {e}")
        return {"name": name, "ok": False, "reason": f"crash: {e}"}


def _record_run(scope: str, results: list[dict]) -> None:
    """Persist a one-line config marker so the admin page can render
    'last refreshed ...' without parsing the whole log file."""
    if db is None:
        return
    summary = {
        "scope": scope,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": sum(1 for r in results if r.get("ok")),
        "fail": sum(1 for r in results if not r.get("ok")),
        "tools": [
            {"name": r.get("name"), "ok": r.get("ok"),
             "version": r.get("version"),
             "changed": r.get("changed", False)}
            for r in results
        ],
    }
    try:
        db.execute(
            "INSERT INTO config (`key`, value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE value=VALUES(value)",
            ("sca_last_updated_at", summary["at"]),
        )
        db.execute(
            "INSERT INTO config (`key`, value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE value=VALUES(value)",
            ("sca_last_update_log", json.dumps(summary)),
        )
    except Exception:
        # DB outage during a refresh shouldn't crash the refresh.
        pass


# ---- public entry points ----------------------------------------------------

def run(scope: str = "all", *,
        only: Optional[Iterable[str]] = None,
        log_path: Optional[Path] = None) -> dict:
    """Run an update pass.

    scope: "all" | "scanners" | "sca". Ignored if `only` is provided.
    only:  explicit list of TOOLS keys to run.
    log_path: where to append the log; defaults to /data/logs/sca_update.log.
    """
    log = _Logger(log_path)
    log.header(f"nextgen-dast scanner / SCA update — scope={scope}")
    keys: list[str] = []
    if only:
        keys = [k for k in only if k in TOOLS]
    elif scope == "scanners":
        keys = SCANNER_KEYS[:]
    elif scope == "sca":
        keys = SCA_KEYS[:]
    else:
        keys = SCANNER_KEYS + SCA_KEYS

    started = time.time()
    results: list[dict] = []
    for name in keys:
        log.line(f"-> {name}")
        results.append(_run_one(name, log))
    elapsed = time.time() - started
    ok = sum(1 for r in results if r.get("ok"))
    log.line(f"DONE in {elapsed:.1f}s — {ok}/{len(results)} tools succeeded")
    log.close()
    _record_run(scope, results)
    return {"scope": scope, "elapsed_s": round(elapsed, 1),
            "results": results}


def status() -> dict:
    """Return overlay versions / last-refresh timestamps for the admin page.
    Safe to call from request handlers; touches the filesystem only."""
    rows: list[dict] = []
    for name, spec in TOOLS.items():
        entry: dict = {"name": name, "kind": spec["kind"]}
        if spec["kind"] == "github_binary":
            entry["overlay_version"] = _current_overlay_version(spec["overlay"])
            entry["overlay_present"] = (spec["overlay"] / spec["binary"]).is_file()
        elif spec["kind"] == "git_repo":
            p = spec["path"]
            entry["path"] = str(p)
            entry["present"] = (p / ".git").is_dir()
            try:
                proc = subprocess.run(
                    ["git", "-C", str(p), "log", "-1", "--format=%cI %h"],
                    capture_output=True, text=True, timeout=5,
                )
                if proc.returncode == 0:
                    entry["last_commit"] = proc.stdout.strip()
            except Exception:
                pass
        elif spec["kind"] == "pip_overlay":
            venv_pip = SCANNER_OVERLAY / "pyvenv" / "bin" / "pip"
            if venv_pip.is_file():
                try:
                    show = subprocess.run(
                        [str(venv_pip), "show", spec["package"]],
                        capture_output=True, text=True, timeout=5,
                    )
                    for line in show.stdout.splitlines():
                        if line.startswith("Version:"):
                            entry["overlay_version"] = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass
        elif spec["kind"] == "url_file":
            d: Path = spec["dest"]
            entry["present"] = d.is_file()
            if d.is_file():
                stat = d.stat()
                entry["bytes"] = stat.st_size
                entry["mtime"] = datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif spec["kind"] == "osv_zip":
            extract = OSV_DB_DIR / spec["ecosystem"] / "extracted"
            entry["ecosystem"] = spec["ecosystem"]
            entry["records"] = (sum(1 for _ in extract.glob("*.json"))
                                if extract.is_dir() else 0)
        rows.append(entry)
    last_at = ""
    last_log = ""
    if db is not None:
        try:
            r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                             ("sca_last_updated_at",))
            if r:
                last_at = r.get("value") or ""
            r = db.query_one("SELECT value FROM config WHERE `key`=%s",
                             ("sca_last_update_log",))
            if r:
                last_log = r.get("value") or ""
        except Exception:
            pass
    return {"tools": rows,
            "last_updated_at": last_at,
            "last_update_summary": last_log}


# ---- CLI --------------------------------------------------------------------

def _cli() -> int:
    ap = argparse.ArgumentParser(description="Update scanner binaries / templates / SCA DBs")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true",
                   help="Refresh everything (scanners + SCA)")
    g.add_argument("--scanners", action="store_true",
                   help="Refresh scanner binaries / templates only")
    g.add_argument("--sca", action="store_true",
                   help="Refresh SCA databases only")
    g.add_argument("--tool", action="append",
                   help="Refresh a single tool by key (repeatable)")
    g.add_argument("--status", action="store_true",
                   help="Print current overlay versions + last refresh")
    ap.add_argument("--log", default=str(DEFAULT_LOG),
                    help="Append progress to this log file")
    args = ap.parse_args()

    if args.status:
        s = status()
        print(json.dumps(s, indent=2, default=str))
        return 0

    log_path = Path(args.log)
    if args.tool:
        result = run(scope="custom", only=args.tool, log_path=log_path)
    elif args.scanners:
        result = run(scope="scanners", log_path=log_path)
    elif args.sca:
        result = run(scope="sca", log_path=log_path)
    else:
        result = run(scope="all", log_path=log_path)
    fail = sum(1 for r in result["results"] if not r.get("ok"))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(_cli())
