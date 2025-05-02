# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Server-side enumeration + invocation of toolkit probes.

The probes themselves live in /app/toolkit (volume-mounted :ro). This
module just lists them, reads their manifests, and shells out to run one.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

TOOLKIT_DIR = Path("/app/toolkit")
PROBES_DIR = TOOLKIT_DIR / "probes"

# Probe name format guard (used in any path-sensitive lookup).
PROBE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,32}$")


def list_probes() -> list[dict]:
    if not PROBES_DIR.is_dir():
        return []
    out = []
    for manifest_path in sorted(PROBES_DIR.glob("*.manifest.json")):
        try:
            data = json.loads(manifest_path.read_text())
        except Exception:
            continue
        name = data.get("name") or manifest_path.stem.replace(".manifest", "")
        script = PROBES_DIR / f"{name}.py"
        if not script.is_file():
            continue
        data["script_path"] = str(script)
        data["available"] = True
        out.append(data)
    return out


def get_probe(name: str) -> Optional[dict]:
    if not PROBE_NAME_RE.match(name or ""):
        return None
    for p in list_probes():
        if p["name"] == name:
            return p
    return None


def find_probe_for_finding(finding: dict) -> Optional[dict]:
    """Return the most relevant probe for this finding, or None.

    Match precedence (highest first):
      1. The finding's title appears in the probe's `matches_titles` list
         (case-insensitive substring match — covers 'Htaccess Bypass' vs
         'htaccess bypass' vs 'weak restriction bypassable').
      2. The finding's source_tool is in `matches_tools` AND the finding's
         OWASP / CWE classification is in `validates`.
      3. The OWASP / CWE classification alone is in `validates`.

    The first match wins. This lets the Challenge button surface a probe
    even when the manifest's title list doesn't enumerate every wording
    variant a scanner might emit."""
    title = (finding.get("title") or "").lower()
    tool = (finding.get("source_tool") or "").lower()
    owasp = finding.get("owasp_category") or ""
    cwe = ("CWE-" + finding["cwe"]) if finding.get("cwe") else ""

    probes = list_probes()

    # Tier 1 — explicit title match
    for p in probes:
        for t in (p.get("matches_titles") or []):
            if t and t.lower() in title:
                return p

    # Tier 2 — tool + OWASP/CWE intersect
    for p in probes:
        tools = [s.lower() for s in (p.get("matches_tools") or [])]
        validates = p.get("validates") or []
        if tool in tools and (owasp in validates or cwe in validates):
            return p

    # Tier 3 — OWASP/CWE alone
    for p in probes:
        validates = p.get("validates") or []
        if (owasp and owasp in validates) or (cwe and cwe in validates):
            return p

    return None


def run_probe(name: str, config: dict, *,
              timeout: float = 60.0) -> dict:
    """Run a probe synchronously, feeding `config` as JSON on stdin and
    parsing its JSON verdict from stdout. Always returns a dict — wraps
    any subprocess error so the caller doesn't need to."""
    p = get_probe(name)
    if not p:
        return {"ok": False, "error": f"unknown probe {name!r}"}
    script = p["script_path"]
    try:
        proc = subprocess.run(
            [sys.executable, script, "--stdin"],
            input=json.dumps(config).encode(),
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "probe timed out"}
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    try:
        result = json.loads(out)
    except Exception:
        return {"ok": False, "error": "probe output was not JSON",
                "stdout": out[:2000], "stderr": err[:2000],
                "exit_code": proc.returncode}
    result["_exit_code"] = proc.returncode
    if err:
        result["_stderr"] = err[:2000]
    return result
