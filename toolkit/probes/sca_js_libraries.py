#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""SCA validation probe for client-side JavaScript libraries.

Given a target URL, fetches the page's HTML, extracts every
<script src=...> URL, downloads each script (subject to the SafeClient
budget), and runs retire.js against the lot. Returns a Verdict listing
every detected library with its version and any matched
vulnerabilities.

Used both by the orchestrator's auto-validate pass (re-confirm an SCA
finding the SCA stage produced) and by a pentester running it stand-
alone against any target.

Examples (CLI):
    python sca_js_libraries.py --url 'https://app.example.com/'
    python sca_js_libraries.py --url 'https://app.example.com/' \\
        --component jquery --max-urls 8
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict          # noqa: E402
from lib.http import SafeClient               # noqa: E402


_SCRIPT_SRC_RE = re.compile(
    r"""<\s*(?:script|link)[^>]*?(?:src|href)\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _retire_signature_path() -> str | None:
    overlay = Path("/data/sca/retire/jsrepository.json")
    baseline = Path("/opt/sca/retire/jsrepository.json")
    if overlay.is_file() and overlay.stat().st_size > 1000:
        return str(overlay)
    if baseline.is_file():
        return str(baseline)
    return None


class SCAJSLibrariesProbe(Probe):
    name = "sca_js_libraries"
    summary = ("Identify outdated/vulnerable JS libraries by extracting "
               "<script src> URLs and running retire.js against each.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument("--max-urls", type=int, default=20,
                            help="Cap how many JS URLs to scan (default 20)")
        parser.add_argument("--component",
                            help="If set, validation passes only when retire.js "
                                 "reports a vulnerability for this exact component "
                                 "name (case-insensitive). Used by auto-validate.")
        parser.add_argument("--min-severity", default="medium",
                            help="Minimum vuln severity to count as 'validated' "
                                 "(critical|high|medium|low|info, default medium)")

    def run(self, args, client: SafeClient) -> Verdict:
        # Pull the root HTML through the SafeClient so it counts against
        # budget / scope checks like every other probe HTTP call.
        try:
            r = client.get(args.url)
        except Exception as e:
            return Verdict(ok=False, validated=None,
                           summary=f"failed to fetch {args.url}: {e}",
                           error=str(e))
        # SafeClient.Response exposes .status / .body. The getattr
        # fallbacks tolerate a future client built on requests / httpx
        # where the conventional names are status_code / content.
        status = getattr(r, "status", None)
        if status is None:
            status = getattr(r, "status_code", 0)
        body_bytes = getattr(r, "body", None)
        if body_bytes is None:
            body_bytes = getattr(r, "content", b"") or b""
        if status >= 400 or not body_bytes:
            return Verdict(ok=False, validated=None,
                           summary=f"target returned HTTP {status}")

        # Discover JS URLs and dedupe.
        body = body_bytes.decode("utf-8", "replace")
        urls: list[str] = []
        seen: set[str] = set()
        for m in _SCRIPT_SRC_RE.finditer(body):
            ref = m.group(1).strip()
            if not ref or ref.startswith(("data:", "javascript:", "mailto:")):
                continue
            absolute = urllib.parse.urljoin(args.url, ref)
            if not (absolute.split("?", 1)[0].endswith(".js") or
                    "/js/" in absolute or "/static/" in absolute):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            urls.append(absolute)
            if len(urls) >= int(args.max_urls):
                break
        if not urls:
            return Verdict(ok=True, validated=False, confidence=0.5,
                           summary="no <script src> URLs found on the page")

        # Stage the JS files into a probe-private temp dir under /tmp so
        # the SafeClient stays in charge of all HTTP calls.
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="sca-probe-"))
        local_paths: list[tuple[str, Path]] = []
        for u in urls:
            try:
                jr = client.get(u)
            except Exception:
                continue
            jr_status = getattr(jr, "status", None)
            if jr_status is None:
                jr_status = getattr(jr, "status_code", 0)
            if jr_status >= 400:
                continue
            data = getattr(jr, "body", None)
            if data is None:
                data = getattr(jr, "content", b"") or b""
            if not data:
                continue
            local = tmp / urllib.parse.quote(u, safe="")
            try:
                local.write_bytes(data[:2_000_000])
            except OSError:
                continue
            local_paths.append((u, local))
        if not local_paths:
            return Verdict(ok=True, validated=False, confidence=0.4,
                           summary="found script URLs but none returned content")

        # Run retire.js against the staged directory.
        sig_arg: list[str] = []
        sig_path = _retire_signature_path()
        if sig_path:
            sig_arg = ["--jsrepo", sig_path]
        # retire 5.x dropped --js (binary defaults to JS scanning); the
        # only required flag is --path.
        cmd = ["retire", "--outputformat", "json",
               "--exitwith", "0",
               "--path", str(tmp)] + sig_arg
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=120)
        except FileNotFoundError:
            return Verdict(ok=False, validated=None,
                           summary="retire.js not installed (image build issue)",
                           error="retire binary missing")
        except subprocess.TimeoutExpired:
            return Verdict(ok=False, validated=None,
                           summary="retire.js timed out (>120s)")
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            return Verdict(ok=False, validated=None,
                           summary="retire.js returned non-JSON output",
                           error=(proc.stderr or "")[:300])

        # Map each retire result back to its source URL via the file path.
        path_to_url = {str(p): u for u, p in local_paths}
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_sev = sev_order.get((args.min_severity or "medium").lower(), 2)
        component_filter = (args.component or "").strip().lower() or None
        detected: list[dict] = []
        validated_any = False
        worst = ""
        for entry in data.get("data", []) or []:
            file_path = entry.get("file") or ""
            url = path_to_url.get(file_path) or file_path
            for comp in entry.get("results", []) or []:
                comp_name = (comp.get("component") or "").strip()
                version = (comp.get("version") or "").strip()
                vulns = comp.get("vulnerabilities") or []
                if component_filter and comp_name.lower() != component_filter:
                    continue
                detected.append({
                    "url": url,
                    "component": comp_name,
                    "version": version,
                    "vulnerabilities": vulns,
                })
                for v in vulns:
                    sev = (v.get("severity") or "medium").lower()
                    if sev_order.get(sev, 0) >= min_sev:
                        validated_any = True
                        if sev_order.get(sev, 0) > sev_order.get(worst, -1):
                            worst = sev
        if not detected:
            return Verdict(ok=True, validated=False, confidence=0.5,
                           summary=("no library matched"
                                    + (f" '{component_filter}'"
                                       if component_filter else "")))
        if not validated_any:
            return Verdict(ok=True, validated=False, confidence=0.7,
                           summary=("libraries identified but none with "
                                    f"severity ≥ {args.min_severity}"),
                           evidence={"detected": detected})
        return Verdict(
            ok=True, validated=True, confidence=0.9,
            summary=(f"{len(detected)} JS lib(s) with vulnerabilities; "
                     f"worst severity {worst}"),
            evidence={"detected": detected,
                      "scanned_urls": len(local_paths),
                      "min_severity": args.min_severity},
            severity_uplift=worst or "medium",
            remediation=(
                "Upgrade the listed libraries to a patched release; if you "
                "cannot upgrade, add a Subresource Integrity hash AND a "
                "CSP that blocks the vulnerable file from being executed."),
        )


if __name__ == "__main__":
    SCAJSLibrariesProbe().main()
