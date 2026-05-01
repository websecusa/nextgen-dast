#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""SCA finding validator.

The general-purpose SCA stage walks a target's JavaScript surface and
records (component, version, CVE) tuples. Those findings are useful as
a posture signal but they're easy to argue with — "are you sure that's
the version we ship now?" comes up every quarter when a developer is
sitting in front of the report. This probe answers that question for a
specific finding by going back to the cited file and verifying the
library version actually present.

What we do, given one finding:

    1. Fetch the URL the SCA finding pointed at (typically the .js file
       directly — `app/js/core.min.js` or similar). One request.
    2. Sniff the version using two strategies:
         a. Per-library regex over the file head. Most JS libraries
            preserve a `/*! jQuery v3.7.1 */`-style banner even after
            minification because their build tools mark it as a legal
            comment. We have hand-curated patterns for the libraries
            that show up in nearly every customer engagement
            (jQuery, Bootstrap, Popper, Vue, React, Angular, Lodash,
            Moment).
         b. retire.js as a fallback for libraries the regex catalogue
            doesn't know. retire ships a signature DB that recognises
            most public JS libs from a content hash.
    3. Compare the detected version against the finding's claim:
         * detected matches `package.version` and falls inside
           `vulnerable_range`  → finding still holds (validated)
         * detected >= `fixed_version`                             → finding is stale (not validated)
         * detected disagrees with `package.version` but still in
           the vulnerable range                                    → finding still holds, version drift noted
         * version cannot be detected                              → inconclusive
    4. Return a structured Verdict the UI can render as a diff:
       installed (claimed) / installed (now) / fixed / range / CVE.

The probe never executes any JavaScript. It downloads one file and
runs string operations against it.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.probe import Probe, Verdict          # noqa: E402
from lib.http import SafeClient               # noqa: E402


# ----------------------------------------------------------------------
# Per-library version sniffers. Each entry is (canonical_name,
# regex_with_a_single_capture_group) — the regex runs against the head
# of the fetched file (first ~8 KB). Order matters only when the same
# file matches more than one entry; we always check `component` first
# (the library the finding names) to bias toward the right answer when
# the file is, say, a jQuery+Migrate bundle.
#
# Patterns cover both pretty-printed and minified forms because most
# JS build tools preserve banner comments (`/*! ... */`) through
# minification. Fallback patterns also try the runtime version-property
# assignment some libraries write near the top (e.g. moment's
# `version='2.24.0'`).
# ----------------------------------------------------------------------
_VERSION_SNIFFERS: list[tuple[str, re.Pattern]] = [
    ("jquery", re.compile(
        r"jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("jquery-ui", re.compile(
        r"jQuery\s+UI\s+(?:-\s+)?v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("jquery-migrate", re.compile(
        r"jQuery\s+Migrate\s+(?:-\s+)?v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("bootstrap", re.compile(
        r"Bootstrap\s+v(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("popper.js", re.compile(
        r"(?:@popperjs/core|Popper(?:\.js)?)\s+v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("vue", re.compile(
        r"Vue\.js\s+v(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("react", re.compile(
        r"React\s+v(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("angular", re.compile(
        r"AngularJS\s+v(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("@angular/core", re.compile(
        r"@angular/core\s+@?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("lodash", re.compile(
        r"lodash\s+(?:lodash\.com/license\s*\|\s*)?(?:Build:|v\.?|@)?\s*v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("moment", re.compile(
        r"moment\s+(?:version=|v)\s*['\"]?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("touchswipe", re.compile(
        r"TouchSwipe[^v]*v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
    ("easing", re.compile(
        r"jQuery\s+Easing\s+v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
        re.IGNORECASE)),
]


# Generic banner sniff used when we know the component name but the
# table above doesn't carry a custom regex. Picks up any leading
# `/*! <name> v1.2.3` style banner.
_GENERIC_BANNER_RE = re.compile(
    r"(?:/\*[!*]?|//[!*]?)\s*([A-Za-z0-9_.\-@/]+)\s+v?(\d+\.\d+\.\d+(?:[-\w.]+)?)",
)


def _split_semver(v: str) -> tuple:
    """Best-effort semver tuple for ordered comparison. Strips a leading
    'v', splits on '.' and '-', coerces numeric parts to int. Returns a
    tuple comparable with `<` / `>=`. Pre-release suffix (e.g. -beta.1)
    sorts BEFORE the same numeric on purpose — '3.4.0-beta' < '3.4.0' —
    matching semver ordering."""
    if not v:
        return ()
    s = v.lstrip("vV").strip()
    base, _, pre = s.partition("-")
    parts: list = []
    for chunk in base.split("."):
        try:
            parts.append((1, int(chunk)))
        except ValueError:
            parts.append((0, chunk))
    # Pre-release suffix orders before "no suffix"; mark presence with
    # a leading 0 (lower) so 3.4.0-beta < 3.4.0 < 3.4.1.
    if pre:
        parts.append((0, pre))
    else:
        parts.append((2, ""))   # marker that ranks above any pre-release
    return tuple(parts)


_RANGE_RE = re.compile(
    r"(?P<op>>=|<=|>|<|=|\^|~)?\s*(?P<ver>\d[\w.\-+]*)"
)


def _matches_range(version: str, vulnerable_range: str) -> Optional[bool]:
    """Decide whether `version` falls inside `vulnerable_range`. We
    accept a small subset of common range syntaxes:

        '>=1.0.3 <3.4.0'         retire.js / OSV style
        '<3.4.0'                 single upper bound
        '<= 3.4.0'               etc.
        '3.4.0'                  exact match

    Returns True/False on success, or None if the range can't be parsed
    (defer the call to the caller). Only operators in the regex are
    honoured — wildcards (^, ~) are NOT expanded, we just compare the
    base version. Good enough for the SCA cache's typical output."""
    if not version or not vulnerable_range:
        return None
    v = _split_semver(version)
    if not v:
        return None
    clauses = vulnerable_range.replace(",", " ").split()
    if not clauses:
        return None
    ok_all = True
    parsed_any = False
    for clause in clauses:
        m = _RANGE_RE.search(clause)
        if not m:
            continue
        parsed_any = True
        op = (m.group("op") or "=").strip()
        rv = _split_semver(m.group("ver"))
        if op == ">=":
            ok = v >= rv
        elif op == ">":
            ok = v > rv
        elif op == "<=":
            ok = v <= rv
        elif op == "<":
            ok = v < rv
        elif op in ("=", "", "^", "~"):
            # treat caret/tilde as bare equality match — over-cautious
            # but errs on "still vulnerable" rather than "false clear",
            # which is the right side for a security tool.
            ok = v == rv
        else:
            continue
        ok_all = ok_all and ok
    if not parsed_any:
        return None
    return ok_all


def _retire_signature_path() -> Optional[str]:
    overlay = Path("/data/sca/retire/jsrepository.json")
    baseline = Path("/opt/sca/retire/jsrepository.json")
    if overlay.is_file() and overlay.stat().st_size > 1000:
        return str(overlay)
    if baseline.is_file():
        return str(baseline)
    return None


def _retire_single_file(component: str, body: bytes) -> Optional[str]:
    """Run retire.js against a single staged file and return the
    detected version string for `component`, or None when retire either
    isn't installed, returns nothing useful, or doesn't recognise the
    component. Best-effort fallback for libraries we don't have a regex
    sniffer for."""
    sig_path = _retire_signature_path()
    sig_arg = ["--jsrepo", sig_path] if sig_path else []
    tmp = Path(tempfile.mkdtemp(prefix="sca-validate-"))
    try:
        local = tmp / "candidate.js"
        local.write_bytes(body[:2_000_000])
        cmd = ["retire", "--outputformat", "json", "--exitwith", "0",
               "--path", str(tmp)] + sig_arg
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            return None
        for entry in (data.get("data") or []):
            for comp in entry.get("results", []) or []:
                name = (comp.get("component") or "").strip().lower()
                if component and name != component.lower():
                    continue
                version = (comp.get("version") or "").strip()
                if version:
                    return version
        return None
    finally:
        # rmtree without importing shutil — only one file, one dir.
        try:
            for p in tmp.iterdir():
                p.unlink(missing_ok=True)
            tmp.rmdir()
        except OSError:
            pass


def _detect_version(component: str, body_text: str,
                    body_bytes: bytes) -> tuple[Optional[str], str]:
    """Return (detected_version, method) for the named component.
    `method` is a short label ('regex:jquery', 'banner', 'retire.js',
    'unknown') used in the verdict for traceability.

    Strategy: per-library regex first (preferring the entry whose name
    matches `component`), then the generic banner sniff scoped to the
    component name, then retire.js for fallback."""
    head = body_text[:8192]
    component_lc = (component or "").strip().lower()

    # 1) Try the named component's specific regex first.
    if component_lc:
        for name, rx in _VERSION_SNIFFERS:
            if name == component_lc:
                m = rx.search(head)
                if m:
                    return m.group(1), f"regex:{name}"

    # 2) Try every other regex (a content-fingerprint finding can use
    # an alias like 'migrate' that maps to 'jquery-migrate'; the loop
    # picks up that case).
    for name, rx in _VERSION_SNIFFERS:
        m = rx.search(head)
        if m:
            return m.group(1), f"regex:{name}"

    # 3) Generic banner sniff scoped to the component name.
    if component_lc:
        for m in _GENERIC_BANNER_RE.finditer(head):
            if component_lc in m.group(1).lower():
                return m.group(2), "banner"

    # 4) retire.js fallback for unknown libraries.
    detected = _retire_single_file(component_lc or "", body_bytes)
    if detected:
        return detected, "retire.js"

    return None, "unknown"


class SCAFindingValidate(Probe):
    name = "sca_finding_validate"
    summary = ("Validate a specific SCA finding by fetching the cited "
               "file and comparing the detected library version to the "
               "vulnerable range / fixed version.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument("--component", default="",
                            help="Component name (defaults to "
                                 "raw_data.package.name)")
        parser.add_argument("--claimed-version", dest="claimed_version",
                            default="",
                            help="Version SCA recorded (defaults to "
                                 "raw_data.package.version)")
        parser.add_argument("--fixed-version", dest="fixed_version",
                            default="",
                            help="First fixed version (defaults to "
                                 "raw_data.cached_vuln.fixed_version)")
        parser.add_argument("--vulnerable-range", dest="vulnerable_range",
                            default="",
                            help="Vulnerable range (defaults to "
                                 "raw_data.cached_vuln.vulnerable_range)")
        parser.add_argument("--cve-id", dest="cve_id", default="",
                            help="CVE id (defaults to "
                                 "raw_data.cached_vuln.cve_id)")

    def _enrich_from_raw_data(self, args) -> None:
        """Pull the package + cached_vuln fields out of the finding's
        raw_data JSON when the caller didn't pass them as flags. The
        Challenge button always passes raw_data; CLI users can pass
        flags manually."""
        raw_blob = ""
        extra = getattr(args, "extra", None) or {}
        if isinstance(extra, dict):
            raw_blob = extra.get("raw_data") or ""
        if not raw_blob:
            return
        try:
            raw = (json.loads(raw_blob)
                   if isinstance(raw_blob, str) else raw_blob)
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        pkg = raw.get("package") or {}
        vuln = raw.get("cached_vuln") or {}
        if not args.component:
            args.component = (pkg.get("name") or "").strip()
        if not args.claimed_version:
            args.claimed_version = (pkg.get("version") or "").strip()
        if not args.fixed_version:
            args.fixed_version = (vuln.get("fixed_version") or "").strip()
        if not args.vulnerable_range:
            args.vulnerable_range = (vuln.get("vulnerable_range") or "").strip()
        if not args.cve_id:
            args.cve_id = (vuln.get("cve_id") or "").strip()

    def run(self, args, client: SafeClient) -> Verdict:
        self._enrich_from_raw_data(args)

        url = (args.url or "").strip()
        component = (args.component or "").strip()
        claimed = (args.claimed_version or "").strip()
        fixed = (args.fixed_version or "").strip()
        vrange = (args.vulnerable_range or "").strip()
        cve_id = (args.cve_id or "").strip()

        if not url:
            return Verdict(ok=False, validated=None,
                           summary="no URL to validate",
                           error="missing url")
        if not component:
            return Verdict(ok=False, validated=None,
                           summary="finding does not name a component",
                           error="missing component")

        # Fetch the file via SafeClient. One request. Probes that overrun
        # their budget are killed by the lib; we set a low budget here
        # because we genuinely need just this file.
        try:
            r = client.get(url)
        except Exception as e:
            return Verdict(ok=False, validated=None,
                           summary=f"failed to fetch {url}: {e}",
                           error=str(e))
        # SafeClient.Response exposes `.status` and `.body`. The
        # hasattr fallbacks tolerate a future client that uses the
        # requests-library names instead, but `.status` is the canonical
        # path here.
        status = getattr(r, "status", None)
        if status is None:
            status = getattr(r, "status_code", 0)
        if status >= 400:
            return Verdict(
                ok=True, validated=False, confidence=0.6,
                summary=(f"target returned HTTP {status} for "
                         f"{url} — file is no longer served, finding may "
                         "be stale"),
                evidence={
                    "url": url, "status": status,
                    "component": component, "claimed_version": claimed,
                    "fixed_version": fixed, "cve_id": cve_id,
                })

        body_bytes = getattr(r, "body", None)
        if body_bytes is None:
            body_bytes = getattr(r, "content", b"") or b""
        body_text = body_bytes.decode("utf-8", "replace")
        sha_prefix = hashlib.sha256(body_bytes).hexdigest()[:16]

        detected, method = _detect_version(component, body_text, body_bytes)

        # Build the evidence block first — it's identical across the
        # validated/not-validated branches, just with different summary
        # text wrapping it.
        evidence = {
            "url": url,
            "component": component,
            "cve_id": cve_id,
            "claimed_version": claimed or None,
            "detected_version": detected,
            "detection_method": method,
            "fixed_version": fixed or None,
            "vulnerable_range": vrange or None,
            "file_size_bytes": len(body_bytes),
            "content_sha256_prefix": sha_prefix,
        }

        if not detected:
            # We have the file, we just couldn't pull a version out of
            # it. Don't claim "patched" — the original SCA detector had
            # other signals (file hash, AST shape) we can't replicate
            # with a regex. Mark as inconclusive so the analyst knows
            # to look more closely.
            return Verdict(
                ok=True, validated=None, confidence=0.4,
                summary=(f"fetched {url} but could not detect a "
                         f"version banner for '{component}'. Original "
                         f"SCA finding stands; manual review needed."),
                evidence=evidence,
            )

        # Decide vulnerable / patched. Prefer the explicit range when
        # present; otherwise fall back to comparing to fixed_version.
        is_vulnerable: Optional[bool] = None
        if vrange:
            is_vulnerable = _matches_range(detected, vrange)
        if is_vulnerable is None and fixed:
            is_vulnerable = _split_semver(detected) < _split_semver(fixed)

        # Build a one-line "diff" used in the verdict summary so the UI
        # / report has a clear sentence without parsing the evidence
        # dict. Format: "jquery 3.0.0 (claimed) / 3.0.0 (now); fixed in
        # 3.4.0".
        parts = [f"{component} {detected}"]
        if claimed and claimed != detected:
            parts.append(f"(claimed {claimed})")
        if fixed:
            parts.append(f"fixed in {fixed}")
        if cve_id:
            parts.append(f"[{cve_id}]")
        diff_line = " — ".join(parts) if len(parts) > 1 else parts[0]

        if is_vulnerable is True:
            return Verdict(
                ok=True, validated=True, confidence=0.92,
                summary=("Confirmed: file at "
                         f"{url} still ships {component} {detected}. "
                         f"{diff_line}."),
                evidence=evidence,
                remediation=(
                    f"Upgrade {component} to {fixed or 'a patched release'} "
                    "or later. If the build pipeline pins a transitive "
                    f"dependency on the older {component} version, refresh "
                    "the lockfile. Add a Subresource Integrity hash AND a "
                    "deploy-time check that fails when a vulnerable "
                    "release ships."),
            )

        if is_vulnerable is False:
            return Verdict(
                ok=True, validated=False, confidence=0.92,
                summary=("Patched: file at "
                         f"{url} now ships {component} {detected}, which "
                         "is outside the vulnerable range. Original "
                         "finding appears to be stale — close after "
                         "confirming the SCA cache has been refreshed."),
                evidence=evidence,
            )

        # Range parsed nothing useful, no fixed_version to fall back to.
        # Return the file as evidence with an inconclusive verdict.
        return Verdict(
            ok=True, validated=None, confidence=0.5,
            summary=(f"detected {component} {detected} but could not "
                     "determine whether that version is vulnerable from "
                     "the recorded range. Manual cross-check with the "
                     "advisory recommended."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SCAFindingValidate().main()
