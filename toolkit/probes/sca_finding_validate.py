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


# Pulled from any flavor of <script src="..."> the page exposes. We use
# a permissive expression here because we are not parsing a DOM, just
# salvaging URLs. The match captures the src value irrespective of
# quote style (single, double, none) and tolerates extra attributes.
_SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
    re.IGNORECASE,
)

# Cap on how many candidate scripts we follow when an SCA finding
# pointed at a page URL instead of a JS asset. Five keeps the total
# request count (1 page fetch + up to 5 scripts) inside the manifest's
# request_budget_max=6, so the SafeClient cap kicks in cleanly.
_MAX_SCRIPT_FOLLOWS = 5


def _looks_like_html(body_text: str) -> bool:
    """Cheap heuristic — true if the body opens with a markup byte
    sequence we'd expect from a browser-rendered page. We don't sniff
    Content-Type because some servers mis-set it; the leading bytes
    are more reliable for the "is this an HTML wrapper?" decision the
    fan-out logic needs."""
    head = body_text[:2048].lstrip().lower()
    if not head:
        return False
    return (head.startswith("<!doctype html")
            or head.startswith("<html")
            or "<head" in head[:512]
            or "<body" in head[:512])


def _extract_script_srcs(html: str, base_url: str) -> list[str]:
    """Pull script src URLs out of an HTML page and resolve each
    relative URL against `base_url`. Filters out empty values, data:
    and javascript: pseudo-protocols, and de-duplicates while keeping
    document order. Caps the result at _MAX_SCRIPT_FOLLOWS so the caller
    cannot blow the request budget."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if not src:
            continue
        low = src.lower()
        if low.startswith(("data:", "javascript:", "blob:", "about:")):
            continue
        absolute = urllib.parse.urljoin(base_url, src)
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
        if len(out) >= _MAX_SCRIPT_FOLLOWS:
            break
    return out


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


# OSV ecosystem aliases — `package.ecosystem` on the OSV side may be
# 'npm', 'SEMVER' (npm-shaped semver from a non-tagged ecosystem),
# 'PyPI', etc. We treat 'SEMVER' and 'npm' as interchangeable for
# matching because almost every npm-derived OSV record uses one or the
# other. Empty / unknown ecosystem on either side falls through to a
# name-only match — better to derive an approximate range than to
# return a probe verdict with no range data at all.
_OSV_ECO_EQUIVALENTS: dict[str, set[str]] = {
    "npm": {"npm", "semver"},
    "semver": {"npm", "semver"},
}


def _derive_osv_range(vuln: dict, *, ecosystem: str, name: str,
                       version: str) -> tuple[str, str]:
    """Translate an OSV `vulnerability` record into the (fixed_version,
    vulnerable_range) pair the rest of this probe uses.

    OSV stores affected versions as a list of `affected[]` blocks, one
    per ecosystem. Each block has a `ranges[]` list, and each range is
    an event sequence of `{introduced, fixed, last_affected}`. We:

      1. Pick the affected[] block whose ecosystem matches our finding
         and whose name matches our component (some advisories cover
         multiple package names — bootstrap, bootstrap-sass, twbs/
         bootstrap, etc.).
      2. Within that block, pick the range whose [introduced, fixed)
         interval contains our `version` if we can decide; otherwise
         take the first range as a best-effort.
      3. Convert the events to a SemVer-style string the existing
         `_matches_range` accepts: ">=A <B".

    Returns ("", "") when nothing matches — the caller leaves the
    args fields empty and the probe lands on the "couldn't determine
    vulnerability from the recorded range" branch, same as before."""
    if not isinstance(vuln, dict):
        return "", ""
    eco_lc = (ecosystem or "").strip().lower()
    name_lc = (name or "").strip().lower()
    eco_aliases = _OSV_ECO_EQUIVALENTS.get(eco_lc, {eco_lc})

    candidates = []
    for entry in vuln.get("affected") or []:
        ent_pkg = entry.get("package") or {}
        ent_eco = (ent_pkg.get("ecosystem") or "").strip().lower()
        ent_name = (ent_pkg.get("name") or "").strip().lower()
        # Prefer eco+name matches; accept name-only when no eco match
        # has surfaced yet so a misaligned ecosystem field doesn't
        # leave the probe with empty data.
        if eco_aliases and ent_eco and ent_eco not in eco_aliases:
            continue
        if name_lc and ent_name and ent_name != name_lc:
            continue
        candidates.append(entry)

    if not candidates:
        return "", ""

    # Two-pass selection: first walk every range looking for one whose
    # [introduced, fixed) interval contains our version; only if no
    # range matches do we fall back to the first range as a best-
    # effort. This matters for advisories that publish separate
    # ranges per branch (3.0.0..3.4.1 AND 4.0.0..4.3.1 for the same
    # CVE). The earlier single-pass form fell into best-effort the
    # moment the first candidate failed the version check, hiding the
    # branch-correct range that came after it.
    target_v = _split_semver(version) if version else None
    parsed_ranges: list[tuple[str, str, str]] = []
    for entry in candidates:
        for rng in entry.get("ranges") or []:
            introduced = ""
            fixed = ""
            last_affected = ""
            for ev in rng.get("events") or []:
                if "introduced" in ev and not introduced:
                    introduced = (ev.get("introduced") or "").strip()
                if "fixed" in ev and not fixed:
                    fixed = (ev.get("fixed") or "").strip()
                if "last_affected" in ev and not last_affected:
                    last_affected = (ev.get("last_affected") or "").strip()
            if introduced or fixed or last_affected:
                parsed_ranges.append((introduced, fixed, last_affected))

    if not parsed_ranges:
        return "", ""

    chosen_range: Optional[tuple[str, str, str]] = None
    if target_v is not None:
        for introduced, fixed, last_affected in parsed_ranges:
            if not (introduced and fixed):
                continue
            lo = _split_semver(introduced) if introduced != "0" else ()
            hi = _split_semver(fixed)
            if (not lo or target_v >= lo) and target_v < hi:
                chosen_range = (introduced, fixed, last_affected)
                break
    if chosen_range is None:
        chosen_range = parsed_ranges[0]

    introduced_c, fixed_c, last_affected_c = chosen_range
    chosen_fixed = fixed_c

    parts = []
    if introduced_c and introduced_c != "0":
        parts.append(f">={introduced_c}")
    if fixed_c:
        parts.append(f"<{fixed_c}")
    elif last_affected_c:
        parts.append(f"<={last_affected_c}")
    return chosen_fixed, " ".join(parts)


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


# Cap on how much of the response body we run regex sniffers against.
# The original 8 KB was sized for a single-library JS file where the
# banner is always at the top. Real-world apps ship multi-library
# bundles (jQuery + Bootstrap + Popper + ... in a single core.min.js
# of ~700 KB) where any individual library's banner can live well
# past the first kilobyte. 1 MiB covers every JS bundle we have seen
# in practice and keeps the regex pass cheap (single-digit milliseconds
# even on a fully matched sweep).
_SNIFF_WINDOW_BYTES = 1 * 1024 * 1024


def _detect_version(component: str, body_text: str,
                    body_bytes: bytes) -> tuple[Optional[str], str]:
    """Return (detected_version, method) for the named component.
    `method` is a short label ('regex:jquery', 'banner', 'retire.js',
    'unknown') used in the verdict for traceability.

    Strategy: per-library regex first (preferring the entry whose name
    matches `component`), then the generic banner sniff scoped to the
    component name, then retire.js for fallback. When the named
    component IS in our regex catalog and its dedicated regex misses,
    we deliberately do NOT fall through to other libraries' regexes —
    finding jQuery's banner in core.min.js does not tell us anything
    about whether Bootstrap is in the same bundle, and reporting one
    library's version under another library's name produced
    misleading "phantom detection" verdicts in earlier builds."""
    window = body_text[:_SNIFF_WINDOW_BYTES]
    component_lc = (component or "").strip().lower()
    component_in_catalog = any(
        name == component_lc for name, _ in _VERSION_SNIFFERS)

    # 1) Try the named component's specific regex first.
    if component_lc and component_in_catalog:
        for name, rx in _VERSION_SNIFFERS:
            if name == component_lc:
                m = rx.search(window)
                if m:
                    return m.group(1), f"regex:{name}"
        # 1b) Catalog miss for a known component. Try the component-
        # scoped generic banner before giving up — covers cases where
        # the lib uses a non-canonical banner string the catalog regex
        # missed.
        for m in _GENERIC_BANNER_RE.finditer(window):
            if component_lc in m.group(1).lower():
                return m.group(2), "banner"
        # We will not fall through to other libraries' regexes here.
        # Return None so the caller can mark the verdict as "no proof"
        # rather than misattributing another lib's banner. retire.js
        # below is still given a chance — it does its own per-library
        # signature match against the file content and won't mislabel.
        detected = _retire_single_file(component_lc, body_bytes)
        if detected:
            return detected, "retire.js"
        return None, "unknown"

    # 2) Component NOT in the catalog (or no component name supplied).
    # Try every regex — the SCA finding may have been raised against an
    # alias the catalog doesn't enumerate (e.g. 'migrate' should match
    # 'jquery-migrate'). First match wins.
    for name, rx in _VERSION_SNIFFERS:
        m = rx.search(window)
        if m:
            return m.group(1), f"regex:{name}"

    # 3) Generic banner sniff scoped to the component name (if any).
    if component_lc:
        for m in _GENERIC_BANNER_RE.finditer(window):
            if component_lc in m.group(1).lower():
                return m.group(2), "banner"

    # 4) retire.js fallback for libraries we can't sniff via regex.
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
        """Pull the package + vulnerability fields out of the finding's
        raw_data JSON when the caller didn't pass them as flags. The
        Challenge button always passes raw_data; CLI users can pass
        flags manually.

        Three raw_data shapes are recognized:
          * retire.js — `{package, cached_vuln: {fixed_version,
            vulnerable_range, cve_id}}`. cached_vuln carries already-
            normalised strings, so we copy them across verbatim.
          * osv-scanner — `{ecosystem, package, vulnerability}` where
            `vulnerability` is the raw OSV record. Range and fixed
            version live inside `affected[].ranges[].events[]` and
            need to be rederived per-ecosystem; the CVE id lives in
            `aliases`.
          * LLM-augmented — same envelope as retire.js since
            sca.augment_with_llm normalises to that shape.

        Order matters: we prefer cached_vuln when both are present
        because it has already been normalised; the OSV branch only
        runs when cached_vuln is absent or empty.
        """
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
        cached_vuln = raw.get("cached_vuln") or {}
        if not args.component:
            args.component = (pkg.get("name") or "").strip()
        if not args.claimed_version:
            args.claimed_version = (pkg.get("version") or "").strip()

        # Branch 1 — retire.js / LLM-augmented findings carry a
        # pre-normalised cached_vuln block. Use it as-is.
        if cached_vuln:
            if not args.fixed_version:
                args.fixed_version = (
                    cached_vuln.get("fixed_version") or "").strip()
            if not args.vulnerable_range:
                args.vulnerable_range = (
                    cached_vuln.get("vulnerable_range") or "").strip()
            if not args.cve_id:
                args.cve_id = (cached_vuln.get("cve_id") or "").strip()
            return

        # Branch 2 — osv-scanner findings carry the raw OSV record at
        # raw_data.vulnerability. Derive the fields we need from the
        # affected[] entry whose ecosystem matches the finding.
        osv_vuln = raw.get("vulnerability") or {}
        if not osv_vuln:
            return
        eco = (raw.get("ecosystem") or pkg.get("ecosystem") or "").strip()
        comp = (pkg.get("name") or args.component or "").strip()
        version = (pkg.get("version") or args.claimed_version or "").strip()
        fixed, vrange = _derive_osv_range(
            osv_vuln, ecosystem=eco, name=comp, version=version)
        if not args.fixed_version and fixed:
            args.fixed_version = fixed
        if not args.vulnerable_range and vrange:
            args.vulnerable_range = vrange
        if not args.cve_id:
            cve = ""
            for alias in osv_vuln.get("aliases") or []:
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    cve = alias
                    break
            # Fall back to the OSV id (GHSA-...) when no CVE alias is
            # present — better than an empty string in the verdict.
            args.cve_id = cve or (osv_vuln.get("id") or "").strip()

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
        # Track which URL produced the version match. For a direct JS
        # finding this is just the input URL; for an HTML fan-out it's
        # the specific script we sniffed. The verdict surfaces this so
        # an analyst reviewing the audit log can see exactly what we
        # validated against.
        detected_url = url
        scripts_checked: list[str] = []

        # When the original SCA finding pointed at the bare site root
        # (legacy data — fingerprint-derived findings used to record the
        # target hostname instead of the actual JS asset), the response
        # body is HTML and we have nothing to sniff. Walk the page's
        # <script src=...> attributes and try each candidate within the
        # client's remaining request budget. This recovers validation
        # for findings produced before the upstream sca_runner fix.
        if not detected and _looks_like_html(body_text):
            for js_url in _extract_script_srcs(body_text, url):
                scripts_checked.append(js_url)
                try:
                    jr = client.get(js_url)
                except Exception:
                    # Budget exhausted or unreachable script — try the
                    # next candidate; SafeClient will raise consistently
                    # once the cap is hit, so keep the loop bounded.
                    break
                jstatus = getattr(jr, "status", None)
                if jstatus is None:
                    jstatus = getattr(jr, "status_code", 0)
                if jstatus >= 400:
                    continue
                jbody = getattr(jr, "body", None) or getattr(
                    jr, "content", b"") or b""
                jtext = jbody.decode("utf-8", "replace")
                cand, cand_method = _detect_version(
                    component, jtext, jbody)
                if cand:
                    detected = cand
                    method = cand_method
                    detected_url = js_url
                    body_bytes = jbody
                    sha_prefix = hashlib.sha256(jbody).hexdigest()[:16]
                    break

        # Build the evidence block first — it's identical across the
        # validated/not-validated branches, just with different summary
        # text wrapping it.
        evidence = {
            "url": url,
            "detected_url": detected_url,
            "scripts_checked": scripts_checked,
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
            # We fetched the cited URL (and any linked scripts) but found
            # no version banner. We don't claim "patched" — the upstream
            # SCA detector relied on signals (hash, AST shape) we can't
            # reproduce here. We DO call the result a "no proof" verdict
            # rather than asserting the finding stands: an open finding
            # that has been validated and yielded no evidence should look
            # different in the UI from one that simply has not been
            # checked yet. confidence=0.5 (was 0.4) bumps the verdict out
            # of the "obvious manual review" band into "the analyst has
            # to make a call" territory; status remains 'open' but the
            # validation_notes make the no-proof state explicit.
            checked_note = ""
            if scripts_checked:
                checked_note = (
                    f" Followed {len(scripts_checked)} <script src> "
                    f"URLs from the page; none carried a recognizable "
                    f"'{component}' banner.")
            elif _looks_like_html(body_text):
                checked_note = (
                    f" The response was HTML, not a JS asset, and "
                    "exposed no script references the probe could "
                    "fan out to.")
            return Verdict(
                ok=True, validated=None, confidence=0.5,
                summary=(f"no validation evidence: fetched {url} but "
                         f"could not detect a version banner for "
                         f"'{component}'.{checked_note} Finding has "
                         "no on-target proof — review whether to keep "
                         "it open or close as unverifiable."),
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
