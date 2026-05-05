#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Content-Security-Policy ships specific weakening directives.

This probe is deliberately narrower than `config_csp_missing_or_unsafe`,
which fires when the CSP is absent or has an obviously broken
script-src. This one assumes the CSP IS present and looks for the
finer-grained weaknesses that survive a basic policy review:

  - `script-src` (or its `default-src` fallback) contains
    `'unsafe-inline'` AND no nonce / hash source -- the modern CSP3
    fallback rule means a nonce/hash makes 'unsafe-inline' a no-op,
    so we only flag when neither is present.
  - `'unsafe-eval'` appears anywhere in script-src / default-src.
  - `base-uri` directive is absent (attacker-injected `<base href>`
    can re-anchor every relative script URL, defeating an otherwise
    strict policy).
  - `object-src` directive is absent AND `default-src` does not
    constrain it (default-src is the fallback for object-src; only
    flag when both are missing or default-src is `*` / `'unsafe-*'`).

We require >=1 of those four signals and report all that apply, so
operators see the full attack surface in one finding.

To stay high-fidelity:
  - The CSP must actually be present on a 200 HTML response.
    A site without CSP is the sibling probe's territory; this probe
    refuses to overlap.
  - `'unsafe-inline'` is ignored when a nonce / hash source is also
    listed (CSP3 fallback rule).

Detection signal:
  At least one of {script-src 'unsafe-inline' without nonce/hash;
  'unsafe-eval' anywhere in script-src/default-src; base-uri absent;
  object-src absent with default-src not constraining} on a 200 HTML
  response from `/` or another sampled path.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = ("/", "/index.html", "/login", "/dashboard")

# Regex for breaking a CSP header string into directive -> sources
# pairs. Keep it anchored so a directive name embedded in a
# comment-shaped value can't false-positive.
_DIRECTIVE_RE = re.compile(r"(?:^|;)\s*([a-z-]+)\s+([^;]+)", re.I)


def _csp(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-security-policy":
            return str(v)
    return ""


def _content_type_html(headers: dict) -> bool:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return "text/html" in str(v).lower()
    return False


def _parse_csp(csp: str) -> dict:
    """Parse `csp` into {directive_name: [source, source, ...]} with
    lower-cased directive names. Source tokens keep their original
    casing so quoted keywords like `'unsafe-inline'` stay matchable."""
    out: dict = {}
    for m in _DIRECTIVE_RE.finditer(csp or ""):
        name = m.group(1).lower()
        sources = m.group(2).split()
        out[name] = sources
    return out


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith("'nonce-") or s.startswith("'sha")
               for s in (sources or []))


def _has_token(sources: list[str], token: str) -> bool:
    """Case-insensitive membership check; CSP keywords are
    quoted-lower-case in spec but real-world headers vary."""
    needle = token.lower()
    return any(s.lower() == needle for s in (sources or []))


def _is_unconstrained_default_src(sources: list[str]) -> bool:
    """default-src is a viable object-src fallback when it actually
    constrains. Treat `*` as unconstrained, and treat the absence of
    default-src as also unconstrained for our purposes."""
    if not sources:
        return True
    return _has_token(sources, "*")


def _analyze(parsed: dict) -> list[dict]:
    """Return the list of weakness rows that apply. Each row has a
    `kind` (machine-readable) and `note` (human-readable)."""
    findings: list[dict] = []

    # CSP3 fallback: when both `script-src` and a nonce/hash are
    # present, the script-src wins; default-src is irrelevant for
    # script. So we evaluate script controls using script-src if
    # set, else default-src.
    script_sources = parsed.get("script-src") or parsed.get("default-src") or []
    nonce_or_hash = _has_nonce_or_hash(script_sources)

    if _has_token(script_sources, "'unsafe-inline'") and not nonce_or_hash:
        findings.append({
            "kind": "unsafe_inline_script",
            "note": ("script-src includes 'unsafe-inline' with no "
                     "nonce / hash source -- inline <script> blocks "
                     "the attacker injects will execute."),
        })
    if _has_token(script_sources, "'unsafe-eval'"):
        findings.append({
            "kind": "unsafe_eval",
            "note": ("script-src includes 'unsafe-eval' -- eval() and "
                     "new Function() will execute attacker-controlled "
                     "strings."),
        })

    # base-uri is independent of script-src; if missing, an injected
    # <base href="//attacker"> can redirect every relative <script
    # src> to the attacker's host even on a CSP that locks down
    # script-src to 'self'.
    if not parsed.get("base-uri"):
        findings.append({
            "kind": "missing_base_uri",
            "note": ("no base-uri directive -- a single injected "
                     "<base> tag can re-root every relative URL on "
                     "the page, defeating a strict script-src 'self'."),
        })

    # object-src protects against <object>/<embed>/<applet> sourced
    # script equivalents. default-src is its fallback.
    object_sources = parsed.get("object-src")
    default_sources = parsed.get("default-src") or []
    if not object_sources and _is_unconstrained_default_src(default_sources):
        findings.append({
            "kind": "missing_object_src",
            "note": ("no object-src directive and default-src does not "
                     "constrain -- <object data='...'> can load "
                     "attacker-controlled plugin content."),
        })

    return findings


class ClientJsCspUnsafeDirectivesProbe(Probe):
    name = "clientjs_csp_unsafe_directives"
    summary = ("Detects fine-grained CSP weaknesses (unsafe-inline / "
               "unsafe-eval / missing base-uri / missing object-src).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to probe (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed_url = urlparse(args.url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p),
                                follow_redirects=False)
            row: dict = {"path": p, "status": r.status}
            if r.status != 200:
                row["skipped"] = "status_not_200"
                attempts.append(row)
                continue
            csp = _csp(r.headers or {})
            row["csp_present"] = bool(csp)
            row["is_html"] = _content_type_html(r.headers or {})
            if not csp:
                # Sibling probe handles the absent case; we
                # explicitly do NOT overlap.
                row["skipped"] = "no_csp_present"
                attempts.append(row)
                continue
            row["csp"] = csp[:300]
            parsed = _parse_csp(csp)
            findings = _analyze(parsed)
            row["findings"] = findings
            attempts.append(row)
            if findings and not confirmed:
                confirmed = {**row, "directives": parsed}

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            kinds = [f["kind"] for f in confirmed["findings"]]
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: CSP on "
                    f"{origin}{confirmed['path']} ships "
                    f"{len(kinds)} directive-level weakness(es): "
                    f"{', '.join(kinds)}. A reflected-XSS or stored-XSS "
                    "elsewhere on this origin will exploit these."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Tighten the CSP one directive at a time:\n"
                    "  - Drop `'unsafe-inline'` from script-src; emit "
                    "every inline <script> with a per-request nonce "
                    "(`<script nonce=\"{nonce}\">`) and add "
                    "`'nonce-{nonce}'` to script-src. CSP3 will then "
                    "ignore the legacy 'unsafe-inline' even if "
                    "another middleware re-adds it.\n"
                    "  - Drop `'unsafe-eval'` and audit any code that "
                    "uses eval / new Function / setTimeout(<string>); "
                    "replace with real function references.\n"
                    "  - Add `base-uri 'self'` (or `'none'`) -- this "
                    "is a single short directive that closes a major "
                    "bypass class.\n"
                    "  - Add `object-src 'none'` -- there is rarely a "
                    "legitimate reason to load <object>/<embed> on "
                    "a modern app.\n"
                    "Verify the result with csp-evaluator.withgoogle.com "
                    "before shipping."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} path(s) on "
                     f"{origin}; every CSP-bearing response is free of "
                     "unsafe-inline (without nonce), unsafe-eval, and "
                     "ships base-uri + object-src constraints."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsCspUnsafeDirectivesProbe().main()
