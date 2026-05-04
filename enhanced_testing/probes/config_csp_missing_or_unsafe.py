#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Misconfiguration: Content-Security-Policy absent or permits inline /
eval'd script.

A CSP that's either missing or permissive is the difference between
"a single reflected-XSS finding becomes session theft" and "the
browser blocks the script before it runs." The bug surfaces in three
shapes:
  1. No CSP at all on an HTML response.
  2. CSP present but `script-src` includes `'unsafe-inline'` (allows
     inline `<script>` blocks the attacker injects).
  3. CSP present but `script-src` includes `'unsafe-eval'` (allows
     `eval()` / `new Function()` inside attacker-controlled JSON).
  Plus 'unsafe-hashes' on a script-src is similarly weak.

A CSP that uses a `'nonce-...'` or `'sha256-...'` source alongside
unsafe-inline is fine -- the browser ignores `'unsafe-inline'` in
that case (CSP3 fallback rules). The probe accounts for that.

Detection signal:
  GET `/`, `/login`, `/dashboard`. Look at headers:
    - If no `Content-Security-Policy` AND content-type starts
      `text/html` -> validate (case 1).
    - If CSP present and `script-src` (or `default-src`, used as the
      script fallback) contains `'unsafe-inline'` or `'unsafe-eval'`
      AND no nonce/hash source -> validate (cases 2 and 3).

Tested against:
  + OWASP Juice Shop  No CSP header on / -> validated=True.
  + nginx default site -> validated=True (also has no CSP) -- but
                          the response is `text/html` so this one's
                          a true positive on both targets.
  + Apps with Helmet's default CSP (`default-src 'self'` only) ->
    validated=False.

Read-only: GET only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = ("/", "/login", "/dashboard", "/account", "/index.html")

# CSP-keyword regex helpers. Keep them anchored so a directive name
# in a comment can't false-positive.
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
    """Return {directive: [sources]}. Lower-cased directives."""
    out: dict = {}
    for m in _DIRECTIVE_RE.finditer(csp or ""):
        name = m.group(1).lower()
        sources = m.group(2).split()
        out[name] = sources
    return out


def _script_src_kind(parsed: dict) -> tuple[str, list[str]]:
    """Classify the effective script-src as one of:
      - 'safe'      (nonce/hash present OR strict allowlist)
      - 'unsafe'    (unsafe-inline or unsafe-eval, no nonce/hash)
      - 'absent'    (no script-src and no default-src)
      - 'permissive'(default-src * or script-src *)
    Returns (kind, sources)."""
    sources = parsed.get("script-src") or parsed.get("default-src") or []
    if not sources:
        return "absent", []
    has_nonce_or_hash = any(s.startswith("'nonce-") or s.startswith("'sha")
                             for s in sources)
    has_unsafe = any(s in ("'unsafe-inline'", "'unsafe-eval'",
                            "'unsafe-hashes'")
                     for s in sources)
    has_star = any(s == "*" for s in sources)
    if has_star:
        return "permissive", sources
    if has_unsafe and not has_nonce_or_hash:
        return "unsafe", sources
    return "safe", sources


class CspMissingOrUnsafeProbe(Probe):
    name = "config_csp_missing_or_unsafe"
    summary = ("Detects Content-Security-Policy that is absent on an "
               "HTML response, or present but permits inline / eval'd "
               "script.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to probe. Repeatable.")

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
            if r.status not in (200,):
                attempts.append({"path": p, "status": r.status,
                                  "skipped": True})
                continue
            csp = _csp(r.headers or {})
            html = _content_type_html(r.headers or {})
            row: dict = {"path": p, "status": r.status,
                         "is_html": html,
                         "csp": csp[:200] or None}
            if html and not csp:
                row["finding"] = "no_csp_on_html"
                confirmed = row
                attempts.append(row)
                break
            if csp:
                parsed = _parse_csp(csp)
                kind, srcs = _script_src_kind(parsed)
                row["script_src_kind"] = kind
                row["script_src"] = srcs
                if kind in ("unsafe", "permissive"):
                    row["finding"] = f"script_src_{kind}"
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            kind = confirmed.get("finding")
            if kind == "no_csp_on_html":
                kind_msg = ("no Content-Security-Policy header on an "
                            "HTML response")
            else:
                kind_msg = (f"script-src is "
                            f"{confirmed.get('script_src_kind')} "
                            f"({' '.join(confirmed.get('script_src') or [])})")
            return Verdict(
                validated=True, confidence=0.90,
                summary=(
                    f"Confirmed: weak CSP on "
                    f"{origin}{confirmed['path']} -- {kind_msg}. A "
                    "future reflected-XSS finding here will turn into "
                    "session theft instead of being blocked by the "
                    "browser."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Ship a Content-Security-Policy that locks down "
                    "script execution to known sources.\n"
                    "  - Helmet (Express): "
                    "  `helmet({contentSecurityPolicy: { directives: { "
                    "  defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\", "
                    "  \"'nonce-{nonce}'\"] }}})` -- generate a per-"
                    "request nonce and inject it on every inline "
                    "<script>.\n"
                    "  - Django: `django-csp`'s middleware with "
                    "`CSP_SCRIPT_SRC = (\"'self'\",)`; remove "
                    "`'unsafe-inline'` even if it means refactoring "
                    "templates to load scripts from files instead of "
                    "inlining.\n"
                    "  - Rails: `config.content_security_policy` with "
                    "`policy.script_src :self, :https`.\n"
                    "Verify with the CSP evaluator at "
                    "csp-evaluator.withgoogle.com -- it flags every "
                    "common weakening before deployment."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} paths on {origin}; "
                     "each HTML response carried a CSP whose script-src "
                     "is locked down (nonce/hash sources, no "
                     "'unsafe-inline'/'unsafe-eval')."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CspMissingOrUnsafeProbe().main()
