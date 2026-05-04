#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Cache poisoning: unkeyed `X-Forwarded-Host` reflected into a
cacheable response.

The classic web-cache-poisoning primitive: a CDN that doesn't
include `X-Forwarded-Host` (or `X-Forwarded-Scheme`, `X-Original-URL`)
in its cache key, paired with an origin that reflects the header into
a `<link rel="canonical">`, an absolute redirect, an OG-meta URL, or
a JSON-LD block. The attacker poisons the cached response with their
own marker host; every subsequent visitor's browser follows the
canonical link / og:url / etc. into the attacker's domain.

The high-fidelity signal pairs three facts:
  1. The attacker-controlled header is reflected into the response
     body verbatim.
  2. The response carries a cacheable header set.
  3. The reflection ends up in a HTML element that browsers act on
     (canonical link, og:url, redirect Location, base href).

Detection signal:
  GET `/`, `/login`, `/about`, `/index.html` with header
  `X-Forwarded-Host: dast-marker-XXXX.example`. Validate when the
  marker host appears in the response body AND a cacheable Cache-
  Control header is set.

Tested against:
  + OWASP Juice Shop  Express's edge config doesn't reflect XFH;
                      validated=False.
  + Real apps with Rails / Django default canonical-URL templates
    paired with a non-Vary-on-XFH CDN -> validated=True.

Read-only: GET only.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

POISON_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Original-Host",
    "X-Host",
    "Forwarded",
)

PATHS = ("/", "/login", "/index.html", "/home", "/about")

# Lighter version of the cacheable-headers check from the cache-
# deception probe. Same logic; duplicated so each probe is self-
# contained (the existing toolkit follows that pattern).
_NOCACHE_TOKENS = ("private", "no-store", "no-cache",
                    "must-revalidate", "max-age=0")


def _is_cacheable(headers: dict) -> tuple[bool, str]:
    cc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "cache-control":
            cc = str(v).lower()
            break
    if any(tok in cc for tok in _NOCACHE_TOKENS):
        return False, f"cache-control: {cc}"
    if "public" in cc or re.search(r"max-age=\s*[1-9]\d*", cc) or "s-maxage" in cc:
        return True, f"cache-control: {cc}"
    if not cc:
        return True, "no Cache-Control header"
    return False, f"cache-control: {cc}"


def _reflection_context(text: str, marker: str) -> str | None:
    """Return a short label for WHERE the marker ended up. We only
    treat 'this is exploitable' contexts as findings -- canonical
    link, og:url meta, base href, json-ld @id, and absolute
    Location-style URLs in JS strings."""
    if not text or marker not in text:
        return None
    # Most actionable contexts -- ordered by exploit value.
    contexts: tuple[tuple[re.Pattern, str], ...] = (
        (re.compile(r'<link[^>]+rel\s*=\s*"canonical"[^>]*'
                    r'href\s*=\s*"[^"]*' + re.escape(marker), re.I),
                                                   "<link rel=canonical>"),
        (re.compile(r'<meta[^>]+property\s*=\s*"og:url"[^>]*'
                    r'content\s*=\s*"[^"]*' + re.escape(marker), re.I),
                                                   "<meta og:url>"),
        (re.compile(r'<base\s+href\s*=\s*"[^"]*' + re.escape(marker), re.I),
                                                   "<base href>"),
        (re.compile(r'"@id"\s*:\s*"[^"]*' + re.escape(marker)),
                                                   "json-ld @id"),
        (re.compile(r'(?:href|src|action)\s*=\s*"[^"]*//' + re.escape(marker), re.I),
                                                   "absolute href/src/action"),
    )
    for pat, label in contexts:
        if pat.search(text):
            return label
    # Fall-through: the marker is in the body but not in a high-
    # value sink. Return a generic label so the caller can still
    # surface the reflection while not yet validating.
    return "body (no exploit context)"


class CachePoisonXForwardedHostProbe(Probe):
    name = "config_cache_poison_xforwarded_host"
    summary = ("Detects cache-poisoning surface where an unkeyed "
               "X-Forwarded-Host header is reflected into a cacheable "
               "response.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to probe. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        marker = f"dast-poison-{secrets.token_hex(6)}.example"
        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            for hdr in POISON_HEADERS:
                hval = (f"host={marker}" if hdr == "Forwarded"
                        else marker)
                r = client.request("GET", url, headers={hdr: hval})
                row: dict = {"path": p, "header": hdr,
                             "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    ctx = _reflection_context(r.text or "", marker)
                    if ctx:
                        cacheable, why = _is_cacheable(r.headers or {})
                        row.update({"reflected": True,
                                    "context": ctx,
                                    "cacheable": cacheable,
                                    "cache_reason": why})
                        if cacheable and "no exploit context" not in ctx:
                            confirmed = row
                            attempts.append(row)
                            break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "marker": marker,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: cache-poisoning surface at "
                    f"{origin}{confirmed['path']}. The "
                    f"`{confirmed['header']}: {marker}` header was "
                    f"reflected into the response's "
                    f"{confirmed['context']} AND the response is "
                    f"cacheable ({confirmed['cache_reason']}). An "
                    "attacker can poison the CDN entry so every later "
                    "visitor follows their marker URL."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Strip `X-Forwarded-Host` (and friends) at the edge "
                    "before they reach the origin, OR include them in "
                    "the cache key.\n"
                    "  - Cloudflare / Akamai / CloudFront: configure "
                    "the cache key to include `X-Forwarded-Host`, "
                    "`X-Forwarded-Scheme`, `X-Original-Host`, "
                    "`X-Host`, `Forwarded`. (Or strip them before "
                    "origin; either prevents the poison.)\n"
                    "  - nginx in front of the origin: add "
                    "`proxy_set_header X-Forwarded-Host '';` (clobber "
                    "the inbound value).\n"
                    "  - Build canonical / og:url / redirect URLs from "
                    "a static `PUBLIC_BASE_URL` env var, never from "
                    "request headers. (Same fix as the host-header "
                    "password-reset probe -- they share a root cause.)\n"
                    "Bust the cache after the fix to evict any poisoned "
                    "entries."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} path/header "
                     f"combinations on {origin}; no marker reflection "
                     "in a cacheable response in an exploit context."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CachePoisonXForwardedHostProbe().main()
