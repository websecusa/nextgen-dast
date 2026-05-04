#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
AEM / Sling: default selectors return JCR content tree as JSON.

Sling's default servlet honours selectors -- `/.json`,
`/.tidy.json`, `/.infinity.json`, `/.<depth>.json` -- that
serialise the JCR node at the path. Reachable on a publish
dispatcher = anonymous content-tree exfil. The signature is
unique: any response carrying a top-level or nested
`jcr:primaryType` field is JCR-specific.

  /.infinity.json    -> dump everything under /
  /.tidy.json        -> human-readable JSON dump
  /.4.json           -> 4 levels deep
  /etc.tidy.json     -> /etc subtree (often unhardened)
  /libs.json         -> /libs subtree (lots of internal AEM detail)

Detection signal: GET candidate selector paths; validate when
response body is JSON containing `jcr:primaryType`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/.json",
    "/.tidy.json",
    "/.4.json",
    "/.infinity.json",
    "/content.json",
    "/content.tidy.json",
    "/content.4.json",
    "/etc.json",
    "/etc.tidy.json",
    "/var.json",
    "/libs.json",
    "/.docview.json",
)

JCR_RE = re.compile(r'"jcr:primaryType"\s*:\s*"[^"]+"')


class AemSlingDotJsonSelectorsProbe(Probe):
    name = "aem_sling_dotjson_selectors"
    summary = ("Detects Sling default selectors (.json / .tidy.json "
               "/ .infinity.json) returning JCR content on a "
               "publish dispatcher -- anonymous content-tree exfil.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional selector path to test.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for p in paths:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                if JCR_RE.search(text):
                    # Pull a sample of the JCR types found, capped
                    # so we don't blow up the verdict body.
                    types = JCR_RE.findall(text)[:5]
                    row.update({"jcr_primary_types_seen": types,
                                 "snippet": text[:200]})
                    confirmed.append(row)
                    attempts.append(row)
                    if len(confirmed) >= 3:
                        break
                    continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: Sling default selector exposed at "
                    f"{origin}{top['path']}. Response carries JCR-"
                    "specific `jcr:primaryType` fields -- the AEM "
                    "publish dispatcher is letting JSON selectors "
                    "through. "
                    f"{len(confirmed)} selector path(s) leak; "
                    "/.infinity.json (if reachable) returns the "
                    "entire JCR tree under that path."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Block the default selectors at the publish "
                    "dispatcher. Adobe's hardening rules ship a "
                    "default-deny on these:\n"
                    "  - dispatcher.any /filter: deny "
                    "  `\\.(infinity|tidy|sysview|docview|query|"
                    "  feed|json|xml|jsonp)`.\n"
                    "  - Reset cache to evict already-served JSON.\n"
                    "Audit access logs for `.infinity.json` and "
                    "`.tidy.json` requests during the exposure window "
                    "-- scrapers commonly use these as content-"
                    "exfiltration shortcuts."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} Sling selector "
                     f"paths on {origin}; no `jcr:primaryType` "
                     "field returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemSlingDotJsonSelectorsProbe().main()
