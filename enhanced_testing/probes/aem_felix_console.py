#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
AEM: Apache Felix OSGi console reachable on the public origin.

`/system/console` is the Apache Felix Web Console -- the OSGi
runtime management UI for AEM (and any other Sling-based stack).
Reachable to anonymous = OSGi bundle / config / service
enumeration; reachable to admin = arbitrary OSGi service config
write, which is RCE-equivalent (flip an authentication-handler
bundle's config to pass-through, or load a bundle from a file
URL).

Detection signal: GET candidate paths; validate per-path on the
Felix-specific HTML title or the bundles.json structural
signature (`{"bundles":[{"id":..., "symbolicName":"org.apache..."}]}`).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, kind) pairs. kind=html means look for the Felix HTML
# title; kind=json means look for the bundles JSON structure.
TARGETS = (
    ("/system/console",                          "html"),
    ("/system/console/bundles",                  "html"),
    ("/system/console/configMgr",                "html"),
    ("/system/console/status-Configurations",    "html"),
    ("/system/console/bundles.json",             "json"),
    ("/system/console/services.json",            "json"),
    ("/system/console/components.json",          "json"),
)

_HTML_TITLE = re.compile(r"<title>\s*Apache Felix Web Console", re.I)


class AemFelixConsoleProbe(Probe):
    name = "aem_felix_console"
    summary = ("Detects Apache Felix Web Console (AEM / Sling OSGi "
               "management UI) reachable on the public origin -- "
               "RCE-equivalent on auth.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional Felix-console path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for p in (args.path or []):
            kind = "json" if p.endswith(".json") else "html"
            targets.append((p, kind))

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, kind in targets:
            r = client.request("GET", urljoin(origin, path),
                                follow_redirects=True)
            row: dict = {"path": path, "kind": kind,
                         "status": r.status, "size": r.size,
                         "final_url": r.final_url}
            if r.status in (200, 401) and r.body:
                text = r.text or ""
                if kind == "html":
                    if _HTML_TITLE.search(text):
                        row["matched"] = "Apache Felix Web Console"
                        confirmed = row
                else:
                    try:
                        doc = json.loads(text)
                    except (ValueError, json.JSONDecodeError):
                        doc = None
                    if (isinstance(doc, dict)
                            and isinstance(doc.get(
                                path.rsplit("/", 1)[-1]
                                .replace(".json", "")), list)):
                        # The path's leaf-name (bundles / services /
                        # components) is the JSON top-level key.
                        list_key = path.rsplit("/", 1)[-1].replace(
                            ".json", "")
                        items = doc.get(list_key)
                        if (isinstance(items, list)
                                and items
                                and isinstance(items[0], dict)
                                and any(k in items[0] for k in
                                         ("symbolicName",
                                          "name", "id"))):
                            row.update({
                                "matched": f"{list_key}.json structure",
                                "items_count": len(items),
                                "sample_names":
                                    [i.get("symbolicName")
                                     or i.get("name") or i.get("id")
                                     for i in items[:5]],
                            })
                            confirmed = row
                if confirmed:
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: Apache Felix console reachable at "
                    f"{origin}{confirmed['path']}. The OSGi runtime "
                    "management surface is on the public origin -- "
                    "RCE on default credentials (admin/admin / "
                    "anonymous/anonymous on older versions)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Per Adobe's AEM hardening checklist, "
                    "/system/console must be blocked on the publish "
                    "dispatcher and behind a VPN on the author tier.\n"
                    "  - dispatcher.any: deny `/system/.*` for the "
                    "  publish farm.\n"
                    "  - On the author tier: harden the dispatcher "
                    "  to refuse external traffic; admins reach the "
                    "  console via VPN.\n"
                    "  - Rotate the admin / OSGi service-user "
                    "  passwords; verify the existing "
                    "  `auth_default_admin_credentials` probe."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} Felix-console "
                     f"paths on {origin}; none returned the Felix "
                     "signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemFelixConsoleProbe().main()
