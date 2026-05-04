#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Adobe Experience Manager: Querybuilder JSON endpoint exposed.

Adobe documents the AEM `/bin/querybuilder.json` servlet as a
content-search API for authenticated authors. Reachable to
anonymous on a publish (`dispatcher`-fronted) instance, it
becomes a complete content-tree exfil: the attacker iterates
`?path=/&p.limit=N&p.hits=full` and walks every JCR node the
publish instance has, including unpublished drafts, internal
metadata (`cq:lastModifiedBy`, `cq:lastReplicated`), and
sometimes properties that authors typed into private content
fields.

Adobe's hardening guide
(https://experienceleague.adobe.com/docs/experience-manager-65/
administering/security/security-checklist.html) explicitly tells
ops to block /bin/querybuilder on publish dispatchers. Many
deployments don't.

Detection signal: GET the canonical query and inspect the
response body for the AEM-specific `{"success":true,"results":...,
"hits":[{"jcr:path":"/..."}]}` shape. The `jcr:path` field is
JCR-specific; nothing else returns it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Each (path, query-args) pair to probe.
TARGETS = (
    ("/bin/querybuilder.json",
     {"path": "/", "p.limit": "10", "p.hits": "full"}),
    ("/bin/querybuilder.json",
     {"type": "cq:Page", "p.limit": "10"}),
    ("/bin/querybuilder.json",
     {"path": "/etc", "p.limit": "10"}),
    ("/bin/querybuilder.json",
     {"path": "/var", "p.limit": "10"}),
    ("/bin/querybuilder.feed",
     {"path": "/", "p.limit": "10"}),
)


class AemQuerybuilderFullDumpProbe(Probe):
    name = "aem_querybuilder_full_dump"
    summary = ("Detects exposed AEM querybuilder endpoint -- "
               "anonymous JCR content-tree exfiltration.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, params in TARGETS:
            url = urljoin(origin, path) + "?" + urlencode(params)
            r = client.request("GET", url)
            row: dict = {"path": path, "params": params,
                         "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    doc = None
                if (isinstance(doc, dict)
                        and doc.get("success") is True
                        and isinstance(doc.get("hits"), list)
                        and any(isinstance(h, dict)
                                  and "jcr:path" in h
                                  for h in doc.get("hits") or [])):
                    sample_paths = [h.get("jcr:path")
                                     for h in doc["hits"][:5]
                                     if isinstance(h, dict)]
                    row.update({
                        "results": doc.get("results"),
                        "total": doc.get("total"),
                        "hits_count": len(doc["hits"]),
                        "sample_jcr_paths": sample_paths,
                    })
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: AEM querybuilder exposed at "
                    f"{origin}{confirmed['path']}. Response carries "
                    f"{confirmed['hits_count']} hits including "
                    f"`jcr:path` values: "
                    f"{confirmed['sample_jcr_paths'][:3]}. The "
                    "complete JCR content tree -- including "
                    "unpublished drafts, internal metadata, and "
                    "private author fields -- is anonymously "
                    "enumerable."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Block /bin/querybuilder on the publish "
                    "dispatcher. Adobe's hardening checklist "
                    "documents this as a default-deny rule.\n"
                    "  - In dispatcher.any: add a "
                    "  `/0001 { /type \"deny\" /url \"/bin/.*\" }` "
                    "  filter rule.\n"
                    "  - Or, in nginx-fronted setups, "
                    "  `location ~ ^/bin/ { return 404; }`.\n"
                    "After the fix, audit access logs for "
                    "/bin/querybuilder requests during the exposure "
                    "window -- scrapers commonly hit this endpoint."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} querybuilder "
                     f"queries on {origin}; no AEM-shape JSON "
                     "response returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemQuerybuilderFullDumpProbe().main()
