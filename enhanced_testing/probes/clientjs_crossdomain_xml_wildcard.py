#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Adobe Flash cross-domain policy permits wildcard origins.

`/crossdomain.xml` is the legacy Flash / Adobe AIR policy file that
tells the Flash runtime which origins may load the host's resources
across origins. A wildcard policy:

    <allow-access-from domain="*"/>

means any origin's Flash content could read the host's authenticated
responses. Although Flash itself is end-of-life, several non-Flash
clients still respect this file (some Java applets, Silverlight via
its own mechanism handled by the sibling probe, and various
older-stack libraries). It also signals that the operator hasn't
audited their cross-origin posture in years.

To stay high-fidelity:
  - We require the response to be HTTP 200 (a 403 / 404 is the
    correct posture and must NOT be flagged).
  - We require a substring match for `<allow-access-from domain="*"`
    -- a strict literal that no scoped policy can match.
  - We require the response Content-Type to look XML-ish OR the body
    to start with `<?xml` / `<cross-domain-policy`. This rejects
    HTML "soft 200" not-found pages.

Detection signal:
  GET `/crossdomain.xml` returns 200 with XML body containing
  `<allow-access-from domain="*"`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

POLICY_PATH = "/crossdomain.xml"
WILDCARD_MARKER = '<allow-access-from domain="*"'
XML_MARKERS = ("<?xml", "<cross-domain-policy")


def _content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_like_xml_policy(body_text: str, ct: str) -> bool:
    """Reject HTML soft-404 / catch-all pages by demanding either an
    XML content-type OR the body actually begin with an XML / policy
    marker (after leading whitespace)."""
    if "xml" in ct:
        return True
    head = body_text.lstrip()[:80].lower()
    return any(head.startswith(m) for m in XML_MARKERS)


class ClientJsCrossDomainXmlWildcardProbe(Probe):
    name = "clientjs_crossdomain_xml_wildcard"
    summary = ("Detects /crossdomain.xml that grants Flash / legacy "
               "cross-origin access to any domain via "
               "domain=\"*\".")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args; --url is enough.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(origin, POLICY_PATH)

        r = client.request("GET", url, follow_redirects=False)
        ct = _content_type(r.headers or {})
        body = r.text or ""
        attempt = {"url": url, "status": r.status,
                   "content_type": ct,
                   "body_excerpt": body[:300]}
        evidence = {"origin": origin, "attempt": attempt}

        if r.status == 200 \
                and WILDCARD_MARKER in body \
                and _looks_like_xml_policy(body, ct):
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: {url} returns 200 with a wildcard "
                    "Flash cross-domain policy. Any origin's legacy "
                    "Flash / cross-domain client may read this host's "
                    "authenticated responses."),
                evidence={**evidence, "marker": WILDCARD_MARKER},
                severity_uplift="medium",
                remediation=(
                    "Either remove `/crossdomain.xml` entirely (Flash "
                    "is end-of-life, the file is rarely needed in "
                    "2026), or replace its contents with a strict "
                    "allowlist:\n"
                    "  <?xml version=\"1.0\"?>\n"
                    "  <!DOCTYPE cross-domain-policy SYSTEM "
                    "\"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\">\n"
                    "  <cross-domain-policy>\n"
                    "    <allow-access-from domain=\"*.your-tenant.example\" "
                    "secure=\"true\"/>\n"
                    "  </cross-domain-policy>\n"
                    "Pair with `<site-control "
                    "permitted-cross-domain-policies=\"master-only\"/>` so "
                    "stray policy files in subdirectories aren't honored."),
            )
        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: {url} returned {r.status}; no wildcard "
                     "Flash cross-domain policy is served."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsCrossDomainXmlWildcardProbe().main()
