#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Microsoft Silverlight client-access policy permits wildcard origins.

`/clientaccesspolicy.xml` is the Silverlight equivalent of Flash's
`crossdomain.xml`. Silverlight (and a handful of WCF-style clients
that still respect the file) consult it to decide whether a cross-
origin caller may read the host's resources. The wildcard form looks
like:

    <allow-from>
      <domain uri="*"/>
    </allow-from>

Any origin's Silverlight content -- or any modern client that still
honors this policy -- can then read this host's authenticated
responses. Silverlight is end-of-life, but the file's mere presence
indicates an unaudited cross-origin posture.

To stay high-fidelity:
  - Status MUST be 200 (404 / 403 is the right posture; never flag).
  - Body MUST contain a wildcard `<domain uri="*"`.
  - Body MUST look XML-ish (XML content-type OR begins with `<?xml`
    or `<access-policy`). HTML soft-404 pages that happen to embed
    the literal `*` somewhere are rejected.

Detection signal:
  GET `/clientaccesspolicy.xml` returns 200 with an XML body that
  contains `<domain uri="*"`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

POLICY_PATH = "/clientaccesspolicy.xml"
WILDCARD_MARKER = '<domain uri="*"'
XML_MARKERS = ("<?xml", "<access-policy")


def _content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_like_xml_policy(body_text: str, ct: str) -> bool:
    if "xml" in ct:
        return True
    head = body_text.lstrip()[:80].lower()
    return any(head.startswith(m) for m in XML_MARKERS)


class ClientJsClientAccessPolicyWildcardProbe(Probe):
    name = "clientjs_clientaccesspolicy_wildcard"
    summary = ("Detects /clientaccesspolicy.xml that grants Silverlight "
               "/ legacy cross-origin access to any domain via "
               "<domain uri=\"*\"/>.")
    safety_class = "read-only"

    def add_args(self, parser):
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
                    "Silverlight client-access policy. Any origin's "
                    "Silverlight / WCF client may read this host's "
                    "authenticated responses."),
                evidence={**evidence, "marker": WILDCARD_MARKER},
                severity_uplift="medium",
                remediation=(
                    "Remove `/clientaccesspolicy.xml` -- Silverlight "
                    "reached end-of-support in 2021 and the file is "
                    "rarely required by anything still in production. "
                    "If a legacy WCF / Silverlight client still depends "
                    "on it, replace the wildcard with an explicit "
                    "allowlist:\n"
                    "  <?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    "  <access-policy>\n"
                    "    <cross-domain-access>\n"
                    "      <policy>\n"
                    "        <allow-from http-request-headers=\"*\">\n"
                    "          <domain uri=\"https://app.your-tenant.example\"/>\n"
                    "        </allow-from>\n"
                    "        <grant-to>\n"
                    "          <resource path=\"/api\" include-subpaths=\"true\"/>\n"
                    "        </grant-to>\n"
                    "      </policy>\n"
                    "    </cross-domain-access>\n"
                    "  </access-policy>"),
            )
        return Verdict(
            validated=False, confidence=0.90,
            summary=(f"Refuted: {url} returned {r.status}; no wildcard "
                     "Silverlight client-access policy is served."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ClientJsClientAccessPolicyWildcardProbe().main()
