#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: PDF accepted with an `/OpenAction /URI` external-action
trigger.

PDF supports document-level actions (`/OpenAction`) that fire when the
file is opened. `/URI` actions cause the viewer to dereference an
external URL — turning a stored PDF into both a phish-bait artifact
(a recipient who opens the PDF gets bounced through the URL) and an
SSRF surface when the server runs the PDF through a renderer
(thumbnail, full-text indexer, e-signature pipeline).

We build a minimal, well-formed PDF with an `/OpenAction` pointing at
a same-origin canary URL — `<origin>/round12-pdf-canary`. The path
intentionally won't exist; we never test whether the server actually
fetched it (no out-of-band oracle is in scope). What we DO confirm,
high-fidelity, is whether the server:
  (a) accepted the upload (2xx),
  (b) serves the file back at a same-origin URL with `Content-Type:
      application/pdf`, AND
  (c) preserved the action structure — the literal byte sequences
      `/OpenAction` AND `/URI` survive in the served body.

All three together are unambiguous: the storage path is hostile-PDF
friendly, and there's no sanitisation gate stripping document-level
actions on ingest.

Detection signal:
  Upload accepted + same-origin fetch returns application/pdf + the
  served body still contains the `/OpenAction` and `/URI` markers.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

UPLOAD_PATHS = (
    "/file-upload",
    "/upload",
    "/api/upload",
    "/api/file/upload",
    "/api/files",
    "/files/upload",
    "/uploads",
    "/api/documents",
)

FETCH_PREFIXES = (
    "/uploads/",
    "/files/",
    "/static/uploads/",
    "/public/uploads/",
    "/upload/",
    "/documents/",
)

PATH_RE = re.compile(
    r'(?:"(?:path|url|location|file|filename)"\s*:\s*"([^"]+)"|'
    r'<a [^>]*href="([^"]+)")', re.I)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _build_pdf(origin: str) -> bytes:
    """Build a minimal valid PDF with an /OpenAction /URI trigger.

    Hand-rolled to keep the file under 1 KB and avoid pulling in a
    dependency. The xref offsets are computed at the end. The PDF is
    syntactically valid and renders blank in any compliant viewer; the
    only "active" content is the /OpenAction → /URI dictionary."""
    canary = origin.rstrip("/") + "/round12-pdf-canary"
    # Build object bodies first; we'll assemble with offsets after.
    objs: list[bytes] = []
    # 1: catalog with OpenAction
    objs.append(
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R "
        b"/OpenAction << /S /URI /URI (" + canary.encode() + b") >> "
        b">>\nendobj\n")
    # 2: pages tree
    objs.append(
        b"2 0 obj\n"
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n"
        b"endobj\n")
    # 3: single empty page
    objs.append(
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n")

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    body = bytearray(header)
    offsets: list[int] = []
    for o in objs:
        offsets.append(len(body))
        body.extend(o)
    xref_off = len(body)
    body.extend(b"xref\n0 4\n")
    body.extend(b"0000000000 65535 f \n")
    for off in offsets:
        body.extend(f"{off:010d} 00000 n \n".encode())
    body.extend(b"trailer\n")
    body.extend(b"<< /Size 4 /Root 1 0 R >>\n")
    body.extend(b"startxref\n")
    body.extend(f"{xref_off}\n".encode())
    body.extend(b"%%EOF\n")
    return bytes(body)


def _build_multipart(filename: str, content: bytes,
                     field: str = "file") -> tuple[str, bytes]:
    boundary = "----dast-pdf-" + secrets.token_hex(8)
    crlf = b"\r\n"
    parts = []
    parts.append(("--" + boundary).encode())
    parts.append(
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"'.encode())
    parts.append(b"Content-Type: application/pdf")
    parts.append(b"")
    parts.append(content)
    parts.append(("--" + boundary + "--").encode())
    parts.append(b"")
    return boundary, crlf.join(parts)


class UploadPdfExternalActionProbe(Probe):
    name = "upload_pdf_external_action"
    summary = ("Detects upload handlers that accept PDFs with "
               "/OpenAction /URI triggers and serve them unmodified.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--upload-path", action="append", default=[],
            help="Additional upload endpoint to try (repeatable).")
        parser.add_argument(
            "--field", default="file",
            help="Multipart field name (default: file).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(UPLOAD_PATHS) + list(args.upload_path or [])

        pdf_payload = _build_pdf(origin)
        attempts: list[dict] = []
        confirmed: dict | None = None

        for p in paths:
            upload_url = urljoin(origin, p)
            stem = secrets.token_hex(4)
            test_name = f"r12-{stem}.pdf"
            boundary, body = _build_multipart(
                test_name, pdf_payload, field=args.field)
            r = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary}"),
            }, body=body)
            row: dict = {"path": p, "filename": test_name,
                         "upload_status": r.status, "upload_size": r.size}

            if r.status not in (200, 201, 202, 204):
                attempts.append(row)
                continue

            location_hdr = _hdr(r.headers, "Location")
            served_path = None
            if location_hdr:
                served_path = location_hdr
            else:
                m = PATH_RE.search(r.text or "")
                if m:
                    served_path = m.group(1) or m.group(2)

            guesses: list[str] = []
            if served_path:
                guesses.append(served_path)
            else:
                for prefix in FETCH_PREFIXES[:3]:
                    guesses.append(prefix + test_name)

            row["fetch_targets"] = guesses
            served_mime = ""
            served_body_bytes = b""
            for guess in guesses:
                fetch_url = (guess if guess.startswith(("http://", "https://"))
                             else urljoin(origin, guess))
                if urlparse(fetch_url).netloc and \
                        urlparse(fetch_url).netloc != parsed.netloc:
                    continue
                fr = client.request("GET", fetch_url)
                if fr.status == 200 and fr.body:
                    served_mime = _hdr(fr.headers, "Content-Type").lower()
                    served_body_bytes = fr.body
                    row["served_url"] = fetch_url
                    row["served_mime"] = served_mime
                    row["served_size"] = fr.size
                    break

            mime_ok = "application/pdf" in served_mime
            action_intact = (b"/OpenAction" in served_body_bytes
                             and b"/URI" in served_body_bytes)
            row["mime_is_pdf"] = mime_ok
            row["openaction_preserved"] = action_intact

            if mime_ok and action_intact:
                row["confirmed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: PDF with /OpenAction /URI uploaded "
                         f"to {origin}{confirmed['path']} and served back "
                         f"at {confirmed.get('served_url', '?')} as "
                         f"application/pdf — the document-level action "
                         "survived ingest. Server-side renderers may "
                         "dereference the action; recipients opening the "
                         "stored PDF will be redirected."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Sanitise PDFs on ingest. Run uploads through "
                    "qpdf (`qpdf --linearize --remove-restrictions`) or "
                    "Ghostscript with a profile that strips "
                    "/OpenAction, /AA, /JS, /JavaScript, /Launch, "
                    "/EmbeddedFile, and /URI dictionaries.\n"
                    "If server-side rendering is part of the pipeline, "
                    "execute it in a sandbox with no network egress so "
                    "an action that survives ingest cannot reach "
                    "internal services."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} PDF upload "
                     f"endpoints on {origin}; none preserved both the "
                     "PDF MIME and the /OpenAction structure on serve-back."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadPdfExternalActionProbe().main()
