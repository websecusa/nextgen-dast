#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: SVG accepted with executable script content (stored XSS)
or with internal-href image references (server-side SSRF surface).

SVG is the worst-of-both-worlds upload format: the browser treats it
as an image element and as a document — `<script>` inside an SVG
served with `Content-Type: image/svg+xml` runs in the origin of the
serving page when fetched directly or embedded with `<object>`. SVG
also supports `<image xlink:href="...">` references that some
server-side renderers (thumbnailers, PDF converters) will fetch,
turning an upload into an SSRF primitive.

The probe uploads a benign-marked SVG with both surfaces:
  - `<script>round12()</script>` — a no-op call to a function name
    that doesn't exist anywhere; even if the script runs, the browser
    throws a ReferenceError, harming nothing. The PRESENCE of the tag
    in the served body is what we measure.
  - `<image xlink:href="<origin>/round12-svg-canary">` — same-origin
    only, against a path that won't exist. We do NOT validate the
    SSRF angle (no out-of-band oracle is in scope); we report it as a
    risk only when the XSS angle is independently confirmed.

Detection criteria — ALL must be true for validated=True:
  (a) the upload returned a 2xx status,
  (b) we can fetch the SVG back at a same-origin URL,
  (c) the served Content-Type is `image/svg+xml` (the mode where
      `<script>` runs in the origin), and
  (d) the served body still contains the literal `<script>` tag — i.e.
      the server did not sanitise it.

Detection signal:
  Upload accepted + same-origin fetch returns image/svg+xml + body
  preserves the <script> tag.
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
    "/avatar",
    "/api/avatar",
)

# Where uploaded files are commonly served from.
FETCH_PREFIXES = (
    "/uploads/",
    "/files/",
    "/static/uploads/",
    "/public/uploads/",
    "/upload/",
    "/avatars/",
)

# Pull a path back out of an upload response (Location header or JSON).
PATH_RE = re.compile(
    r'(?:"(?:path|url|location|file|filename)"\s*:\s*"([^"]+)"|'
    r'<a [^>]*href="([^"]+)")', re.I)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _build_svg(origin: str) -> bytes:
    """Build the test SVG. Two surfaces:
       - <script> tag with a benign call (round12() is undefined, so
         even an executing browser does nothing).
       - <image xlink:href="..."> pointing at a same-origin canary so
         a server-side renderer that follows external refs can be
         observed (we do NOT verify the fetch — flag is XSS-only).
    """
    canary = origin.rstrip("/") + "/round12-svg-canary"
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg" '
        b'xmlns:xlink="http://www.w3.org/1999/xlink" '
        b'width="64" height="64" viewBox="0 0 64 64">\n'
        b'  <rect x="0" y="0" width="64" height="64" fill="#fff"/>\n'
        b'  <script type="application/ecmascript">round12()</script>\n'
        b'  <image xlink:href="' + canary.encode() + b'" '
        b'width="1" height="1"/>\n'
        b'</svg>\n'
    )


def _build_multipart(filename: str, content: bytes,
                     field: str = "file",
                     content_type: str = "image/svg+xml"
                     ) -> tuple[str, bytes]:
    boundary = "----dast-svg-" + secrets.token_hex(8)
    crlf = b"\r\n"
    parts = []
    parts.append(("--" + boundary).encode())
    parts.append(
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"'.encode())
    parts.append(f"Content-Type: {content_type}".encode())
    parts.append(b"")
    parts.append(content)
    parts.append(("--" + boundary + "--").encode())
    parts.append(b"")
    return boundary, crlf.join(parts)


class UploadSvgXssOrSsrfProbe(Probe):
    name = "upload_svg_xss_or_ssrf"
    summary = ("Detects upload handlers that accept SVG containing "
               "<script> and serve it back as image/svg+xml unsanitised.")
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

        svg_payload = _build_svg(origin)
        attempts: list[dict] = []
        confirmed: dict | None = None

        for p in paths:
            upload_url = urljoin(origin, p)
            stem = secrets.token_hex(4)
            test_name = f"r12-{stem}.svg"
            boundary, body = _build_multipart(
                test_name, svg_payload, field=args.field)
            r = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary}"),
            }, body=body)
            row: dict = {"path": p, "filename": test_name,
                         "upload_status": r.status, "upload_size": r.size}

            if r.status not in (200, 201, 202, 204):
                attempts.append(row)
                continue

            # Find where it landed.
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
            served_body = ""
            for guess in guesses:
                fetch_url = (guess if guess.startswith(("http://", "https://"))
                             else urljoin(origin, guess))
                if urlparse(fetch_url).netloc and \
                        urlparse(fetch_url).netloc != parsed.netloc:
                    # Refuse to chase a redirect off-origin.
                    continue
                fr = client.request("GET", fetch_url)
                if fr.status == 200 and fr.body:
                    served_mime = _hdr(fr.headers, "Content-Type").lower()
                    served_body = fr.text or ""
                    row["served_url"] = fetch_url
                    row["served_mime"] = served_mime
                    row["served_size"] = fr.size
                    break

            # Two corroborating signals: SVG MIME + script tag intact.
            mime_ok = "image/svg+xml" in served_mime
            script_intact = "<script" in served_body.lower()
            row["mime_is_svg"] = mime_ok
            row["script_tag_preserved"] = script_intact

            if mime_ok and script_intact:
                row["confirmed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: SVG with <script> uploaded to "
                         f"{origin}{confirmed['path']} and served back "
                         f"at {confirmed.get('served_url', '?')} with "
                         f"Content-Type '{confirmed['served_mime']}' — "
                         "the script tag survived sanitisation, giving "
                         "stored XSS in the application's origin."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Sanitise SVG uploads through an SVG-aware allowlist "
                    "(DOMPurify configured for SVG, svg-sanitizer, or "
                    "ImageMagick re-encode to PNG when SVG isn't actually "
                    "needed by the feature). Strip `<script>`, "
                    "`<foreignObject>`, event-handler attributes "
                    "(`onload`, `onerror`, `onclick`...), and "
                    "`xlink:href` values that aren't data: URIs.\n"
                    "Defence in depth: serve user uploads from a "
                    "cookieless, sandboxed subdomain with `Content-"
                    "Disposition: attachment` and a strict CSP. The "
                    "upload origin should not be the application origin."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} SVG upload "
                     f"endpoints on {origin}; none returned an SVG with "
                     "an intact <script> tag."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadSvgXssOrSsrfProbe().main()
