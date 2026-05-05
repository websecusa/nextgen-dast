#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: ImageMagick MVG / SVG with image-fetch directive lands in
a server-side renderer that respects external `url(...)` references
(the ImageTragick / GhostButt class of bug).

ImageMagick interprets MVG ("Magick Vector Graphics") and certain SVG
constructs as draw scripts. Some directives — historically `image
over` and `url()` — caused the renderer to fetch URLs server-side,
which became CVE-2016-3714 ("ImageTragick"). Even modern ImageMagick
builds with the policy.xml hardening still process MVG/SVG by default
unless the operator has explicitly disabled the modules.

We upload a 1-KB MVG file with a same-origin `url(...)` reference. The
canary URL is `<origin>/round12-mvg-canary` — same-origin only. There
is NO out-of-band callback; the test is structural plus timing.

Detection criteria — BOTH must be true for validated=True:
  (a) Upload accepted with a 2xx (proves the renderer didn't reject
      the MVG syntax outright; many libraries refuse non-image
      uploads),
  (b) Round-trip latency on the upload exceeds a low threshold (>2 s)
      consistent with a server-side render attempting to dereference
      the embedded URL. A plain copy-to-disk on a small file finishes
      in <500 ms; a renderer that tries to fetch a same-origin path
      that doesn't exist will pause for the connection / 404 cycle.

This is structural + behavioural — neither signal alone is enough.
Latency without acceptance could be a slow validator; acceptance
without latency could be a stub that never invoked the renderer.

Detection signal:
  Upload accepted (2xx) AND server response time exceeds 2000 ms on a
  ~1 KB MVG file (well above any size-proportional cost).
"""
from __future__ import annotations

import secrets
import sys
import time
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

# MVG draw script that exercises the historical ImageMagick fetch
# surface. The `image over` directive is the canonical ImageTragick
# trigger; we point it at a same-origin path that won't exist so the
# server fetch (if it happens) hits a 404 and returns harmlessly.
MVG_TEMPLATE = (
    "push graphic-context\n"
    "viewbox 0 0 64 64\n"
    "fill 'white'\n"
    "rectangle 0,0 64,64\n"
    "image over 0,0 64,64 'CANARY_URL'\n"
    "pop graphic-context\n"
)

# Latency floor for "server attempted a fetch" — a same-origin
# round-trip on the scanner network is sub-second; 2 s catches the
# render-pipeline pause without flagging on slow networks.
LATENCY_THRESHOLD_MS = 2000

# Sanity floor: the upload itself shouldn't take >30 s; longer means
# something else is wrong (timeout, network) and we should refute
# rather than mis-attribute.
LATENCY_CEILING_MS = 30000


def _build_multipart(filename: str, content: bytes,
                     field: str = "file",
                     content_type: str = "image/svg+xml"
                     ) -> tuple[str, bytes]:
    boundary = "----dast-mvg-" + secrets.token_hex(8)
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


class UploadImageMagickMvgCanaryProbe(Probe):
    name = "upload_imagemagick_mvg_canary"
    summary = ("Detects upload pipelines that pass MVG / SVG to "
               "ImageMagick and dereference external image references.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--upload-path", action="append", default=[],
            help="Additional upload endpoint to try (repeatable).")
        parser.add_argument(
            "--field", default="file",
            help="Multipart field name (default: file).")
        parser.add_argument(
            "--latency-threshold-ms", type=int,
            default=LATENCY_THRESHOLD_MS,
            help=("Latency floor that flags a likely server-side "
                  "fetch (default 2000)."))

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(UPLOAD_PATHS) + list(args.upload_path or [])

        canary_url = origin.rstrip("/") + "/round12-mvg-canary"
        mvg_text = MVG_TEMPLATE.replace("CANARY_URL", canary_url)
        # Some pipelines accept .svg only; we wrap the MVG inside an
        # SVG `<image>` so the same-origin reference still flows
        # through. Try MVG first, SVG-wrap second.
        mvg_payload = mvg_text.encode()
        svg_wrap = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<svg xmlns="http://www.w3.org/2000/svg" '
            b'xmlns:xlink="http://www.w3.org/1999/xlink" '
            b'width="64" height="64">\n'
            b'  <image xlink:href="' + canary_url.encode() + b'" '
            b'width="64" height="64"/>\n'
            b'</svg>\n')

        attempts: list[dict] = []
        confirmed: dict | None = None
        latency_ceiling = LATENCY_CEILING_MS
        threshold = max(1000, int(args.latency_threshold_ms))

        # Try each (filename, content, content-type) variant against
        # the first endpoint that 2xx-accepts; bail early on success.
        variants = (
            (f"r12-{secrets.token_hex(4)}.mvg",
             mvg_payload, "image/svg+xml"),
            (f"r12-{secrets.token_hex(4)}.svg",
             svg_wrap, "image/svg+xml"),
        )

        for fname, body_bytes, mime in variants:
            for p in paths:
                upload_url = urljoin(origin, p)
                boundary, body = _build_multipart(
                    fname, body_bytes, field=args.field,
                    content_type=mime)
                t0 = time.monotonic()
                r = client.request("POST", upload_url, headers={
                    "Content-Type": (
                        f"multipart/form-data; boundary={boundary}"),
                }, body=body)
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                row: dict = {"path": p, "filename": fname,
                             "upload_status": r.status,
                             "elapsed_ms": elapsed_ms,
                             "threshold_ms": threshold}

                accepted = r.status in (200, 201, 202, 204)
                row["accepted"] = accepted
                # Both signals required: structural acceptance plus
                # render-shaped latency.
                if accepted and threshold <= elapsed_ms < latency_ceiling:
                    row["confirmed"] = True
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "canary_url": canary_url,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.85,
                summary=(f"Confirmed: MVG / SVG with same-origin image "
                         f"reference uploaded to "
                         f"{origin}{confirmed['path']} returned 2xx and "
                         f"took {confirmed['elapsed_ms']} ms — "
                         "consistent with a server-side renderer "
                         "dereferencing the embedded URL "
                         "(ImageMagick / Ghostscript / similar)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Disable URL-fetching in the image processor:\n"
                    "  - ImageMagick: ship a `policy.xml` that disables "
                    "the `URL`, `HTTPS`, `HTTP`, `FTP`, `MVG`, `MSL`, "
                    "`TEXT`, `LABEL`, and `EPHEMERAL` coders. The "
                    "ImageTragick advisory has the canonical policy.\n"
                    "  - Ghostscript: run with `-dSAFER`. (Default in "
                    "9.50+, but verify.)\n"
                    "  - Better still, validate the upload as a raster "
                    "image (PNG/JPEG/WEBP) by header magic and refuse "
                    "anything else; the SVG/MVG attack surface goes "
                    "away entirely.\n"
                    "Defence in depth: run rendering in a sandbox with "
                    "no network egress."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} MVG/SVG upload "
                     f"endpoints on {origin}; no upload combined "
                     "acceptance with render-shaped latency."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadImageMagickMvgCanaryProbe().main()
