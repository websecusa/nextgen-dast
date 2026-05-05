#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: extension-based filtering bypassed via double extensions,
case folding, null-byte truncation, or .htaccess overrides.

Servers that decide a file's MIME or execution behavior from string
matching against the extension are routinely defeated by the classic
bypass set:
  - `harmless.php.jpg`  (allowlist matches the trailing `.jpg`,
                         Apache's mod_mime executes on the inner `.php`)
  - `harmless.jpg.php`  (allowlist sees `.jpg`, last extension wins)
  - `harmless.PHP`      (case-folded match misses)
  - `harmless.php%00.jpg` (null-truncation in older PHP / IIS)
  - `.htaccess`         (Apache rewrite override on directory the
                         upload lands in)

We upload BENIGN content — the body is `<?php /* round12-canary */ ?>`,
which executes nothing. The detection signal is structural: even if the
server interprets the file, it does nothing. We declare validated=True
only when ALL of:
  (a) the upload returned a 2xx status with a fetchable URL or path
      that maps onto the file we sent,
  (b) we can fetch the file back at that URL,
  (c) the response Content-Type indicates the dangerous extension was
      honored (e.g. `application/x-httpd-php`, `application/x-php`,
      `text/x-php`) — this is the unambiguous proof the server treats
      it as PHP-source rather than as the inert bytes we wanted.

Two corroborating signals (accepted upload + dangerous served Content-
Type) make this high-fidelity. Returning `text/plain` or
`application/octet-stream` is not enough on its own.

Detection signal:
  Upload accepted + file fetched back same-origin + served with a
  PHP-script Content-Type header.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common upload endpoints. The probe sweeps these in order; first
# accepting endpoint wins.
UPLOAD_PATHS = (
    "/file-upload",
    "/upload",
    "/api/upload",
    "/api/file/upload",
    "/api/files",
    "/files/upload",
    "/uploads",
)

# The benign payload. PHP open-tag with a comment-only body — even if
# the server executes the file, this returns an empty page and changes
# no state. The token `round12-canary` lets us recognise our content if
# the server echoes it back (some servers store-and-list).
PAYLOAD = b"<?php /* round12-canary */ ?>"

# Extension-bypass filenames. Each entry is (filename, why-it-matters).
BYPASS_NAMES = (
    ("harmless.php.jpg",     "double-extension; mod_mime executes inner .php"),
    ("harmless.jpg.php",     "trailing .php after benign extension"),
    ("harmless.PHP",         "case-folded extension match"),
    ("harmless.php%00.jpg",  "null-byte truncation"),
    (".htaccess",            "directory rewrite override"),
)

# Content-Types that prove the server treats the file as PHP source.
PHP_MIMES = (
    "application/x-httpd-php",
    "application/x-php",
    "text/x-php",
    "application/php",
    "text/php",
)

# Where uploaded files are commonly served from. We fetch by appending
# the filename to each of these candidate roots if the upload response
# didn't already echo a Location/path.
FETCH_PREFIXES = (
    "/uploads/",
    "/files/",
    "/static/uploads/",
    "/public/uploads/",
    "/upload/",
)

# Pull a path / URL back out of the upload response. Many handlers
# include the public path in the response JSON or a Location header.
PATH_RE = re.compile(
    r'(?:"(?:path|url|location|file|filename)"\s*:\s*"([^"]+)"|'
    r'<a [^>]*href="([^"]+)")', re.I)


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _build_multipart(filename: str, content: bytes,
                     field: str = "file",
                     content_type: str = "image/jpeg") -> tuple[str, bytes]:
    """Hand-roll a minimal multipart/form-data body. Returns
    (boundary, body). We deliberately do not pull in `requests`."""
    boundary = "----dast-extbypass-" + secrets.token_hex(8)
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


class UploadExtensionBypassDoubleProbe(Probe):
    name = "upload_extension_bypass_double"
    summary = ("Detects upload handlers that accept extension-bypass "
               "filenames and serve them with a PHP-source MIME type.")
    safety_class = "probe"

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

        # Iterate filenames first so the worst bypass surface (.php.jpg)
        # is tried at every endpoint before falling back. Stop the moment
        # we get unambiguous proof on any endpoint+name.
        for fname, reason in BYPASS_NAMES:
            for p in paths:
                upload_url = urljoin(origin, p)
                # Use a per-attempt unique stem so server-side dedup
                # doesn't masquerade as success on the second run.
                stem = secrets.token_hex(4)
                # The bypass filename is what the server sees in the
                # multipart Content-Disposition header — keep the bypass
                # token but prefix with the unique stem to find it later.
                test_name = fname.replace("harmless", f"r12-{stem}")
                if fname == ".htaccess":
                    # .htaccess is intentionally identical — the bypass
                    # is the literal filename, not a stem. We can still
                    # tell our attempts apart via the upload response.
                    test_name = ".htaccess"
                boundary, body = _build_multipart(
                    test_name, PAYLOAD, field=args.field)
                r = client.request("POST", upload_url, headers={
                    "Content-Type": (
                        f"multipart/form-data; boundary={boundary}"),
                }, body=body)
                row: dict = {"path": p, "filename": test_name,
                             "bypass_reason": reason,
                             "upload_status": r.status, "upload_size": r.size}

                if r.status not in (200, 201, 202, 204):
                    attempts.append(row)
                    continue

                # Try to recover where the server stashed the file.
                location_hdr = _hdr(r.headers, "Location")
                served_path = None
                if location_hdr:
                    served_path = location_hdr
                else:
                    m = PATH_RE.search(r.text or "")
                    if m:
                        served_path = m.group(1) or m.group(2)

                # If neither Location nor a JSON path came back, fall
                # back to guessing common upload roots. Cap to the first
                # 3 prefixes so a stubborn server doesn't burn our
                # request budget.
                guesses: list[str] = []
                if served_path:
                    guesses.append(served_path)
                else:
                    for prefix in FETCH_PREFIXES[:3]:
                        guesses.append(prefix + test_name)

                row["fetch_targets"] = guesses
                served_mime = ""
                fetched_url = None
                for guess in guesses:
                    fetch_url = (guess if guess.startswith(("http://", "https://"))
                                 else urljoin(origin, guess))
                    # Same-origin gate — refuse to chase a Location that
                    # points elsewhere (defence in depth; SafeClient will
                    # refuse out-of-scope requests too).
                    if urlparse(fetch_url).netloc and \
                            urlparse(fetch_url).netloc != parsed.netloc:
                        continue
                    fr = client.request("GET", fetch_url)
                    if fr.status == 200 and fr.body:
                        served_mime = _hdr(fr.headers, "Content-Type").lower()
                        fetched_url = fetch_url
                        row["served_url"] = fetch_url
                        row["served_mime"] = served_mime
                        row["served_status"] = fr.status
                        break

                # Final confirmation: file fetched back AND served with
                # a PHP-source MIME (the dangerous outcome).
                if fetched_url and any(m in served_mime for m in PHP_MIMES):
                    row["confirmed"] = True
                    confirmed = row
                    attempts.append(row)
                    break
                attempts.append(row)
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: extension-bypass upload at "
                         f"{origin}{confirmed['path']} accepted "
                         f"{confirmed['filename']} and the server now "
                         f"serves it with Content-Type "
                         f"'{confirmed['served_mime']}', proving the "
                         f"PHP-source extension is honored."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Drive upload validation off the file's actual "
                    "content, not its name:\n"
                    "  - Re-encode images through a server-side library "
                    "(Pillow / ImageMagick safely-configured) and store "
                    "the re-encoded output. Reject anything that does "
                    "not parse as the declared media type.\n"
                    "  - Force the served Content-Type explicitly when "
                    "the file is fetched back (do NOT let the web server "
                    "infer it from filename); pin to a safe type per "
                    "upload category.\n"
                    "  - Configure the upload directory with `php_flag "
                    "engine off` (Apache) or equivalent to prevent any "
                    "interpreter from running files there.\n"
                    "  - Refuse `.htaccess`, `web.config`, and dotfiles "
                    "by name AND by parsing rejection."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} extension-bypass "
                     f"uploads on {origin}; none were both accepted and "
                     "served with a PHP-source Content-Type."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadExtensionBypassDoubleProbe().main()
