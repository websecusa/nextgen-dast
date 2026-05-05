#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
File upload: decompression-bomb defence missing — server accepts a
small archive that expands to a much larger payload.

The classic "42.zip" is destructive; we don't ship that. Instead we
build a TAME bomb: a ~10 KB ZIP that decompresses to ~4 MB of zeros.
That ratio (~400×) is high enough to confirm the server has no
size-after-decompression check, but low enough that a server that
DOES start unpacking won't OOM or fill its disk before the test
finishes. We cap both the compressed and uncompressed sizes
explicitly.

Two corroborating signals make this high-fidelity:
  (a) the server returned a 2xx — it didn't reject on either the
      compressed size (10 KB is small) or on a streaming
      decompression-ratio check, AND
  (b) the upload took materially longer than a tiny benign upload to
      the same endpoint — consistent with the server actually
      decompressing the bytes (zero-fill is fast, but not free).

Single-shot timing isn't enough — we always send a small benign ZIP
to the same endpoint first, then the bomb, and require the bomb to be
at least 1.5× slower in absolute terms with a minimum delta of 500 ms.

Detection signal:
  Bomb upload accepted (2xx) AND elapsed_ms_bomb >= elapsed_ms_baseline
  * 1.5 with delta >= 500 ms.
"""
from __future__ import annotations

import io
import secrets
import sys
import time
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

# Bomb sizing. 4 MB uncompressed, ~10 KB compressed (DEFLATE
# compresses zero-fill near optimally). Caps below keep the test
# bounded — if a misconfigured target balloons further, we've still
# defined an upper bound on the wire bytes.
UNCOMPRESSED_BYTES = 4 * 1024 * 1024     # 4 MB
COMPRESSED_BUDGET  = 100 * 1024          # 100 KB hard ceiling on wire
LATENCY_RATIO_MIN  = 1.5
LATENCY_DELTA_MIN_MS = 500


def _build_zip_bomb() -> bytes:
    """Build a tame ~4 MB-uncompressed ZIP. Single entry of zero-fill,
    DEFLATE-compressed to ~10 KB. NOT recursive (no nested archives,
    no ZIP-overlap tricks). Failure-mode: a server that accepts and
    decompresses spends a small amount of CPU and disk."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w",
                         compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as zf:
        zf.writestr("round12-bomb.bin", b"\x00" * UNCOMPRESSED_BYTES)
    out = buf.getvalue()
    # Sanity-bound the wire payload. If the platform's zlib produces
    # an unexpectedly-large output (highly unlikely for zero fill),
    # truncate the test to refuse rather than ship a bigger archive.
    if len(out) > COMPRESSED_BUDGET:
        raise RuntimeError(
            f"refusing to ship {len(out)}-byte test archive; "
            f"max allowed is {COMPRESSED_BUDGET}")
    return out


def _build_zip_baseline() -> bytes:
    """A small benign archive — a few hundred bytes of human-readable
    text. Used as the latency baseline against which we compare the
    bomb's processing time."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w",
                         compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("round12-baseline.txt",
                    b"round12 decompression-ratio baseline\n" * 5)
    return buf.getvalue()


def _build_multipart(filename: str, content: bytes,
                     field: str = "file") -> tuple[str, bytes]:
    boundary = "----dast-decomp-" + secrets.token_hex(8)
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


class UploadDecompressionRatioProbe(Probe):
    name = "upload_decompression_ratio"
    summary = ("Detects upload pipelines lacking a decompression-ratio "
               "limit — small archives expand to large payloads.")
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

        try:
            bomb = _build_zip_bomb()
        except RuntimeError as e:
            return Verdict(ok=False, error=str(e))
        baseline_zip = _build_zip_baseline()

        attempts: list[dict] = []
        confirmed: dict | None = None

        for p in paths:
            upload_url = urljoin(origin, p)

            # --- Baseline upload first (small, benign) ---
            base_name = f"r12-baseline-{secrets.token_hex(4)}.zip"
            b_boundary, b_body = _build_multipart(
                base_name, baseline_zip, field=args.field)
            t0 = time.monotonic()
            br = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={b_boundary}"),
            }, body=b_body)
            base_ms = int((time.monotonic() - t0) * 1000)

            if br.status not in (200, 201, 202, 204):
                # Endpoint doesn't accept ZIPs at all — move on.
                attempts.append({"path": p, "phase": "baseline",
                                 "status": br.status,
                                 "elapsed_ms": base_ms,
                                 "skipped_reason": "non-2xx baseline"})
                continue

            # --- Bomb upload ---
            bomb_name = f"r12-bomb-{secrets.token_hex(4)}.zip"
            x_boundary, x_body = _build_multipart(
                bomb_name, bomb, field=args.field)
            t1 = time.monotonic()
            xr = client.request("POST", upload_url, headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={x_boundary}"),
            }, body=x_body)
            bomb_ms = int((time.monotonic() - t1) * 1000)

            row: dict = {"path": p,
                         "baseline_status": br.status,
                         "baseline_elapsed_ms": base_ms,
                         "bomb_status": xr.status,
                         "bomb_elapsed_ms": bomb_ms,
                         "bomb_compressed_bytes": len(bomb),
                         "bomb_uncompressed_bytes": UNCOMPRESSED_BYTES}

            accepted = xr.status in (200, 201, 202, 204)
            row["bomb_accepted"] = accepted
            ratio = (bomb_ms / base_ms) if base_ms > 0 else 0.0
            delta = bomb_ms - base_ms
            row["latency_ratio"] = round(ratio, 2)
            row["latency_delta_ms"] = delta

            if accepted and ratio >= LATENCY_RATIO_MIN \
                    and delta >= LATENCY_DELTA_MIN_MS:
                row["confirmed"] = True
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts,
                    "ratio_threshold": LATENCY_RATIO_MIN,
                    "delta_threshold_ms": LATENCY_DELTA_MIN_MS}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.88,
                summary=(f"Confirmed: decompression-ratio limit missing "
                         f"on {origin}{confirmed['path']} — a "
                         f"{confirmed['bomb_compressed_bytes']}-byte ZIP "
                         f"that expands to "
                         f"{confirmed['bomb_uncompressed_bytes']} bytes "
                         f"was accepted and processed in "
                         f"{confirmed['bomb_elapsed_ms']} ms vs "
                         f"{confirmed['baseline_elapsed_ms']} ms for the "
                         f"baseline (ratio "
                         f"{confirmed['latency_ratio']}×)."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Reject archives whose decompression ratio exceeds "
                    "a sane bound:\n"
                    "  - Stream-decompress and abort when "
                    "uncompressed-bytes-out / compressed-bytes-in "
                    "exceeds 100× (typical heuristic).\n"
                    "  - Independently cap the total uncompressed size "
                    "(e.g. 50 MB) and the per-entry size before "
                    "writing to disk.\n"
                    "  - For libraries with built-in checks, use "
                    "Python's `zipfile.ZipFile.open` with a streaming "
                    "read and a counter; for Java, prefer "
                    "`ZipSecureFile`. Disable any feature that pre-"
                    "extracts to a tmp dir without size checks."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} ZIP upload "
                     f"endpoints on {origin}; no endpoint combined "
                     "acceptance with bomb-vs-baseline latency growth "
                     "above threshold."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UploadDecompressionRatioProbe().main()
