#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
PHP: `phpinfo()` page reachable on the public origin.

A `<?php phpinfo(); ?>` script left at `/info.php`, `/test.php`,
or similar leaks every PHP config value (which extensions are
loaded, which paths are writable, which secrets sit in env vars),
the OS user / group, and a precise version fingerprint that maps
directly to CVE applicability. It's the textbook "I forgot to
delete the test page" finding.

High-fidelity signal: GET candidate paths; validate when the body
contains both the `<title>phpinfo()</title>` AND the
`<h1 class="p">PHP Version` markers (CSS class is part of the
generated HTML; combining the two prevents false-positives from
pages that simply mention phpinfo in copy).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/phpinfo.php", "/info.php", "/test.php", "/i.php",
    "/_phpinfo.php", "/phpinfo", "/php.php",
    "/admin/phpinfo.php", "/dev/phpinfo.php",
)

_TITLE_RE = re.compile(r"<title>\s*phpinfo\(\)\s*</title>", re.I)
_H1_RE    = re.compile(r'<h1[^>]*class="p"[^>]*>\s*PHP Version', re.I)


class PhpPhpinfoExposedProbe(Probe):
    name = "php_phpinfo_exposed"
    summary = ("Detects phpinfo() pages reachable on the public "
               "origin -- complete PHP config / env / version "
               "disclosure.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional phpinfo path. Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                if _TITLE_RE.search(text) and _H1_RE.search(text):
                    # Pull the version string for evidence.
                    m = re.search(r"<h1[^>]*class=\"p\"[^>]*>"
                                   r"\s*PHP Version\s+([0-9.]+)",
                                   text, re.I)
                    row.update({
                        "phpinfo": True,
                        "php_version": (m.group(1) if m else "unknown"),
                    })
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: phpinfo() page exposed at "
                    f"{origin}{confirmed['path']} (PHP "
                    f"{confirmed['php_version']}). Every PHP config "
                    "value, every loaded module, every env var (incl. "
                    "DB credentials, API keys, signing secrets), the "
                    "filesystem layout, and the exact version are "
                    "now public."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Delete the file from the document root and "
                    "audit the deploy pipeline so it doesn't come "
                    "back. Then:\n"
                    "  - Rotate every secret that was visible in the "
                    "  Environment section.\n"
                    "  - Confirm none of the listed paths are "
                    "  attacker-writable (`/tmp` and `upload_tmp_dir` "
                    "  are routinely interesting).\n"
                    "  - Map the version against the published CVE "
                    "  list -- attackers will."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} phpinfo paths "
                     f"on {origin}; none returned the phpinfo() "
                     "signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpPhpinfoExposedProbe().main()
