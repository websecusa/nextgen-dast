#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
PHP / Composer: vendored dependency manifest exposed.

`/vendor/composer/installed.json` (and the equivalent
`installed.php`) is a complete dump of every package + version the
app depends on. For an attacker that's instant SCA -- they look up
each package against published CVEs and find the one that's not
patched. Different from the existing `info_backup_files_root`
catalogue probe -- this one validates the structural shape of the
JSON, not just the 200, so it doesn't false-positive on an SPA's
catch-all index.html.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/vendor/composer/installed.json",
    "/vendor/composer/installed.php",
    "/vendor/autoload.php",
    "/vendor/composer/autoload_real.php",
    "/composer.json",
    "/composer.lock",
)


class PhpComposerInstalledJsonProbe(Probe):
    name = "php_composer_installed_json"
    summary = ("Detects exposed Composer dependency manifests "
               "(`/vendor/composer/installed.json`, `composer.lock`) "
               "-- complete SCA target list for the attacker.")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: dict | None = None
        for p in PATHS:
            r = client.request("GET", urljoin(origin, p))
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status != 200 or not r.body:
                attempts.append(row)
                continue
            text = r.text or ""
            # JSON variants: parse + check for `packages` array.
            if p.endswith(".json"):
                try:
                    doc = json.loads(text)
                    if isinstance(doc, dict):
                        pkgs = (doc.get("packages")
                                or doc.get("installed"))
                        if isinstance(pkgs, list) and len(pkgs) > 0:
                            row["packages_count"] = len(pkgs)
                            row["sample_pkg_names"] = [
                                pk.get("name") for pk in pkgs[:5]
                                if isinstance(pk, dict)]
                            confirmed = row
                            attempts.append(row)
                            break
                    if (isinstance(doc, dict)
                            and (doc.get("name") or doc.get("require"))):
                        # composer.json shape
                        row["composer_json"] = True
                        row["sample_require"] = list(
                            (doc.get("require") or {}).keys())[:8]
                        confirmed = row
                        attempts.append(row)
                        break
                except (ValueError, json.JSONDecodeError):
                    pass
            elif p.endswith(".lock"):
                try:
                    doc = json.loads(text)
                    if (isinstance(doc, dict)
                            and isinstance(doc.get("packages"), list)
                            and len(doc["packages"]) > 0):
                        row["packages_count"] = len(doc["packages"])
                        row["sample_pkg_names"] = [
                            pk.get("name") for pk in doc["packages"][:5]
                            if isinstance(pk, dict)]
                        confirmed = row
                        attempts.append(row)
                        break
                except (ValueError, json.JSONDecodeError):
                    pass
            elif p.endswith(".php"):
                # installed.php / autoload_real.php / autoload.php --
                # all start with `<?php` and contain Composer-
                # specific markers.
                if "Composer" in text and "<?php" in text:
                    row["composer_php"] = True
                    confirmed = row
                    attempts.append(row)
                    break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(
                    f"Confirmed: Composer dependency manifest at "
                    f"{origin}{confirmed['path']} -- "
                    f"{confirmed.get('packages_count', '(php)')} "
                    "package(s) listed. Sample names: "
                    f"{confirmed.get('sample_pkg_names') or confirmed.get('sample_require') or 'n/a'}. "
                    "Attacker now has a complete SCA target list."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Move `/vendor` outside the document root, OR "
                    "block it at the web server / edge:\n"
                    "  - nginx: `location ~ ^/vendor { deny all; "
                    "  return 404; }`\n"
                    "  - Apache: `<DirectoryMatch \"^/vendor\">"
                    "  Require all denied</DirectoryMatch>`\n"
                    "After the fix, audit access logs for who "
                    "fetched the file during the exposure window. "
                    "Run a dependency-vulnerability scan (composer "
                    "audit, OSV scan) to find which packages need "
                    "upgrading -- the leak's biggest risk is "
                    "informed exploitation of a known CVE in the "
                    "now-known dependency set."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(PATHS)} Composer paths "
                     f"on {origin}; none returned the structural "
                     "Composer manifest signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpComposerInstalledJsonProbe().main()
