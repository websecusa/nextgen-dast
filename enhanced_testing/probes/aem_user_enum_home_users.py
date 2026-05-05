#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
AEM: anonymous user / authorizable enumeration via /home/users.

AEM stores authorizables (users, groups, service accounts) under
`/home/users` in the JCR. When the dispatcher allows JSON
serialization of `/home/users` (or sub-paths), an unauthenticated
attacker can enumerate every user on the publish instance:

  - `/home/users.1.json`        -- one level of children, listing
                                   authorizable home dirs.
  - `/home/users/a.1.json`      -- shard `a` (AEM hashes user
                                   homes into single-letter
                                   subdirectories).
  - `/home/groups.1.json`       -- group enumeration.

The neighboring probe `aem_querybuilder_full_dump` covers the
querybuilder API; this one targets the simpler raw-JCR-listing
form. We rely on the strict structural fingerprint of an AEM user
record (`rep:User` / `rep:authorizableId` properties) to avoid
false positives -- a generic JSON 200 is never enough.

High-fidelity rule:
  (a) status 200;
  (b) JSON response;
  (c) at least one node carries `"jcr:primaryType":"rep:User"` OR
      `"rep:authorizableId":"..."` (both are unique to AEM/JCR
      authorizable records).

Detection signal:
  GET each candidate path; validate when the response is JSON
  containing rep:User / rep:authorizableId structural markers.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

PATHS = (
    "/home/users.1.json",
    "/home/users.json",
    "/home/users/a.1.json",
    "/home/users/b.1.json",
    "/home/groups.1.json",
    "/etc.json",
    "/etc.1.json",
    "/libs.1.json",
    "/var.1.json",
)

# Structural markers unique to AEM authorizable records.
AUTH_RE = re.compile(
    r'"jcr:primaryType"\s*:\s*"(?:rep:User|rep:Group|'
    r'rep:SystemUser)"|"rep:authorizableId"\s*:\s*"[^"]+"')


class AemUserEnumHomeUsersProbe(Probe):
    name = "aem_user_enum_home_users"
    summary = ("Detects anonymous user / authorizable enumeration "
               "via AEM /home/users JSON listing.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional path to test (repeatable).")

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
                # Two corroborating signals:
                #   1. The body is valid JSON (parses).
                #   2. Contains at least one rep:User / rep:Group /
                #      rep:authorizableId field.
                # Both are required.
                try:
                    json.loads(text)
                    row["valid_json"] = True
                except (ValueError, json.JSONDecodeError):
                    row["valid_json"] = False
                if row["valid_json"]:
                    matches = AUTH_RE.findall(text)
                    if matches:
                        # Pull a small sample of authorizable IDs (NOT
                        # full records -- never log entire payload).
                        ids = re.findall(
                            r'"rep:authorizableId"\s*:\s*"([^"]+)"',
                            text)
                        row["authorizable_markers"] = matches[:5]
                        row["sample_ids"] = ids[:5]
                        row["snippet"] = text[:200]
                        confirmed = row
                        attempts.append(row)
                        break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.96,
                summary=(
                    f"Confirmed: AEM user enumeration at "
                    f"{origin}{confirmed['path']}. Response is "
                    "JCR-shape JSON containing rep:User / "
                    "rep:authorizableId records -- the publish "
                    "dispatcher is leaking the authorizable tree to "
                    "anonymous callers. Sample IDs found: "
                    f"{confirmed.get('sample_ids', [])[:3]}."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Block /home, /etc, /libs, /var paths at the "
                    "dispatcher:\n"
                    "  ```\n"
                    "  /0010 { /type \"deny\" /url "
                    "\"^/home(/.*)?$\" }\n"
                    "  /0011 { /type \"deny\" /url "
                    "\"^/(etc|libs|var)(\\..*)?(/.*)?$\" }\n"
                    "  ```\n"
                    "On the publish instance itself, ensure "
                    "rep:authorizableId reads are restricted to "
                    "appropriate principals via the AEM permissions "
                    "panel; treat anonymous access to /home as a "
                    "configuration error.\n"
                    "Audit logs for /home/users.* requests during "
                    "the exposure window -- the user list may have "
                    "been scraped."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} candidate "
                     f"paths on {origin}; no response carried "
                     "rep:User / rep:authorizableId structural "
                     "markers."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AemUserEnumHomeUsersProbe().main()
