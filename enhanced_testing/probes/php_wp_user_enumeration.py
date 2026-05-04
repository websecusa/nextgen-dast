#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
WordPress: anonymous username enumeration.

Two well-known anonymous-enumeration shapes in stock WP:
  1. `/?author=N` -- if author N exists, WP redirects to
     `/author/<slug>/`. The slug IS the username for a brute-force
     attack on `/wp-login.php`.
  2. `/wp-json/wp/v2/users` -- the REST API endpoint for the user
     list. Some installs leave it open to anonymous; the response
     is a JSON array of `{id, name, slug, ...}`.

Either one, by itself, lifts brute-force from "guess username and
password" to "guess only password" -- typically 1000x faster.

High-fidelity signal:
  - For author=N: HTTP 301/302 to `/author/<non-empty-slug>/`.
  - For wp-json: 200 with a JSON array of objects each containing
    `slug` AND `id` AND `name`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

_AUTHOR_LOC_RE = re.compile(r"/author/([A-Za-z0-9_\-]+)/?(?:$|\?|#)")


class PhpWpUserEnumerationProbe(Probe):
    name = "php_wp_user_enumeration"
    summary = ("Detects anonymous WordPress user enumeration via "
               "`?author=N` redirects and the `/wp-json/wp/v2/users` "
               "REST endpoint.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--max-author", type=int, default=5,
            help="Highest author id to probe (default 5).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        max_aid = max(1, int(args.max_author or 5))

        attempts: list[dict] = []
        confirmed_users: list[dict] = []

        # 1. /?author=N redirect-leak
        for aid in range(1, max_aid + 1):
            r = client.request("GET",
                                f"{origin}/?author={aid}",
                                follow_redirects=False)
            row: dict = {"path": f"/?author={aid}",
                         "status": r.status, "size": r.size}
            if r.status in (301, 302) and r.headers:
                loc = ""
                for k, v in r.headers.items():
                    if k.lower() == "location":
                        loc = str(v)
                        break
                m = _AUTHOR_LOC_RE.search(loc)
                if m:
                    slug = m.group(1)
                    row.update({"author_slug": slug, "via": "redirect"})
                    confirmed_users.append({"slug": slug,
                                              "method": "?author"})
                    attempts.append(row)
                    continue
            attempts.append(row)

        # 2. /wp-json/wp/v2/users
        for p in ("/wp-json/wp/v2/users",
                   "/?rest_route=/wp/v2/users",
                   "/wp-json/wp/v2/users?per_page=10"):
            r = client.request("GET", urljoin(origin, p))
            row = {"path": p, "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                try:
                    doc = json.loads(r.text)
                except (ValueError, json.JSONDecodeError):
                    doc = None
                if isinstance(doc, list):
                    users = [u for u in doc
                              if isinstance(u, dict)
                              and "slug" in u and "id" in u]
                    if users:
                        row["users_count"] = len(users)
                        for u in users[:5]:
                            confirmed_users.append({
                                "slug": u.get("slug"),
                                "id": u.get("id"),
                                "name": u.get("name"),
                                "method": "wp-json"})
                        attempts.append(row)
                        break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts,
                    "users": confirmed_users}
        if confirmed_users:
            sample = confirmed_users[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: anonymous WordPress user "
                    f"enumeration on {origin}. Discovered "
                    f"{len(confirmed_users)} username(s) including "
                    f"`{sample.get('slug')}` (via "
                    f"{sample['method']}). Brute force on "
                    "/wp-login.php is now half-known."),
                evidence={**evidence, "confirmed": confirmed_users},
                severity_uplift="high",
                remediation=(
                    "Stop the two enumeration vectors:\n"
                    "  - Author redirect: install a plugin like "
                    "  Stop User Enumeration, OR add an .htaccess / "
                    "  nginx rule that 404s any `?author=` request.\n"
                    "  - REST users endpoint: in functions.php (or "
                    "  via a 'rest_authentication_errors' filter), "
                    "  require `manage_options` to read the users "
                    "  endpoint.\n"
                    "Pair with a brute-force defence on /wp-login.php "
                    "(captcha, 2FA plugin, or fail2ban-on-wp-login)."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: probed {max_aid} author ids and the "
                     f"REST users endpoint on {origin}; no slug "
                     "leaked."),
            evidence=evidence,
        )


if __name__ == "__main__":
    PhpWpUserEnumerationProbe().main()
