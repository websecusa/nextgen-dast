#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Information disclosure: production .js.map files reachable.

Webpack / Vite emit `.js.map` source maps that point back at the
original (unminified, unobfuscated) TypeScript / Angular sources.
Maps are intended for development; production builds either suppress
the `//# sourceMappingURL=` annotation or refuse to serve `*.map`
files. When neither is in place, an attacker fetches the maps and
recovers the entire SPA source tree.

Detection signal:
  Fetch `/`, locate the bundled `main.<hash>.js` reference, fetch
  `main.<hash>.js.map`, parse JSON, look for the `webpack:///` source
  paths or `sources` array — both are unambiguous markers of a real
  source map.

Tested against:
  + OWASP Juice Shop  /main.*.js.map is publicly served and lists
                      `./src/...` paths → validated=True.
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Pattern that matches both Webpack-style hash bundles
# (main.abc123.js) and Vite-style (main-DEadb33f.js).
_BUNDLE_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']*?(?:main|app|runtime|vendor)[^"']*?\.js)["']""",
    re.IGNORECASE)


class SourceMapExposedProbe(Probe):
    name = "info_source_map_exposed"
    summary = ("Detects publicly-served Webpack/Vite source maps that "
               "leak the application's original source tree.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--js-name", action="append", default=[],
            help="Additional JS bundle name to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: fetch the index, find a bundle reference.
        r = client.request("GET", origin + "/")
        attempts: list[dict] = [{"step": "index", "status": r.status,
                                 "size": r.size}]
        bundles: list[str] = []
        if r.status == 200 and r.body:
            for m in _BUNDLE_RE.finditer(r.text):
                bundle = m.group(1)
                if bundle not in bundles:
                    bundles.append(bundle)
                if len(bundles) >= 5:
                    break
        bundles += list(args.js_name or [])
        # If nothing matched, fall back to common static names.
        if not bundles:
            bundles = ["/main.js", "/main.bundle.js", "/app.js"]

        # Step 2: try fetching <bundle>.map for each.
        confirmed: dict | None = None
        for b in bundles:
            map_url = urljoin(origin + "/", b + ".map")
            r = client.request("GET", map_url)
            row = {"step": "map-fetch", "url": map_url,
                   "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                # Verify the body is actually a source map. Two
                # markers: `webpack:///` source paths, and a top-level
                # `sources` list in the JSON envelope.
                text = r.text or ""
                if "webpack:///" in text:
                    row["map_marker"] = "webpack:/// path"
                    confirmed = row
                    attempts.append(row)
                    break
                try:
                    doc = json.loads(text)
                    if isinstance(doc, dict) and isinstance(
                            doc.get("sources"), list) \
                            and len(doc["sources"]) > 0:
                        row["map_marker"] = (f"`sources` array "
                                             f"({len(doc['sources'])} entries)")
                        confirmed = row
                        attempts.append(row)
                        break
                except json.JSONDecodeError:
                    pass
            attempts.append(row)

        evidence = {"origin": origin, "bundles_seen": bundles,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(f"Confirmed: source map at {confirmed['url']} "
                         "— application's original source tree is "
                         "publicly fetchable."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="medium",
                remediation=(
                    "Stop serving `.js.map` from the production "
                    "vhost. Either: (a) build production bundles "
                    "without source maps "
                    "(`webpack --mode production` does this; Vite "
                    "needs `build.sourcemap: false`); (b) emit the "
                    "maps but never copy them into the deploy "
                    "artifact; or (c) serve them only from a "
                    "loopback / VPN-only backend used by "
                    "internal-only error reporting (Sentry, etc.). "
                    "Strip the `//# sourceMappingURL=...` annotation "
                    "from production JS so even guessing the map "
                    "name doesn't help."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: probed {len(bundles)} bundle "
                     f"candidates on {origin}; no .js.map reachable."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SourceMapExposedProbe().main()
