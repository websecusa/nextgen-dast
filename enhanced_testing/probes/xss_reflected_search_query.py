#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Reflected XSS in search / filter query parameter.

A search endpoint that interpolates `q=` into the rendered HTML
without escaping is the canonical reflected-XSS primitive. With
one click on a crafted link, the attacker steals the victim's
session, performs CSRF on their behalf, exfiltrates DOM state,
or pivots into stored XSS via the search history.

The signal that distinguishes "reflected and dangerous" from
"reflected but safely escaped" is whether the literal angle-bracket
characters of the marker survive into the response body. If the
server returns `&lt;dast-marker&gt;` the reflection is safe; if it
returns the raw `<dast-marker>` the bug exists. The marker is a
random suffix wrapped in an unfamiliar tag name so we don't false-
positive on a legitimate template element.

Detection signal:
  GET `/search?q=<dast-marker-XXXX>`, `/?q=`, `/api/search?q=`,
  `/products?search=`, etc. If any response body contains the
  literal substring `<dast-marker-XXXX>` (un-escaped angle brackets),
  validate.

Tested against:
  + OWASP Juice Shop  /#/search?q=... reflects unescaped into the
                      Angular template (well-known challenge)
                      -> validated=True.
  + nginx default site -> validated=False.

Read-only: GET only; the marker is a random tag-shape that has no
effect server-side beyond reflection. We never use a real
<script> payload.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, query-parameter name) pairs to test. Keep the catalogue
# small -- a dedicated fuzz probe belongs in a separate file.
SEARCH_TARGETS = (
    ("/", "q"),
    ("/", "search"),
    ("/search", "q"),
    ("/search", "query"),
    ("/api/search", "q"),
    ("/products", "search"),
    ("/rest/products/search", "q"),
    ("/api/Products", "search"),
)


class ReflectedXssSearchQueryProbe(Probe):
    name = "xss_reflected_search_query"
    summary = ("Detects reflected XSS in search / filter query "
               "parameters by checking whether the marker's angle "
               "brackets survive un-escaped into the response body.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional path|param to test "
                 "(e.g. '/feed|q'). Repeatable.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(SEARCH_TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), n.strip()))

        # Marker uses a tag-shape unlikely to appear naturally in any
        # template, with a random suffix so we can grep for it
        # unambiguously. The bracket characters are the variable.
        suffix = secrets.token_hex(6)
        raw    = f"<dast-marker-{suffix}>"
        encoded_safely = ("&lt;dast-marker-" + suffix + "&gt;")

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, param in targets:
            url = urljoin(origin, path) + "?" + urlencode({param: raw})
            r = client.request("GET", url)
            row: dict = {"path": path, "param": param,
                         "status": r.status, "size": r.size}
            if r.status == 200 and r.body:
                text = r.text or ""
                if raw in text:
                    row.update({"reflected_unescaped": True,
                                "marker": raw,
                                "snippet": text[max(0, text.find(raw)-60):
                                                text.find(raw)+len(raw)+60]})
                    confirmed = row
                    attempts.append(row)
                    break
                if encoded_safely in text:
                    row["reflected_safely"] = True
            attempts.append(row)

        evidence = {"origin": origin, "marker_raw": raw,
                    "marker_encoded": encoded_safely,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: reflected XSS at "
                    f"{origin}{confirmed['path']}?{confirmed['param']}=. "
                    f"The marker {raw!r} appears un-HTML-encoded in the "
                    "response body -- the rendering layer trusts the "
                    "query string verbatim. Snippet: "
                    f"{confirmed.get('snippet','')[:200]!r}"),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="high",
                remediation=(
                    "Escape the parameter at every render path. The "
                    "specific fix depends on where the reflection "
                    "happens:\n"
                    "  - Server-side template (Pug, EJS, Jinja, ERB, "
                    "Handlebars): switch the interpolation operator from "
                    "the raw form (`{{{ }}}` / `<%- %>` / `\\\"|safe\\\"`) to "
                    "the escaped form (`{{ }}` / `<%= %>` / default).\n"
                    "  - Client-side framework (React, Vue, Angular): "
                    "stop using `dangerouslySetInnerHTML` / `v-html` / "
                    "`bypassSecurityTrustHtml`; bind the value with "
                    "regular text interpolation, which auto-escapes.\n"
                    "  - Static site / hand-rolled HTML: pass the value "
                    "through a HTML-escape helper before rendering.\n"
                    "Pair with a strict CSP (`default-src 'self'`; no "
                    "`'unsafe-inline'` on `script-src`) so a future "
                    "regression can't be exploited to run script."),
            )
        # Distinguish "endpoint reflected, safely escaped" from "endpoint
        # didn't reflect at all" -- the former is a softer refutation.
        any_safe = any(a.get("reflected_safely") for a in attempts)
        if any_safe:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: search endpoints on {origin} reflected "
                         "the marker but consistently HTML-escaped the "
                         "angle brackets -- safe."),
                evidence=evidence,
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tested {len(attempts)} search targets on "
                     f"{origin}; none returned the marker un-escaped "
                     "(or reflected at all)."),
            evidence=evidence,
        )


if __name__ == "__main__":
    ReflectedXssSearchQueryProbe().main()
