#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Client-side DOM XSS sink usage in production JS bundles.

Single-page apps frequently sink user-controlled values into
DOM-write operations (`element.innerHTML = ...`, `document.write(...)`,
`eval(...)`, `new Function(...)`, `setTimeout(<string>, ...)`,
`location.href = ...`). Each of those, when fed an untrusted string,
becomes a DOM-XSS or open-redirect vector that the server's CSP cannot
necessarily block.

The probe is a static analyzer over the JS bundles linked from the
target's index page. To stay high-fidelity we apply five filters that
together kill the common false-positive patterns:

  1. The right-hand-side of an assignment (or the first argument of a
     dynamic-execution call) MUST be a non-string-literal expression --
     i.e. an identifier or member access. `el.innerHTML = "<b>hi</b>"`
     is a static template and is NOT flagged; `el.innerHTML = userText`
     IS flagged.
  2. setTimeout / setInterval are flagged ONLY when the first argument
     is string-shaped: a quoted literal, a template literal, or a
     `name + ...` concat expression. The function-reference form,
     which is the overwhelmingly common safe usage (e.g.
     `setTimeout(updatePagination, 150)`), is NOT flagged. A function
     reference is not "string-as-code" and does not deferred-eval.
  3. Each candidate match is suppressed if a recognizable safety
     guard token (`isSafe`, `isValid`, `validate`, `sanitize`,
     `DOMPurify`, `encodeURIComponent`, `trustedTypes`, ...) appears
     within ~280 chars upstream of the sink OR within ~160 chars
     downstream / inline with the sink expression. The downstream
     window catches the very common library shape where the sanitizer
     is called on the assignment RHS itself, e.g.
     `t.innerHTML = escapeMarkup(r)` or
     `a.innerHTML = u[1] + jQuery.htmlPrefilter(o) + u[2]`, which the
     pure-upstream check used to miss. We use `finditer` so a guarded
     match does NOT consume the bundle's slot for that sink type --
     a later, unguarded match in the same bundle will still surface.
  4. Bundles that look like well-known third-party libraries
     (jQuery, select2, bootstrap, react, vue, angular, chart.js,
     moment, lodash, ...) are classified as vendor by URL/filename
     pattern OR by a content fingerprint in the first ~4 KB. Sinks
     inside vendor bundles are still recorded in the evidence (so
     the report is transparent about what was scanned), but they
     do NOT count toward the validation gate. The actionable bug
     for vendor sinks lives at the caller site -- e.g. an app file
     calling `$x.html(unsafe)` -- and a separate probe is the right
     place to detect that. Vendor bundles alone never raise a
     finding.
  5. We require at least 2 distinct sink classes IN APPLICATION
     bundles before raising validated=True. A single application
     hit, or any number of vendor-only hits, is reported as refuted
     with the candidates noted.

Detection signal:
  >=2 distinct sink categories, each on a non-literal RHS, not
  guarded by a recognizable safety check, observed in at least one
  non-vendor (application) bundle linked from the origin's index
  page.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Reused from angular_secrets_in_bundle.py: pull <script src="..."> refs
# from the index page. We deliberately keep this loose so minified or
# pre-formatted HTML still matches.
SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"', re.I)

# Each sink pattern requires the RHS / first-arg to start with an
# identifier-shaped character (letter, underscore, $) -- i.e. NOT a
# quote and NOT a digit. That is the cheap-but-effective way to skip
# string literals like `el.innerHTML = "<b>hi</b>"` while still
# matching `el.innerHTML = unsafeVar` or `el.innerHTML = data.body`.
_IDENT_LEAD = r"[a-zA-Z_$]"

# For setTimeout / setInterval, the actual deferred-eval bug requires
# a STRING first arg, not a function reference. We match only when the
# first arg is shaped like a string: a quoted literal (`'`, `"`,
# backtick template) OR an identifier immediately followed by `+`
# (string concatenation expression). A bare identifier like
# `setTimeout(updatePagination, 150)` is a function reference and
# safe -- it must NOT match.
_STRING_LEAD = r"""(?:['"`]|[A-Za-z_$][\w$]*\s*\+)"""

SINK_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(rf"\.innerHTML\s*=\s*{_IDENT_LEAD}"),
     "innerHTML = <expr>"),
    (re.compile(rf"\.outerHTML\s*=\s*{_IDENT_LEAD}"),
     "outerHTML = <expr>"),
    (re.compile(rf"document\.write\(\s*{_IDENT_LEAD}"),
     "document.write(<expr>)"),
    (re.compile(rf"document\.writeln\(\s*{_IDENT_LEAD}"),
     "document.writeln(<expr>)"),
    (re.compile(rf"\beval\(\s*{_IDENT_LEAD}"),
     "eval(<expr>)"),
    (re.compile(rf"\bnew\s+Function\(\s*{_IDENT_LEAD}"),
     "new Function(<expr>)"),
    # setTimeout / setInterval: see _STRING_LEAD comment above. We
    # accept a quoted/template/concat first arg followed (eventually)
    # by a numeric delay -- the classic `setTimeout("alert(1)", 100)`
    # / `setTimeout("foo " + bar, 100)` deferred-eval shape.
    (re.compile(rf"\bsetTimeout\(\s*{_STRING_LEAD}[^)]*,\s*\d"),
     "setTimeout(<string-as-code>, <delay>)"),
    (re.compile(rf"\bsetInterval\(\s*{_STRING_LEAD}[^)]*,\s*\d"),
     "setInterval(<string-as-code>, <delay>)"),
    (re.compile(rf"location\.href\s*=\s*{_IDENT_LEAD}"),
     "location.href = <expr>"),
    (re.compile(rf"location\.replace\(\s*{_IDENT_LEAD}"),
     "location.replace(<expr>)"),
)

MAX_BUNDLES = 8

# How far back (in chars) to look for a safety guard token before a
# candidate sink match. 280 chars comfortably covers the typical
# `if (isSafeFoo(x)) { sink = x; }` shape even after the file has been
# minified down to a single long line, while staying tight enough that
# we don't pick up an unrelated guard from a prior function block.
GUARD_LOOKBACK_CHARS = 280

# How far forward (in chars) from the start of the sink match to look
# for an inline sanitizer. Smaller than the lookback window because we
# only care about tokens that live in the assignment RHS itself --
# e.g. `t.innerHTML = escapeMarkup(r)` -- not in a later sibling
# expression. 160 chars covers minified RHS expressions of the
# `a.innerHTML = u[1] + ce.htmlPrefilter(o) + u[2]` shape.
GUARD_LOOKAHEAD_CHARS = 160

# Substrings that, if seen near a sink match (upstream within
# GUARD_LOOKBACK_CHARS, or inline within GUARD_LOOKAHEAD_CHARS),
# indicate the value flowing into the sink has been allowlisted,
# validated, sanitized, escaped, or wrapped in Trusted Types.
#
# Two flavors are mixed here:
#   - Generic guards (`isSafe`, `validate`, `sanitize`, ...) that an
#     application author writes around their own sinks.
#   - Library-internal sanitizers (`htmlPrefilter`, `escapeMarkup`,
#     `escapeHtml`, ...) that vendor bundles call as the LAST step
#     before assigning to innerHTML / outerHTML. These tokens are
#     what make `t.innerHTML = i(r)` in select2 (where `i` ===
#     `escapeMarkup`) recognizable as guarded.
#   - Narrow-regex gating tokens (`.match(/`, `.test(/`, `RegExp(`)
#     that catch the `if (h.match(/^new Date\(.../)) eval(h)` shape
#     jQuery's legacy parseJSON polyfill uses.
#
# Presence of any of these tokens in the lookback/lookahead window
# suppresses the match -- we'd rather miss a real bug than ship the
# user a noisy report. The list is deliberately permissive;
# tightening it further requires real taint analysis, which this
# static-pass probe does not attempt.
SAFE_GUARD_TOKENS: tuple[str, ...] = (
    # Generic application-author guards.
    "isSafe",
    "isValid",
    "isAllowed",
    "isAllowlisted",
    "isWhitelisted",
    "validate",
    "sanitize",
    "DOMPurify",
    "encodeURI",
    "encodeURIComponent",
    "escapeHtml",
    "escape_html",
    "escapeHTML",
    "trustedTypes",
    "TrustedTypes",
    "allowlist",
    "whitelist",
    # Library-internal sanitizers we've observed shipping in vendor
    # bundles and being assigned directly to innerHTML / outerHTML.
    # These are the tokens that the old upstream-only check missed
    # and that caused jQuery's `.html()` impl and select2's option
    # renderer to be flagged as DOM-XSS sinks.
    "htmlPrefilter",
    "escapeMarkup",
    "htmlEscape",
    "_escape",
    "escapeHtmlChar",
    "htmlEntities",
    # Narrow-regex gating. The presence of a .match / .test against a
    # regex literal in the lookback window is a strong signal that the
    # eval / innerHTML target has been shape-checked; matching the
    # full regex would require an AST and is overkill here.
    ".match(/",
    ".test(/",
    "RegExp(",
)

# Vendor bundle classification. A bundle that matches ANY of these
# URL/filename substrings is treated as third-party library code.
# Order doesn't matter; the check is a simple `any(substr in url)`.
# We match on the lower-cased URL so capitalization variants (e.g.
# `jQuery-3.6.0.min.js`) still hit.
VENDOR_URL_PATTERNS: tuple[str, ...] = (
    # Library filenames -- the most common signal. Bare filenames
    # like `jquery.js` or versioned `jquery-3.6.0.min.js` both hit
    # via the `jquery` substring.
    "jquery", "select2", "bootstrap", "popper",
    "angular", "react", "vue.", "vue-", "ember",
    "backbone", "knockout", "polymer",
    "lodash", "underscore", "moment", "dayjs", "luxon",
    "chart.js", "chartjs", "chart.min", "d3.", "d3-",
    "highcharts", "plotly", "echarts",
    "datatables", "datatable.", "tabulator",
    "tinymce", "ckeditor", "quill", "summernote",
    "leaflet", "mapbox-gl", "openlayers",
    "prism.", "highlight.js", "highlight.min",
    "mathjax", "katex",
    "ace.js", "codemirror", "monaco",
    "swagger-ui", "redoc",
    "fontawesome", "font-awesome",
    "modernizr", "core-js", "babel-polyfill",
    "require.js", "requirejs",
    "socket.io",
    # Path segments. These rarely appear in app-authored bundles.
    "/vendor/", "/vendors/", "/lib/", "/libs/",
    "/third-party/", "/thirdparty/", "/3rdparty/",
    "/node_modules/", "/bower_components/",
    "/cdn/", "/cdnjs/", "/assets/cdn/",
)

# Vendor content fingerprints. Checked against the first ~4 KB of the
# bundle so we catch libraries that have been renamed (e.g.
# `core.min.js` that is actually jQuery + plugins, which is exactly
# what produced finding 2957). Order is irrelevant.
VENDOR_FINGERPRINT_BYTES = 4096
VENDOR_CONTENT_FINGERPRINTS: tuple[str, ...] = (
    "jQuery JavaScript Library",
    "jQuery v",
    "jquery.com",
    "Sizzle CSS Selector Engine",
    "Select2 ",
    "select2/utils",
    "Bootstrap v",
    "getbootstrap.com",
    "AngularJS v",
    "Angular v",
    "React v",
    "Vue.js v",
    "Vue v",
    "Chart.js",
    "Moment.js",
    "lodash.com",
    "Underscore.js",
    "D3.js",
    "highcharts.com",
    "Plotly.js",
    "DataTables ",
    "TinyMCE",
    "CKEditor",
    "Leaflet",
    "highlight.js",
    "MathJax",
    "CodeMirror",
    "swagger-ui",
)


def _excerpt(text: str, idx: int, span: int = 60) -> str:
    """Return a short, single-line excerpt around offset `idx` so the
    evidence shows context without dumping the full bundle."""
    start = max(0, idx - span)
    end = min(len(text), idx + span)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    return snippet.strip()[:160]


def _is_guarded(text: str, match_start: int) -> bool:
    """Return True iff a recognizable safety guard token appears near
    the sink match -- either upstream within GUARD_LOOKBACK_CHARS or
    inline / downstream within GUARD_LOOKAHEAD_CHARS.

    This is the cheap counterpart to a real taint analysis: real bugs
    rarely sit immediately next to an `isSafe*` / `DOMPurify` /
    `encodeURIComponent` / `htmlPrefilter` / `escapeMarkup` call, so
    a hit in either window is far more likely to be a guarded usage
    than a coincidence. The lookahead window is what catches the
    library-RHS shape `t.innerHTML = escapeMarkup(r)` that the old
    upstream-only check used to miss."""
    back_start = max(0, match_start - GUARD_LOOKBACK_CHARS)
    fwd_end    = min(len(text), match_start + GUARD_LOOKAHEAD_CHARS)
    window = text[back_start:fwd_end]
    return any(tok in window for tok in SAFE_GUARD_TOKENS)


def _is_vendor_bundle(url: str, body_text: str) -> bool:
    """Classify a bundle as third-party (vendor) or application code.

    Two cheap signals, OR'd together:
      - URL/filename substring match (e.g. `jquery`, `select2`,
        `/vendor/`, `/node_modules/`).
      - Content fingerprint in the first VENDOR_FINGERPRINT_BYTES of
        the bundle (catches files that have been renamed by the
        build pipeline, e.g. `core.min.js` that is actually jQuery).

    We err toward labeling things vendor: false-vendoring a bundle
    suppresses sinks inside that bundle from the validation gate,
    which is exactly the right behavior for code we don't own. The
    caller-side usage (e.g. app code calling `$x.html(unsafe)`) is
    detected by a different probe, not this one."""
    lo_url = (url or "").lower()
    for pat in VENDOR_URL_PATTERNS:
        if pat in lo_url:
            return True
    head = (body_text or "")[:VENDOR_FINGERPRINT_BYTES]
    for fp in VENDOR_CONTENT_FINGERPRINTS:
        if fp in head:
            return True
    return False


class ClientJsDomXssSinksProbe(Probe):
    name = "clientjs_dom_xss_sinks"
    summary = ("Detects DOM-write / dynamic-eval sinks fed by non-literal "
               "expressions across the linked JS bundles.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--bundle", action="append", default=[],
            help="Additional bundle URL/path to scan (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: discover bundles. Same approach as
        # angular_secrets_in_bundle.py -- index page + caller overrides.
        r = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if r.status == 200 and r.body:
            bundles.extend(SCRIPT_RE.findall(r.text or ""))
        bundles += list(args.bundle or [])
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles[:MAX_BUNDLES]]

        attempts: list[dict] = []
        # Sink-class -> list of {bundle, excerpt, vendor}. We track
        # vendor / app sinks together in `sink_hits` so the evidence
        # block stays unified; the validation gate below splits them.
        sink_hits: dict[str, list[dict]] = {}
        # Subset of sink_hits keys that were seen in at least one
        # application (non-vendor) bundle. Only this set is allowed
        # to trigger validated=True.
        app_sink_classes: set[str] = set()
        vendor_bundle_count = 0
        app_bundle_count = 0
        for url in bundles:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status != 200 or not rb.body:
                attempts.append(row)
                continue
            text = rb.text or ""
            is_vendor = _is_vendor_bundle(url, text)
            row["vendor"] = is_vendor
            if is_vendor:
                vendor_bundle_count += 1
            else:
                app_bundle_count += 1
            local: list[dict] = []
            for pat, label in SINK_PATTERNS:
                # Walk every match in the bundle and pick the first
                # one that is NOT recognized as guarded. If every
                # match is guarded, the bundle does not contribute a
                # hit for this sink class. Using finditer (not
                # search) is what makes filter (3) in the module
                # docstring actually useful: an early guarded match
                # no longer hides a later real bug.
                chosen_excerpt: str | None = None
                for m in pat.finditer(text):
                    if _is_guarded(text, m.start()):
                        continue
                    chosen_excerpt = _excerpt(text, m.start())
                    break
                if chosen_excerpt is None:
                    continue
                local.append({"sink": label, "excerpt": chosen_excerpt,
                              "vendor": is_vendor})
                sink_hits.setdefault(label, []).append({
                    "bundle": url, "excerpt": chosen_excerpt,
                    "vendor": is_vendor,
                })
                if not is_vendor:
                    app_sink_classes.add(label)
            row["sinks"] = local
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts,
                    "bundles_scanned": len(bundles),
                    "app_bundles": app_bundle_count,
                    "vendor_bundles": vendor_bundle_count,
                    "app_sink_classes": sorted(app_sink_classes)}

        # High-fidelity rule: 2+ distinct sink categories required IN
        # APPLICATION CODE. Vendor sinks alone never raise a finding
        # because the actionable bug for those lives at the caller
        # site, which a separate probe is the right place to detect.
        if len(app_sink_classes) >= 2:
            sample = []
            for label in sorted(app_sink_classes)[:4]:
                # Pick the first app-bundle hit for this label.
                first_app = next((h for h in sink_hits.get(label, [])
                                  if not h.get("vendor")), None)
                if first_app is None:
                    continue
                sample.append({"sink": label,
                               "first_bundle": first_app["bundle"],
                               "excerpt": first_app["excerpt"]})
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: {len(app_sink_classes)} distinct DOM-XSS "
                    f"sink categories observed in application JS on "
                    f"{origin}, each fed a non-literal expression. "
                    f"Sinks present: "
                    f"{', '.join(sorted(app_sink_classes))}."),
                evidence={**evidence, "sink_hits": sink_hits,
                          "sample": sample},
                severity_uplift="medium",
                remediation=(
                    "Replace each flagged sink with a safe equivalent:\n"
                    "  - `el.innerHTML = userText`  ->  "
                    "`el.textContent = userText` (text only) OR run the "
                    "value through DOMPurify.sanitize before assigning.\n"
                    "  - `document.write(x)` is essentially never safe in "
                    "modern code -- delete the call and emit DOM nodes "
                    "via createElement / textContent instead.\n"
                    "  - `eval(x)` and `new Function(x)` should be "
                    "removed entirely; if you genuinely need late-bound "
                    "code, ship a real plugin loader with an allowlist.\n"
                    "  - `setTimeout(stringExpr, ms)` -- pass a function "
                    "reference, never a string.\n"
                    "  - `location.href = userVal` -- validate the value "
                    "against an allowlist of internal paths or hosts "
                    "before assigning.\n"
                    "Then layer Trusted Types "
                    "(`Content-Security-Policy: require-trusted-types-for "
                    "'script'`) so future regressions throw at runtime."),
            )

        # Refuted. Build a summary that explicitly distinguishes the
        # "all sinks live in vendor bundles" case from the "no sinks
        # anywhere" case, since the two reads are very different for
        # triage.
        if sink_hits and not app_sink_classes:
            summary = (
                f"Refuted: scanned {len(bundles)} bundle(s) on {origin}; "
                f"every sink class observed ({', '.join(sink_hits.keys())}) "
                f"lives in a third-party library bundle "
                f"({vendor_bundle_count} of {len(bundles)} bundle(s) "
                f"classified as vendor). Application JS contributed 0 "
                "sink classes -- vendor sinks alone are not a DOM-XSS "
                "finding; the actionable bug, if any, lives at the "
                "caller site in app code.")
        else:
            summary = (
                f"Refuted: scanned {len(bundles)} bundle(s) on {origin}; "
                f"saw {len(app_sink_classes)} sink class(es) in "
                "application JS with non-literal RHS -- not enough to "
                "confirm a DOM-XSS pattern by static analysis.")
        return Verdict(
            validated=False, confidence=0.85,
            summary=summary,
            evidence={**evidence, "sink_hits": sink_hits},
        )


if __name__ == "__main__":
    ClientJsDomXssSinksProbe().main()
