# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Unit tests for the clientjs_dom_xss_sinks probe focused on the
false-positive shape that finding 2957 (assessment 62) surfaced.

These tests are pure-unit -- they construct a stub HTTP client that
returns canned bundle bodies for the URLs the probe walks. No Juice
Shop / no live container needed, so they run in the standard pytest
collection on every CI build instead of being gated on the probe
stack being up.

Coverage:
  - Vendor-only bundles (jQuery + select2) MUST refute, even when
    they contain multiple distinct sink classes. The actionable bug
    for vendor sinks is at the caller site in app code, not inside
    the library implementation.
  - An application bundle with 2+ distinct, unguarded sink classes
    MUST validate.
  - An application bundle whose innerHTML assignment is wrapped in a
    library sanitizer (escapeMarkup) MUST NOT fire (inline-guard
    recognition).
  - The narrow-regex gating pattern that jQuery's legacy parseJSON
    polyfill uses (`h.match(/^new Date\\(.../)`) MUST suppress the
    eval() sink even in an app bundle.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest


# Import the probe module by path. enhanced_testing/lib resolves the
# real toolkit primitives, so we don't need to stub them; the tests
# never make actual HTTP requests because we replace the client.
_PROBE_DIR = Path(__file__).resolve().parent.parent / "probes"
sys.path.insert(0, str(_PROBE_DIR))
sys.path.insert(0, str(_PROBE_DIR.parent))
import clientjs_dom_xss_sinks as probe_mod   # noqa: E402


# ---------- canned bundle bodies ------------------------------------

# Excerpt from the actual core.min.js that triggered finding 2957.
# Real jQuery contents include both an innerHTML assignment (.html()
# impl) and an eval() call gated by a narrow Date regex.
JQUERY_BUNDLE = (
    "/*! jQuery JavaScript Library v3.6.0 - jquery.com */\n"
    "var ce={};"
    "function htmlPrefilter(x){return x;}"
    # The .html() impl: innerHTML = u[1] + htmlPrefilter(o) + u[2].
    # Inline-guard recognition must see `htmlPrefilter` and suppress.
    "ce.html=function(a,o){var u=ke[s]||ke._default;"
    "a.innerHTML=u[1]+ce.htmlPrefilter(o)+u[2];};"
    # Legacy parseJSON polyfill: eval gated by a narrow regex.
    "function _legacy(h){"
    "if(typeof h==='string'&&h.match(/^new Date\\((.*)\\)$/)){"
    "f[g]=eval(h)}};"
)

SELECT2_BUNDLE = (
    "/*! Select2 4.0.13 */\n"
    "var Select2=function(){};"
    "function escapeMarkup(x){return x.replace(/</g,'&lt;');}"
    "function render(t,e){var r=n(e,t);"
    "if(null==r){t.style.display='none';return;}"
    # The select2 option renderer: innerHTML = escapeMarkup(r).
    # Inline-guard recognition must see `escapeMarkup` and suppress.
    "if(typeof r==='string'){t.innerHTML=escapeMarkup(r);}"
    "}"
)

# An application bundle with two distinct, unguarded sinks. This is
# the shape that SHOULD raise a finding -- pre-fix and post-fix both.
APP_BUNDLE_VULN = (
    "function renderResults(data){"
    "document.getElementById('results').innerHTML=data.body;"
    "}"
    "function runScript(snippet){"
    "eval(snippet);"
    "}"
)

# An application bundle whose innerHTML assignment goes through a
# library sanitizer call on the RHS. The inline-guard recognition
# (escapeMarkup substring within GUARD_LOOKAHEAD_CHARS of the match)
# must suppress this.
APP_BUNDLE_SANITIZED = (
    "function show(el,raw){"
    "el.innerHTML=escapeMarkup(raw);"
    "}"
)

# An application bundle whose eval is gated by a narrow regex check.
# The .match(/.../) substring within GUARD_LOOKBACK_CHARS must
# suppress this.
APP_BUNDLE_REGEX_GATED = (
    "function parseDate(h){"
    "if(typeof h==='string'&&h.match(/^\\d{4}-\\d{2}-\\d{2}$/)){"
    "return eval('new Date(\"'+h+'\")');"
    "}}"
)


# ---------- stub HTTP client ----------------------------------------

class _FakeResponse:
    """Mimics toolkit.http.Response just enough for the probe's
    consumption (status / body / text / size)."""

    def __init__(self, body: str, status: int = 200):
        self.status = status
        self.body = body.encode("utf-8")
        self.headers: dict = {}
        self.elapsed_ms = 0
        self.final_url = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def size(self) -> int:
        return len(self.body)


class _StubClient:
    """Returns a canned response per URL. Unknown URLs return 404."""

    def __init__(self, routes: dict[str, str]):
        self.routes = routes

    def request(self, method: str, url: str, **kwargs) -> _FakeResponse:
        if url in self.routes:
            return _FakeResponse(self.routes[url], 200)
        return _FakeResponse("", 404)


def _args(url: str) -> argparse.Namespace:
    # The probe only reads .url and .bundle from args.
    return argparse.Namespace(url=url, bundle=[])


# ---------- the actual cases ---------------------------------------

ORIGIN = "https://example.test"


def _index_html(*bundle_paths: str) -> str:
    tags = "\n".join(
        f'<script src="{p}"></script>' for p in bundle_paths)
    return f"<html><head>{tags}</head><body></body></html>"


def test_vendor_only_bundles_refute_finding_2957_shape():
    """Reproduce finding 2957: jQuery + select2, app bundles empty.
    Pre-fix this fired validated=True; post-fix it must refute."""
    routes = {
        f"{ORIGIN}/": _index_html(
            "/app/js/core.min.js",
            "/app/js/vendor/select2-4.0.13.min.js",
            "/app/js/script.js",
            "/app/js/event-handlers.js?v=2",
        ),
        f"{ORIGIN}/app/js/core.min.js": JQUERY_BUNDLE,
        f"{ORIGIN}/app/js/vendor/select2-4.0.13.min.js": SELECT2_BUNDLE,
        f"{ORIGIN}/app/js/script.js":
            "function App(){console.log('hi')}",
        f"{ORIGIN}/app/js/event-handlers.js?v=2":
            "document.addEventListener('click',function(e){})",
    }
    p = probe_mod.ClientJsDomXssSinksProbe()
    v = p.run(_args(f"{ORIGIN}/"), _StubClient(routes))
    assert v.validated is not True, (
        f"vendor-only sinks must not validate. summary={v.summary!r}")
    # And the evidence must reflect that 2 of 4 bundles were vendor.
    assert v.evidence["vendor_bundles"] == 2
    assert v.evidence["app_bundles"] == 2
    assert v.evidence["app_sink_classes"] == []


def test_app_bundle_two_distinct_sinks_validates():
    """The vulnerable shape we DO want to catch: an app bundle with
    two distinct unguarded sink classes."""
    routes = {
        f"{ORIGIN}/": _index_html("/app/js/script.js"),
        f"{ORIGIN}/app/js/script.js": APP_BUNDLE_VULN,
    }
    p = probe_mod.ClientJsDomXssSinksProbe()
    v = p.run(_args(f"{ORIGIN}/"), _StubClient(routes))
    assert v.validated is True, (
        f"two unguarded sinks in app code must validate. "
        f"summary={v.summary!r}")
    assert set(v.evidence["app_sink_classes"]) >= {
        "innerHTML = <expr>", "eval(<expr>)"}


def test_inline_sanitizer_in_app_bundle_suppresses():
    """An app bundle whose only innerHTML assignment goes through a
    sanitizer on the RHS must NOT contribute a sink class."""
    routes = {
        f"{ORIGIN}/": _index_html("/app/js/script.js"),
        f"{ORIGIN}/app/js/script.js": APP_BUNDLE_SANITIZED,
    }
    p = probe_mod.ClientJsDomXssSinksProbe()
    v = p.run(_args(f"{ORIGIN}/"), _StubClient(routes))
    assert v.validated is not True, (
        f"inline escapeMarkup must suppress. summary={v.summary!r}")
    assert v.evidence["app_sink_classes"] == []


def test_regex_gated_eval_in_app_bundle_suppresses():
    """An app bundle whose only eval is gated by .match(/.../) must
    NOT contribute a sink class."""
    routes = {
        f"{ORIGIN}/": _index_html("/app/js/script.js"),
        f"{ORIGIN}/app/js/script.js": APP_BUNDLE_REGEX_GATED,
    }
    p = probe_mod.ClientJsDomXssSinksProbe()
    v = p.run(_args(f"{ORIGIN}/"), _StubClient(routes))
    assert v.validated is not True, (
        f"regex-gated eval must suppress. summary={v.summary!r}")


def test_vendor_classification_by_content_fingerprint():
    """A bundle renamed to a non-vendor filename but containing a
    library banner in its first 4 KB must still be classified as
    vendor. This is the exact `core.min.js` situation from
    finding 2957."""
    assert probe_mod._is_vendor_bundle(
        "https://x/app/js/core.min.js",
        "/*! jQuery JavaScript Library v3.6.0 - jquery.com */\nvar a=1;",
    ) is True
    assert probe_mod._is_vendor_bundle(
        "https://x/app/js/vendor/select2-4.0.13.min.js", "",
    ) is True
    assert probe_mod._is_vendor_bundle(
        "https://x/app/js/script.js",
        "function App(){console.log('hi')}",
    ) is False


@pytest.mark.parametrize("text,expected", [
    # Inline htmlPrefilter call on the RHS.
    ("a.innerHTML=u[1]+ce.htmlPrefilter(o)+u[2];", True),
    # Inline escapeMarkup call on the RHS.
    ("t.innerHTML=escapeMarkup(r);", True),
    # Upstream isSafe guard.
    ("if(isSafe(x)){el.innerHTML=x;}", True),
    # Unguarded direct assignment of a tainted identifier.
    ("el.innerHTML=userInput;", False),
])
def test_is_guarded_inline_and_upstream(text, expected):
    import re
    pat = re.compile(r"\.innerHTML\s*=\s*[a-zA-Z_$]")
    hit = pat.search(text)
    assert hit is not None, "test setup: pattern must match"
    assert probe_mod._is_guarded(text, hit.start()) is expected
