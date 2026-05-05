#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Expression Language injection — Spring EL and OGNL safe canary.

Apps built on Spring (Spring Web / Spring MVC), Apache Struts, or
similar Java frameworks sometimes pass attacker-controlled strings
through an expression-language evaluator (SpEL via
``StandardEvaluationContext``, OGNL on Struts 2 actions, MVEL).
The class of bug parallels SSTI but uses a different syntax. We
test both:

  * Spring EL: ``${T(Math).max(7,7)}`` — evaluates to ``7``.
  * OGNL:      ``%{7*7}``                — evaluates to ``49``.

CRITICAL — these payloads are intentionally arithmetic only. We do
NOT use ``Runtime.exec`` / ``ProcessBuilder`` / ``T(System)`` /
``new java.lang.ProcessBuilder`` payloads — those would cause real
side effects on a vulnerable target. The arithmetic canary is
enough to prove evaluation.

False-positive control:
  * The literal ``7`` and ``49`` appear naturally in many pages.
    Before flagging, we MUST verify the input was actually
    reflected — we send a unique sentinel string with the payload
    and confirm the sentinel is reflected to know the payload
    landed in the rendered output. We then check that the
    arithmetic result appears at the EXACT POSITION where the
    payload was substituted (the sentinel acts as a position
    anchor).

Detection signal:
  Sentinel reflected in response AND the position immediately
  before/after the sentinel was occupied by ``7`` (Spring EL
  canary) or ``49`` (OGNL canary) — i.e. the canary itself was
  evaluated at that exact spot.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints where reflected user input is plausible. We try common
# search/render shapes — if the app reflects the parameter back
# unmodified, the EL evaluator (if any) will run before reflection.
TARGETS = (
    "/search",
    "/api/search",
    "/api/products/search",
    "/?q=",
    "/render",
    "/preview",
    "/api/view",
    "/error",
    "/welcome",
)

# (label, payload-template, expected-result). The {sentinel} slot
# is replaced with a unique random token at run time so we know
# the input landed.
PAYLOAD_TEMPLATES = (
    ("spring_el", "{sentinel}-${{T(Math).max(7,7)}}-{sentinel}", "7"),
    ("ognl",      "{sentinel}-%{{7*7}}-{sentinel}",              "49"),
)


def _build_param(template: str, sentinel: str) -> str:
    """Materialise the payload with the sentinel injected. The
    template uses doubled braces so .format only substitutes the
    sentinel slots, leaving the EL/OGNL braces intact."""
    return template.format(sentinel=sentinel)


def _confirm_eval(text: str, sentinel: str,
                  expected: str) -> tuple[bool, str]:
    """High-fidelity confirmation: the sentinel must appear in the
    body (proves the parameter was reflected) AND the expected
    arithmetic value must appear in a position adjacent to the
    sentinel — meaning the EL substring was replaced by its
    evaluated value while the surrounding sentinel literals stayed.
    """
    if not text or sentinel not in text:
        return False, ""
    # The full echoed payload would look like:
    #   <sentinel>-<expected>-<sentinel>
    # if EL evaluation succeeded. If unevaluated, the original
    # ``${T(Math).max(7,7)}`` would appear between the sentinels.
    expected_pattern = re.compile(
        re.escape(sentinel) + r"-" + re.escape(expected) +
        r"-" + re.escape(sentinel))
    m = expected_pattern.search(text)
    if not m:
        return False, ""
    s, e = max(0, m.start() - 30), min(len(text), m.end() + 30)
    return True, text[s:e]


class EliSpringOgnlCanaryProbe(Probe):
    name = "eli_spring_ognl_canary"
    summary = ("Detects Spring EL / OGNL expression-language injection "
               "via safe arithmetic canaries (`${T(Math).max(7,7)}` and "
               "`%{7*7}`).")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional path to probe (repeatable).")
        # NOTE: --param is registered by the base Probe parser (see
        # toolkit/lib/probe.py); we read it through args.param and just
        # default to "q" inside run() when nothing was supplied.

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        targets = list(TARGETS) + list(args.target or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        for path in targets:
            # Sentinel is unique per-target so reflection from a
            # cached prior attempt can't trick us into flagging.
            for label, tpl, expected in PAYLOAD_TEMPLATES:
                sentinel = "r12s-" + secrets.token_hex(5)
                payload = _build_param(tpl, sentinel)
                qsep = "?" if "?" not in path else "&"
                # Some entries in TARGETS already include `?q=`; we
                # detect that and avoid double-emitting the param.
                if path.endswith("="):
                    url = urljoin(origin, path) + quote(payload)
                else:
                    pname = args.param or "q"
                    url = (urljoin(origin, path) + qsep +
                           pname + "=" + quote(payload))
                r = client.request("GET", url)
                row: dict = {"path": path, "label": label,
                              "expected": expected,
                              "status": r.status, "size": r.size,
                              "sentinel_reflected":
                                  sentinel in (r.text or "")}
                if r.status in (200, 400, 500) and r.body:
                    ok, snippet = _confirm_eval(r.text, sentinel,
                                                  expected)
                    if ok:
                        row.update({"evaluated": True,
                                     "snippet": snippet})
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
                    f"Confirmed: {confirmed['label']} expression "
                    f"language injection at {origin}{confirmed['path']}. "
                    f"The arithmetic canary was evaluated server-side "
                    f"(expected `{confirmed['expected']}` between two "
                    "sentinel anchors). Snippet: "
                    f"{confirmed['snippet']!r}."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop passing user input through an EL evaluator. "
                    "Render values as plain text instead.\n"
                    "  - Spring: never call `parser.parseExpression(userInput)`. "
                    "Use `SimpleEvaluationContext.forReadOnlyDataBinding()` "
                    "if dynamic evaluation is unavoidable, and never "
                    "let the input feed `T(...)` type references.\n"
                    "  - Struts 2: upgrade past the OGNL CVE-affected "
                    "versions, set "
                    "`struts.allowed.classes` / `struts.excludedClasses` "
                    "deny-list to the OGNL sandbox.\n"
                    "  - JSP / JSTL EL: prefer `<c:out>` over "
                    "`${expr}` for any user-controlled value.\n"
                    "  - Defence in depth: web app firewall rule for "
                    "`${T(`, `${@`, `%{` patterns in query strings."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tried {len(attempts)} EL/OGNL canaries "
                     f"on {origin}; none evaluated to their arithmetic "
                     "result between sentinel anchors."),
            evidence=evidence,
        )


if __name__ == "__main__":
    EliSpringOgnlCanaryProbe().main()
