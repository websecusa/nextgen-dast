#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Deserialization / unsafe-eval: B2B order endpoint evaluates user-
controlled JavaScript via Node's `vm` module.

Some apps that accept "B2B" / "bulk" data wrap user input in
`vm.runInNewContext(...)` or `eval(...)` to support a tiny domain-
specific language. When the parser is invoked on raw, unfiltered
input from the request body, an attacker hands the server a function
expression that, on evaluation, returns an arbitrary value — proving
the server runs attacker-supplied JavaScript.

This is the IIFE arithmetic form: pure-arithmetic payload (`7 * 191`),
no side effects, no destructive operations. We look for the literal
`1337` in the server's response. The number is large enough not to
appear coincidentally in a generic JSON envelope.

Detection signal:
  POST /b2b/v2/orders with `{"orderLinesData":"(function(){return 7*191})()"}`
  → response body contains `1337`.

Tested against:
  + OWASP Juice Shop  current build evaluates the IIFE and echoes
                      1337 → validated=True (when reachable; the
                      route may require auth on some builds).
  + nginx default site → validated=False
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints with a known unsafe-eval surface. Juice Shop's literal
# path comes first; the others are guesses for similar applications.
B2B_PATHS = (
    "/b2b/v2/orders",
    "/api/b2b/orders",
    "/b2b/orders",
)

# Pure-arithmetic IIFE: defines a function and immediately calls it.
# We pick 7 * 191 because 1337 is large, distinctive, and appears
# nowhere in normal API JSON.
PROBE_PAYLOAD = "(function(){return 7*191})()"
PROBE_RESULT  = "1337"


class DeserializationB2bEvalProbe(Probe):
    name = "deserialization_b2b_eval"
    summary = ("Detects B2B/bulk endpoints that evaluate user-controlled "
               "JavaScript via Node's `vm` module.")
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
            # We accept any status — even a 5xx with the result in the
            # body is proof the eval ran. Some servers rewrap the
            # result inside an error envelope.
            if r.body and PROBE_RESULT in r.text:
                row["eval_succeeded"] = True
                # Capture a snippet around the match
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
                summary=(f"Confirmed: server at {origin}{confirmed['path']} "
                         f"evaluates user-controlled JavaScript. The IIFE "
                         f"`{PROBE_PAYLOAD}` returned {PROBE_RESULT} in "
                         "the response — the server ran attacker code."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Replace the eval-style parser with a strict JSON "
                    "schema. If a DSL is genuinely required, evaluate "
                    "it through a properly-sandboxed interpreter (the "
                    "Node `vm` module is NOT a security boundary); "
                    "consider a pure-data DSL like JSON Logic or a "
                    "minimal arithmetic parser written by hand. Audit "
                    "logs from the exposure window for any orderLines-"
                    "Data payload that is not literal JSON — those are "
                    "candidate exploitation events."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: {len(attempts)} B2B unsafe-eval attempts "
                     f"on {origin}; no response contained the marker "
                     f"{PROBE_RESULT}."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DeserializationB2bEvalProbe().main()
