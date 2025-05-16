# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Common scaffolding so each probe is a thin subclass.

A new probe overrides:
  - `name` / `summary` / `safety_class`  (declarative metadata)
  - `add_args(parser)`                   (probe-specific argparse args)
  - `run(args, client)`                  (the actual logic; returns Verdict)

Everything else — the stdin/argv plumbing, JSON output, exit-code
discipline, audit-log emission — is handled here.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

from .http import SafeClient
from .safety import AuditLog, Budget, SafetyViolation


@dataclass
class Verdict:
    """Standardized return shape every probe produces."""
    ok: bool = True
    validated: Optional[bool] = None
    confidence: float = 0.0
    summary: str = ""
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    severity_uplift: Optional[str] = None
    error: Optional[str] = None


class Probe:
    name: str = "probe"
    summary: str = ""
    safety_class: str = "probe"   # read-only | probe | destructive

    # ----- subclass overrides -------------------------------------------

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """Declare probe-specific arguments. Common ones (--url, --param,
        --cookie, etc.) are added by `_base_parser` automatically."""

    def run(self, args, client: SafeClient) -> Verdict:
        """Probe-specific logic. Returns a Verdict."""
        raise NotImplementedError

    # ----- driver -------------------------------------------------------

    def _base_parser(self) -> argparse.ArgumentParser:
        p = argparse.ArgumentParser(
            prog=self.name,
            description=self.summary,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        p.add_argument("--stdin", action="store_true",
                       help="Read JSON config from stdin instead of CLI flags")
        p.add_argument("--url", help="Target URL")
        p.add_argument("--method", default="GET",
                       help="HTTP method (default GET)")
        p.add_argument("--param",
                       help="Parameter name to test (probe-specific use)")
        p.add_argument("--cookie", default="",
                       help="Cookie header value")
        p.add_argument("--header", action="append", default=[],
                       help="Extra header 'Name: value' (repeatable)")
        p.add_argument("--user-agent", default=None)
        p.add_argument("--proxy", default=None,
                       help="Send through this HTTP proxy URL")
        p.add_argument("--scope", action="append", default=[],
                       help="Scope host(s); refuses requests outside these "
                            "(repeatable). Empty = permissive.")
        p.add_argument("--max-requests", type=int, default=20)
        p.add_argument("--max-rps", type=float, default=1.0)
        p.add_argument("--allow-destructive", action="store_true")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--out", default="-",
                       help="Write JSON verdict here ('-' = stdout)")
        return p

    def _config_from_stdin(self, parser) -> argparse.Namespace:
        try:
            blob = json.loads(sys.stdin.read())
        except Exception as e:
            raise SystemExit(f"--stdin: invalid JSON ({e})")
        ns = parser.parse_args([])  # defaults
        for k, v in blob.items():
            if not hasattr(ns, k):
                # extra config goes onto an `extra` dict
                if not hasattr(ns, "extra"):
                    ns.extra = {}
                ns.extra[k] = v
                continue
            setattr(ns, k, v)
        # arrays/dict normalization
        ns.scope = list(blob.get("scope_hosts") or ns.scope or [])
        ns.header = list(ns.header or [])
        if "headers" in blob and isinstance(blob["headers"], dict):
            ns.header = [f"{k}: {v}" for k, v in blob["headers"].items()] + list(ns.header or [])
        return ns

    def _build_client(self, args) -> tuple[SafeClient, Budget, AuditLog]:
        budget = Budget(
            max_requests=int(args.max_requests),
            max_rps=float(args.max_rps),
            scope_hosts=tuple(args.scope or []),
            allow_destructive=bool(args.allow_destructive),
            dry_run=bool(args.dry_run),
        )
        audit = AuditLog()
        headers = {}
        for h in (args.header or []):
            if ":" in h:
                k, _, v = h.partition(":")
                headers[k.strip()] = v.strip()
        client = SafeClient(
            budget=budget, audit=audit,
            cookie=args.cookie or None,
            user_agent=args.user_agent,
            default_headers=headers,
            proxy=args.proxy,
        )
        return client, budget, audit

    def _emit(self, args, verdict: Verdict, audit: AuditLog,
              budget: Budget, exit_code: int) -> None:
        out = {
            "probe": self.name,
            "ok": verdict.ok,
            "validated": verdict.validated,
            "confidence": verdict.confidence,
            "summary": verdict.summary,
            "evidence": verdict.evidence,
            "remediation": verdict.remediation,
            "severity_uplift": verdict.severity_uplift,
            "error": verdict.error,
            "audit_log": audit.to_json(),
            "safety": {
                "requests_used": budget.used,
                "max_requests": budget.max_requests,
                "max_rps": budget.max_rps,
                "dry_run": budget.dry_run,
            },
        }
        text = json.dumps(out, indent=2, default=str)
        if args.out == "-":
            sys.stdout.write(text + "\n")
        else:
            with open(args.out, "w") as fh:
                fh.write(text)
        sys.exit(exit_code)

    def main(self) -> None:
        parser = self._base_parser()
        self.add_args(parser)
        args = parser.parse_args()
        if args.stdin:
            # Re-parse with the SAME parser using stdin JSON instead of argv.
            # _config_from_stdin already merges all known keys onto the
            # namespace; calling add_args again would duplicate-register.
            args = self._config_from_stdin(parser)

        if not args.url:
            print("error: --url is required (or `url` in --stdin JSON)", file=sys.stderr)
            sys.exit(2)

        client, budget, audit = self._build_client(args)
        try:
            verdict = self.run(args, client)
            self._emit(args, verdict, audit, budget, exit_code=0)
        except SafetyViolation as e:
            v = Verdict(ok=False, validated=None,
                        summary=f"safety violation: {e}", error=str(e))
            self._emit(args, v, audit, budget, exit_code=1)
        except Exception as e:
            v = Verdict(ok=False, validated=None,
                        summary=f"runtime error: {type(e).__name__}: {e}",
                        error=str(e))
            self._emit(args, v, audit, budget, exit_code=2)
