# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Safety enforcement for validation probes.

Every outbound request a probe makes MUST go through `SafeClient` (in
http.py), which checks every request against an instance of `Budget`
constructed from these classes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlparse


class SafetyViolation(Exception):
    """Raised when a probe attempts a request that violates the active
    Budget (out of scope, over the request cap, destructive without
    permission, etc.)."""


@dataclass
class Budget:
    """Per-run safety budget. Constructed from probe config; every request
    consults it before being sent."""
    max_requests: int = 20
    max_rps: float = 1.0
    scope_hosts: Iterable[str] = field(default_factory=tuple)
    allow_destructive: bool = False
    dry_run: bool = False

    # runtime state
    _used: int = 0
    _last_send: float = 0.0

    def host_in_scope(self, url: str) -> bool:
        if not self.scope_hosts:
            # No scope set → permissive for ad-hoc CLI use. Orchestrator
            # always sets scope; humans running a probe directly are
            # presumed to know their target.
            return True
        host = (urlparse(url).hostname or "").lower()
        return any(host == s.lower() or host.endswith("." + s.lower())
                   for s in self.scope_hosts)

    def check_method(self, method: str) -> None:
        method = (method or "GET").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE") and not self.allow_destructive:
            raise SafetyViolation(
                f"{method} requests require --allow-destructive (refused for safety)"
            )

    def check_url(self, url: str) -> None:
        if not self.host_in_scope(url):
            raise SafetyViolation(
                f"URL {url} is outside the configured scope_hosts; refusing"
            )

    def consume_request(self) -> None:
        if self._used >= self.max_requests:
            raise SafetyViolation(
                f"request budget exhausted ({self.max_requests}); refusing"
            )
        # rate limit: sleep until the configured RPS window opens up
        if self.max_rps > 0:
            min_gap = 1.0 / self.max_rps
            now = time.monotonic()
            wait = self._last_send + min_gap - now
            if wait > 0:
                time.sleep(wait)
            self._last_send = time.monotonic()
        self._used += 1

    @property
    def used(self) -> int:
        return self._used


@dataclass
class AuditEntry:
    method: str
    url: str
    status: Optional[int]
    size: Optional[int]
    note: str = ""


class AuditLog:
    """Records every request a probe sends so the verdict can be replayed
    by a human auditor."""

    def __init__(self):
        self.entries: list[AuditEntry] = []

    def record(self, method: str, url: str,
               status: Optional[int] = None,
               size: Optional[int] = None,
               note: str = "") -> None:
        self.entries.append(AuditEntry(method, url, status, size, note))

    def to_json(self) -> list[dict]:
        return [
            {"method": e.method, "url": e.url, "status": e.status,
             "size": e.size, "note": e.note}
            for e in self.entries
        ]
