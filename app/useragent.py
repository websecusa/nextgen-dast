# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""User-Agent → per-scanner CLI flag mapping.

Centralized here so server.py and scripts/orchestrator.py emit identical
flags. testssl.sh is intentionally absent — TLS handshakes don't carry an
HTTP User-Agent header, so the option doesn't apply.
"""
from __future__ import annotations

from typing import Optional


def flags_for(tool: str, ua: Optional[str]) -> list[str]:
    if not ua:
        return []
    if tool == "wapiti":
        return ["-A", ua]
    if tool == "nikto":
        return ["-useragent", ua]
    if tool == "nuclei":
        return ["-H", f"User-Agent: {ua}"]
    if tool == "sqlmap":
        return ["--user-agent", ua]
    if tool == "dalfox":
        return ["--user-agent", ua]
    return []
