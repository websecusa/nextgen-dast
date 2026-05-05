#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Spring Boot Actuator: management endpoints exposed to anonymous
callers.

Spring Boot Actuator surfaces a per-app /management API (default
prefix `/actuator`, sometimes `/` on legacy Spring Boot 1.x). Each
endpoint is high-fidelity in what it returns:

  - `/actuator`              -- HAL JSON listing of every available
                                endpoint (tells you exactly what
                                else is exposed).
  - `/actuator/env`          -- every Spring environment property
                                including DB strings, secret-keys,
                                cloud creds.
  - `/actuator/configprops`  -- every @ConfigurationProperties bean,
                                similar leak surface.
  - `/actuator/heapdump`     -- the entire JVM heap (literal
                                gigabytes; HTTP HEAD only).
  - `/actuator/threaddump`   -- every running thread's stack frames
                                + locals (active credentials end up
                                in here on any framework that
                                propagates them via thread-locals).
  - Spring Boot 1.x          -- `/env`, `/trace`, `/dump`,
                                `/configprops` at the root.

The neighboring probe `info_diagnostic_endpoints_exposed` covers a
generic sweep including a few of these. This probe is the focused,
high-fidelity Actuator-only version that produces a sharper finding
when Actuator is the actual hit -- it inspects more endpoints and
distinguishes Spring Boot 1.x from 2.x+ exposure.

High-fidelity rule: status 200 + Spring-shaped body. Specifically:
  - `/actuator` listing must contain `_links` JSON + at least one
    href under that.
  - `/actuator/env` must contain the property-source structure
    (`activeProfiles` + `propertySources`).
  - `/actuator/configprops` must contain `contexts` + a property
    bean shape.
  - For `/actuator/heapdump` we use HEAD (never GET) and validate
    via `Content-Type: application/octet-stream` AND a
    Content-Disposition that contains "heapdump".

Detection signal:
  Per-endpoint structural match. A bare 200 is never enough.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, http-method, validator, label, severity-hint)
# validator is a callable: (response) -> bool
# We deliberately use HEAD on heapdump so we never download MB.

LINKS_RE = re.compile(r'"_links"\s*:\s*\{')
HREF_RE = re.compile(r'"href"\s*:\s*"https?://')
ACT_ENV_RE = re.compile(
    r'"(?:activeProfiles|propertySources)"\s*:')
ACT_CONFIGPROPS_RE = re.compile(
    r'"contexts"\s*:\s*\{|"prefix"\s*:\s*"')
ACT_THREADDUMP_RE = re.compile(
    r'"threads"\s*:\s*\[|"threadName"\s*:')
SB1_ENV_RE = re.compile(r'"systemProperties"\s*:\s*\{|"profiles"\s*:')
SB1_TRACE_RE = re.compile(r'"timestamp"\s*:\s*\d+\s*,\s*"info"\s*:')


def _hdr(headers: dict, name: str) -> str:
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return ""


def _is_actuator_root(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    text = r.text or ""
    # Two markers required: top-level _links AND at least one href
    # value pointing at an http(s) URL inside the JSON.
    if not LINKS_RE.search(text):
        return False
    if not HREF_RE.search(text):
        return False
    # Confirm it parses as JSON.
    try:
        json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return False
    return True


def _is_actuator_env(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    return bool(ACT_ENV_RE.search(r.text or ""))


def _is_actuator_configprops(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    return bool(ACT_CONFIGPROPS_RE.search(r.text or ""))


def _is_actuator_threaddump(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    return bool(ACT_THREADDUMP_RE.search(r.text or ""))


def _is_actuator_heapdump_head(r) -> bool:
    """HEAD-based check -- we never download a heapdump."""
    if r.status != 200:
        return False
    ctype = _hdr(r.headers, "Content-Type").lower()
    cdisp = _hdr(r.headers, "Content-Disposition").lower()
    if "octet-stream" in ctype and ("heapdump" in cdisp
                                       or ".hprof" in cdisp):
        return True
    return False


def _is_sb1_env(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    return bool(SB1_ENV_RE.search(r.text or ""))


def _is_sb1_trace(r) -> bool:
    if r.status != 200 or not r.body:
        return False
    return bool(SB1_TRACE_RE.search(r.text or ""))


TARGETS = (
    ("GET",  "/actuator",                _is_actuator_root,
     "Actuator index (lists every exposed management endpoint)"),
    ("GET",  "/actuator/env",            _is_actuator_env,
     "Actuator env (every property / secret in the Spring env)"),
    ("GET",  "/actuator/configprops",    _is_actuator_configprops,
     "Actuator configprops (every @ConfigurationProperties bean)"),
    ("GET",  "/actuator/threaddump",     _is_actuator_threaddump,
     "Actuator threaddump (every running thread's stack)"),
    ("HEAD", "/actuator/heapdump",       _is_actuator_heapdump_head,
     "Actuator heapdump (the entire JVM heap)"),
    ("GET",  "/env",                     _is_sb1_env,
     "Spring Boot 1.x /env (root-prefix actuator)"),
    ("GET",  "/trace",                   _is_sb1_trace,
     "Spring Boot 1.x /trace (recent-request log)"),
)


class SpringActuatorExposedProbe(Probe):
    name = "spring_actuator_exposed"
    summary = ("Detects Spring Boot Actuator endpoints exposed to "
               "anonymous callers (env / configprops / heapdump / "
               "threaddump etc.).")
    safety_class = "read-only"

    def add_args(self, parser):
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for method, path, validator, label in TARGETS:
            r = client.request(method, urljoin(origin, path))
            row: dict = {"method": method, "path": path,
                         "status": r.status, "size": r.size,
                         "label": label}
            if validator(r):
                row["matched"] = True
                # Snippet for evidence on GET responses; HEAD has
                # no body so we record content-type instead.
                if method == "GET":
                    row["snippet"] = (r.text or "")[:200]
                else:
                    row["content_type"] = _hdr(
                        r.headers, "Content-Type")
                    row["content_disposition"] = _hdr(
                        r.headers, "Content-Disposition")
                confirmed.append(row)
                attempts.append(row)
                # Stop early once we have two confirmations -- the
                # finding is unambiguous and we want to respect the
                # request budget.
                if len(confirmed) >= 2:
                    break
                continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            # Heapdump / env / configprops are highest-severity hits.
            high_value_paths = (
                "/actuator/heapdump", "/actuator/env",
                "/actuator/configprops", "/env")
            severity = ("critical"
                        if any(c["path"] in high_value_paths
                               for c in confirmed)
                        else "high")
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: Spring Actuator exposed at "
                    f"{origin}{top['path']} ({top['label']}). "
                    f"{len(confirmed)} actuator endpoint(s) returned "
                    "Spring-shaped responses to anonymous "
                    "requests."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift=severity,
                remediation=(
                    "Restrict Actuator exposure. Spring Boot 2.x+ "
                    "default-allows only `/health` and `/info`; "
                    "anything else is opt-in.\n"
                    "  ```properties\n"
                    "  # application.properties\n"
                    "  management.endpoints.web.exposure.include=health,info\n"
                    "  # If you need richer endpoints internally, "
                    "bind a separate management port:\n"
                    "  management.server.port=8081\n"
                    "  management.server.address=127.0.0.1\n"
                    "  ```\n"
                    "Spring Boot 1.x: set "
                    "`management.security.enabled=true` and bind "
                    "behind authentication.\n"
                    "If `/actuator/heapdump` was reachable, treat "
                    "every secret in process memory as compromised "
                    "and rotate them. Audit access logs for "
                    "/actuator/* during the exposure window."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: probed {len(attempts)} actuator "
                     f"endpoint(s) on {origin}; none returned a "
                     "Spring-shaped response."),
            evidence=evidence,
        )


if __name__ == "__main__":
    SpringActuatorExposedProbe().main()
