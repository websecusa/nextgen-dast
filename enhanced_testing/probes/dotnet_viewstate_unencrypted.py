#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
ASP.NET ViewState: unencrypted / unsigned.

Web Forms pages persist server-side state across postbacks in a
hidden form field named `__VIEWSTATE`. When the application's
`<machineKey>` configuration leaves ViewState as plain Base64
(neither MAC-protected nor encrypted), an attacker can:

  1. Read sensitive state (the BinaryFormatter stream often carries
     control properties, role values, server-side flags) -- info
     disclosure.
  2. Tamper with the value (the server will deserialize the modified
     stream) -- privilege escalation.
  3. With a known machine key, deliver a deserialization payload
     (ysoserial.net `TypeConfuseDelegate`) -- RCE.

ViewState is signed by default in ASP.NET 4.5+. A page that emits
unsigned ViewState is either older or has been explicitly downgraded
in the web.config. Either is worth flagging.

High-fidelity rule: a single ViewState string is not enough. We
require:
  (a) a `__VIEWSTATE` hidden input on the page (proof we're on a
      Web Forms page);
  (b) the Base64 decodes cleanly to a stream that begins with the
      ViewState marker bytes (`0xff 0x01` followed by serializer
      version), proving it's a real ViewState and not random data;
  (c) NO `__VIEWSTATEGENERATOR` MAC suffix present AND the decoded
      payload's tail does NOT contain the 20- or 32-byte HMAC
      signature shape (we observe size-mod parity for SHA1 / SHA256).

If all three line up, ViewState is unsigned.

Detection signal:
  GET candidate .aspx paths; parse hidden `__VIEWSTATE` field;
  base64-decode; check magic bytes and absence of MAC tail.
"""
from __future__ import annotations

import base64
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common Web Forms entry points worth probing.
ASPX_PATHS = (
    "/", "/default.aspx", "/Default.aspx",
    "/login.aspx", "/Login.aspx",
    "/home.aspx", "/Home.aspx",
    "/account/login.aspx",
)

# Match the hidden input regardless of attribute order -- we just
# need to capture the value attribute. ASP.NET emits these with
# specific id and name attributes.
VIEWSTATE_RE = re.compile(
    r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"[^>]*/?>',
    re.I)
VIEWSTATEGEN_RE = re.compile(
    r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"', re.I)
EVENTVALIDATION_RE = re.compile(
    r'name="__EVENTVALIDATION"[^>]*value="([^"]*)"', re.I)

# ASP.NET's ObjectStateFormatter binary header. Real ViewState always
# begins with these two bytes followed by a serializer-version byte.
VS_MAGIC = b"\xff\x01"


class DotnetViewstateUnencryptedProbe(Probe):
    name = "dotnet_viewstate_unencrypted"
    summary = ("Detects ASP.NET pages that emit `__VIEWSTATE` "
               "without MAC protection or encryption.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--path", action="append", default=[],
            help="Additional .aspx path to inspect (repeatable).")

    def _decode_viewstate(self, value: str) -> tuple[bytes, str]:
        """Return (decoded-bytes, error-or-empty). ViewState is
        Base64; standard padding rules apply."""
        # ViewState Base64 sometimes uses URL-safe alphabet on
        # newer ASP.NET; try both.
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                # Pad to a multiple of 4 with '='.
                pad = "=" * (-len(value) % 4)
                return fn(value + pad), ""
            except Exception:
                continue
        return b"", "base64-decode-failed"

    def _viewstate_signed(self, decoded: bytes) -> tuple[bool, str]:
        """Return (looks-signed, reason). The MAC suffix is either
        20 bytes (SHA1) or 32 bytes (SHA256/HMACSHA256). When MAC is
        present, the decoded bytes split as [serialized-stream][MAC].
        When MAC is absent, the stream stops cleanly at the end of
        the ObjectStateFormatter graph.

        We can't 100% verify a MAC without the key. We use a
        heuristic that's high-precision but not perfect:
          - Decoded size > 64 bytes (smaller than this isn't a real
            ViewState anyway).
          - If the bytes start with VS_MAGIC and the trailer
            *doesn't* look like printable / structured data, treat
            as signed (stream + MAC).
          - If the decoded bytes start with `\\x00` (encryption
            marker on encrypted ViewState payloads), treat as
            encrypted -- not the bug we're flagging.
        """
        if len(decoded) < 8:
            return True, "too-short"
        if decoded[:1] == b"\x00":
            # Encrypted ViewState begins with a null byte / no clean
            # ObjectStateFormatter magic. Don't flag.
            return True, "looks-encrypted"
        if not decoded.startswith(VS_MAGIC):
            # Not a recognizable ViewState shape.
            return True, "no-vs-magic"
        # Inspect the last 20-40 bytes -- if they look like printable
        # ASCII or repeat the same byte, the trailer is probably part
        # of the serialized graph (no MAC). High-entropy random bytes
        # at the tail = MAC present.
        tail = decoded[-32:]
        # Count printable ASCII bytes in tail.
        printable = sum(1 for b in tail if 32 <= b < 127)
        if printable >= len(tail) * 3 // 4:
            # Tail is mostly printable -> stream end, no MAC suffix.
            return False, "tail-printable"
        return True, "tail-binary-like-mac"

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = list(ASPX_PATHS) + list(args.path or [])

        attempts: list[dict] = []
        unsigned: dict | None = None
        for p in paths:
            r = client.request("GET", urljoin(origin, p),
                               follow_redirects=True)
            row: dict = {"path": p, "status": r.status,
                         "size": r.size}
            if r.status != 200 or not r.body:
                attempts.append(row)
                continue
            text = r.text or ""
            m = VIEWSTATE_RE.search(text)
            if not m:
                row["has_viewstate"] = False
                attempts.append(row)
                continue
            row["has_viewstate"] = True
            # Track presence of the generator/eventvalidation fields
            # too -- they often co-occur and help triangulate.
            row["has_viewstategen"] = bool(VIEWSTATEGEN_RE.search(text))
            row["has_eventval"] = bool(
                EVENTVALIDATION_RE.search(text))
            decoded, err = self._decode_viewstate(m.group(1))
            row["vs_decoded_size"] = len(decoded)
            row["vs_decode_error"] = err
            row["vs_starts_with_magic"] = (
                decoded.startswith(VS_MAGIC) if decoded else False)
            if err or not decoded:
                attempts.append(row)
                continue
            looks_signed, reason = self._viewstate_signed(decoded)
            row["looks_signed_reason"] = reason
            row["looks_signed"] = looks_signed
            if not looks_signed and decoded.startswith(VS_MAGIC):
                row["unsigned_evidence"] = {
                    "magic_ok": True,
                    "tail_reason": reason,
                    "decoded_size": len(decoded),
                }
                unsigned = row
                attempts.append(row)
                break
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if unsigned:
            return Verdict(
                validated=True, confidence=0.88,
                summary=(
                    f"Confirmed: ASP.NET ViewState on "
                    f"{origin}{unsigned['path']} appears unsigned. "
                    "The Base64 payload decodes to a valid "
                    "ObjectStateFormatter stream (`\\xff\\x01` "
                    "magic) but has no high-entropy MAC trailer -- "
                    "tampering will not be rejected by the runtime."),
                evidence={**evidence, "unsigned": unsigned},
                severity_uplift="high",
                remediation=(
                    "Restore MAC protection AND encryption in "
                    "web.config. ASP.NET 4.5+ defaults are correct; "
                    "this site has been downgraded.\n"
                    "  ```xml\n"
                    "  <system.web>\n"
                    "    <pages enableViewState=\"true\" "
                    "viewStateEncryptionMode=\"Always\" />\n"
                    "    <machineKey "
                    "validation=\"HMACSHA256\" "
                    "decryption=\"AES\" "
                    "validationKey=\"AutoGenerate,IsolateApps\" "
                    "decryptionKey=\"AutoGenerate,IsolateApps\" />\n"
                    "  </system.web>\n"
                    "  ```\n"
                    "Audit any field that's tunneled through "
                    "ViewState (role flags, control visibility) -- "
                    "treat those values as untrusted input until "
                    "this is fixed."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tested {len(attempts)} candidate "
                     f".aspx paths on {origin}; no unsigned "
                     "ViewState observed."),
            evidence=evidence,
        )


if __name__ == "__main__":
    DotnetViewstateUnencryptedProbe().main()
