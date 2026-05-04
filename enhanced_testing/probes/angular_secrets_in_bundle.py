#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Frontend bundle leaks cloud / API secrets.

Modern SPA build pipelines (Angular's `environment.ts`, React's
`process.env.REACT_APP_*`, Vue's `import.meta.env.VITE_*`)
inline whatever environment values were present at build time
into the JS bundle. Teams routinely commit production API keys,
service-account secrets, Firebase configs, GitHub PATs, Slack
webhooks into these files; the build then ships them to every
visitor's browser.

The bug is platform-agnostic -- any framework that emits a JS
bundle does it. We sweep the homepage's `<script>` tags, fetch
each bundle, and pattern-match against well-known secret shapes.
The match is structural (regex), not heuristic.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Each pattern is a (regex, label, severity_hint) triple.
# Patterns are deliberately strict so we don't false-positive on
# random base64 strings -- the leading prefix is the
# discriminator.
PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS Access Key ID"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"),
     "AWS STS Session Token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API Key"),
    (re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
     "Stripe Secret Key"),
    (re.compile(r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
     "Stripe Restricted Key"),
    (re.compile(r"\bgh[opusr]_[A-Za-z0-9]{36}\b"),
     "GitHub Personal Access Token"),
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/"
                 r"B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
     "Slack Incoming Webhook"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
     "Slack OAuth / API token"),
    (re.compile(r"https://api\.telegram\.org/bot\d{6,}:[A-Za-z0-9_-]{30,}"),
     "Telegram Bot Token URL"),
    (re.compile(r'"apiKey"\s*:\s*"AIza[0-9A-Za-z_\-]{35}".+'
                 r'"authDomain"\s*:\s*"[^"]+\.firebaseapp\.com"'),
     "Firebase config block (apiKey + authDomain)"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
     "SendGrid API Key"),
    (re.compile(r"\bSK[a-f0-9]{32}\b"),
     "Twilio API Key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Embedded private key"),
)

SCRIPT_RE = re.compile(r'<script[^>]+src\s*=\s*"([^"]+\.js[^"]*)"',
                        re.I)


class AngularSecretsInBundleProbe(Probe):
    name = "angular_secrets_in_bundle"
    summary = ("Detects cloud / API secrets embedded in frontend JS "
               "bundles via the build's environment-inlining "
               "pipeline.")
    safety_class = "read-only"

    def add_args(self, parser):
        parser.add_argument(
            "--bundle", action="append", default=[],
            help="Additional bundle URL/path to scan.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        r = client.request("GET", urljoin(origin, "/"))
        bundles: list[str] = []
        if r.status == 200 and r.body:
            bundles.extend(SCRIPT_RE.findall(r.text or ""))
        bundles += list(args.bundle or [])
        bundles = [(b if b.startswith(("http://", "https://"))
                    else urljoin(origin, b)) for b in bundles[:10]]

        attempts: list[dict] = []
        confirmed: list[dict] = []
        for url in bundles:
            rb = client.request("GET", url)
            row: dict = {"bundle": url, "status": rb.status,
                         "size": rb.size}
            if rb.status == 200 and rb.body:
                text = rb.text or ""
                hits: list[dict] = []
                for pat, label in PATTERNS:
                    m = pat.search(text)
                    if m:
                        # Mask the value -- never print the secret
                        # in full to log files.
                        val = m.group(0)
                        masked = (val[:6] + "*" * max(0, len(val) - 10)
                                  + val[-4:]) if len(val) > 12 else val
                        hits.append({"kind": label,
                                      "value_excerpt": masked})
                if hits:
                    row["hits"] = hits
                    confirmed.append(row)
                    attempts.append(row)
                    if len(confirmed) >= 3:
                        break
                    continue
            attempts.append(row)

        evidence = {"origin": origin, "attempts": attempts}
        if confirmed:
            top = confirmed[0]
            sample = top["hits"][0]
            return Verdict(
                validated=True, confidence=0.95,
                summary=(
                    f"Confirmed: secret in JS bundle at "
                    f"{top['bundle']}. Found {sample['kind']} "
                    f"(masked: {sample['value_excerpt']}). "
                    f"{len(confirmed)} bundle(s) leak in total."),
                evidence={**evidence, "confirmed": confirmed},
                severity_uplift="critical",
                remediation=(
                    "Treat the secret as compromised: rotate it "
                    "immediately, then audit the cloud provider's "
                    "audit log for unauthorised use during the "
                    "exposure window.\n"
                    "Pipeline fix:\n"
                    "  - Move secrets out of the build-time env "
                    "(`environment.prod.ts`, `process.env.REACT_APP_*`, "
                    "`import.meta.env.VITE_*`). The browser should "
                    "call your backend, which proxies the call with "
                    "the secret it holds privately.\n"
                    "  - Add a CI-time secret scanner (gitleaks, "
                    "trufflehog) on the built bundle as a release-"
                    "gate; refuse to ship a build that contains a "
                    "matching pattern."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: scanned {len(attempts)} bundles on "
                     f"{origin}; no known secret patterns matched."),
            evidence=evidence,
        )


if __name__ == "__main__":
    AngularSecretsInBundleProbe().main()
