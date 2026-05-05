#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: subscription / feature-flag tier honored from a
client-controlled header or query parameter.

Some apps split "free" and "premium" features at the edge by reading
an internal header (`X-Feature-Flags`, `X-Subscription`,
`X-Account-Tier`, `X-User-Plan`) that an upstream proxy is supposed
to populate based on the authenticated subject. When the same header
is reachable from the public internet (the proxy doesn't strip it,
or the application is reachable directly), a free user can flip
themselves to premium by sending the header themselves.

The same thing happens with query parameters used as a debug/dev
override (`?subscription=premium`, `?tier=enterprise`,
`?feature_flags=premium`).

This probe creates a fresh free account, gathers a baseline
"premium-shaped" response (or 402/403 rejection), then re-runs the
same request with each of the override headers / parameters set. We
require BOTH a baseline NEGATIVE outcome (clear restriction) and a
post-override POSITIVE outcome (premium-shaped success) to validate.

Detection signal:
  Validated=True only when:
    1. Baseline request without the header was 402/403/200-but-not-
       premium, AND
    2. Same request with the override header / param returned a
       premium-shaped body (status 200 + a recognizable tier marker
       in the body).
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Endpoints that ARE typically tier-gated. We sweep until one
# returns a 4xx (clear gate) for the free account.
GATED_PATHS = (
    "/api/premium/features",
    "/api/feature/premium",
    "/api/subscription/status",
    "/api/account/tier",
    "/api/users/me/premium",
    "/api/billing/plan",
    "/rest/membership",
    "/rest/deluxe-membership",
)

# Header / param spoofs we test. The header set + the query param
# set are sent as one request each (we cycle through them).
OVERRIDE_HEADERS = [
    {"X-Feature-Flags": "premium=true"},
    {"X-Subscription": "premium"},
    {"X-Account-Tier": "enterprise"},
    {"X-User-Plan": "premium"},
    {"X-User-Role": "premium"},
]
OVERRIDE_QUERIES = (
    "?subscription=premium",
    "?tier=enterprise",
    "?feature_flags=premium",
    "?plan=premium",
)

# Strings that, when present in the response body, count as a
# "premium tier" marker. Anchored / surrounded so we don't match a
# random literal in unrelated payload text.
PREMIUM_PATTERNS = (
    re.compile(r'"(?:tier|plan|subscription)"\s*:\s*"(?:premium|enterprise|deluxe|pro)"', re.I),
    re.compile(r'"isPremium"\s*:\s*true', re.I),
    re.compile(r'"premium(?:Member|User)?"\s*:\s*true', re.I),
    re.compile(r'"(?:features|entitlements)"\s*:\s*\[[^\]]*"premium"', re.I),
)


def _register_and_login(client: SafeClient, origin: str) -> dict:
    email = f"feat-{secrets.token_hex(6)}@dast.test"
    pw = "Pr0be-" + secrets.token_hex(4)
    out: dict = {"email": email, "password": pw, "token": None}
    body = json.dumps({"email": email, "password": pw,
                       "passwordRepeat": pw,
                       "securityQuestion": {"id": 1},
                       "securityAnswer": "probe"}).encode()
    r = client.request("POST", urljoin(origin, "/api/Users"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["register_status"] = r.status
    body = json.dumps({"email": email, "password": pw}).encode()
    r = client.request("POST", urljoin(origin, "/rest/user/login"),
                       headers={"Content-Type": "application/json"},
                       body=body)
    out["login_status"] = r.status
    if r.status == 200 and r.body:
        try:
            doc = json.loads(r.text) or {}
            auth = doc.get("authentication") or {}
            out["token"] = auth.get("token")
        except json.JSONDecodeError:
            pass
    return out


def _looks_premium(text: str) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in PREMIUM_PATTERNS)


class BizLogicSubscriptionFeatureFlagHeaderProbe(Probe):
    name = "bizlogic_subscription_feature_flag_header"
    summary = ("Detects tier-gating that trusts a client-controlled "
               "feature-flag header / query parameter — a free user "
               "can self-elevate to premium.")
    safety_class = "read-only"

    def add_args(self, parser):
        # No probe-specific args; sweeps a small fixed candidate set.
        pass

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=(f"Inconclusive: free-tier probe account could "
                         f"not be created on {origin}."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]
        auth_h = {"Authorization": f"Bearer {token}"}

        # ---- Phase 1: locate a gated endpoint ----
        # We want a path that, for our brand-new free user, returns
        # 4xx OR a 200 response that does NOT look premium. If no
        # candidate behaves that way, the gating either lives
        # somewhere we can't see or doesn't exist on this origin.
        gated_path = ""
        baseline_status = 0
        baseline_body = ""
        baseline_premium = False
        for path in GATED_PATHS:
            r = client.request("GET", urljoin(origin, path), headers=auth_h)
            if r.status == 404:
                continue
            premium = _looks_premium(r.text or "")
            # A 4xx is the cleanest gate; a 200 that ALREADY looks
            # premium can't tell us anything (we're already inside).
            # 200 + non-premium is the next cleanest case.
            if r.status in (401, 402, 403) or (r.status == 200 and not premium):
                gated_path = path
                baseline_status = r.status
                baseline_body = (r.text or "")[:200]
                baseline_premium = premium
                break
        if not gated_path:
            return Verdict(
                validated=False, confidence=0.85,
                summary=(f"Refuted: no observable tier-gated endpoint "
                         f"on {origin}."),
                evidence={"origin": origin, "tried": list(GATED_PATHS)},
            )

        # ---- Phase 2: try each override header on the gated path ----
        successful_overrides: list[dict] = []
        attempts: list[dict] = []
        full_url = urljoin(origin, gated_path)

        for header_set in OVERRIDE_HEADERS:
            headers = dict(auth_h)
            headers.update(header_set)
            r = client.request("GET", full_url, headers=headers)
            premium = _looks_premium(r.text or "")
            entry = {"override": header_set, "status": r.status,
                     "premium_shaped": premium,
                     "body_excerpt": (r.text or "")[:200]}
            attempts.append(entry)
            if r.status == 200 and premium and not baseline_premium:
                successful_overrides.append(entry)

        # ---- Phase 3: query-param overrides ----
        for q in OVERRIDE_QUERIES:
            url_q = full_url + q
            r = client.request("GET", url_q, headers=auth_h)
            premium = _looks_premium(r.text or "")
            entry = {"override": q, "status": r.status,
                     "premium_shaped": premium,
                     "body_excerpt": (r.text or "")[:200]}
            attempts.append(entry)
            if r.status == 200 and premium and not baseline_premium:
                successful_overrides.append(entry)

        evidence = {"origin": origin, "endpoint": gated_path,
                    "baseline_status": baseline_status,
                    "baseline_body_excerpt": baseline_body,
                    "baseline_premium_shaped": baseline_premium,
                    "attempts": attempts,
                    "session_email": sess.get("email")}

        # Validation requires:
        #   - baseline was non-premium (gating IS in place), AND
        #   - at least one override flipped to premium-shaped 200.
        if not baseline_premium and successful_overrides:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: tier gate on {origin}{gated_path} "
                         "honors a client-controlled override. Free "
                         f"account was elevated to premium via "
                         f"{successful_overrides[0]['override']!r} — "
                         "baseline status "
                         f"{baseline_status} → 200 premium."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Tier checks MUST consult the server's "
                    "authoritative subscription record (DB / billing "
                    "system) keyed on the authenticated subject — "
                    "never on a request header or query parameter.\n"
                    "  - Strip the override headers at the edge proxy "
                    "BEFORE they reach the application.\n"
                    "  - Remove debug/dev query-param overrides from "
                    "the production build entirely; no `if (req.query"
                    ".feature_flags) ...` branches in prod code paths."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: tier-gate header/param overrides did "
                     f"not flip the response on {origin}{gated_path} "
                     f"(baseline_premium={baseline_premium}, "
                     f"successful_overrides={len(successful_overrides)})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicSubscriptionFeatureFlagHeaderProbe().main()
