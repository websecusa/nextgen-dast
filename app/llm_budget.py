# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Shared per-assessment LLM dollar accountant.

Before Round 5 every LLM consumer (enhanced_ai, agentic_ai, enrichment,
consolidation) tracked its own spend, or didn't track at all. The
agentic pass in particular bounded itself only by HTTP-request count
and turn count -- it had no idea what its cap_usd was. Result: a $50
per-assessment cap could be silently exceeded if the agent burned its
budget on a single round, leaving nothing for the consolidation roll-
up and enrichment to round out the assessment.

This module is the one place that knows:
  - the assessment's USD cap (from assessments.enhanced_ai_budget_usd
    or the system-default config row)
  - the reservation kept aside for downstream-critical passes
    (consolidation + per-finding enrichment) so the agent can't
    starve them
  - the live running total across every pass on this assessment

Reservation rule (hybrid floor + percentage):
  reserved = max(RESERVED_USD_FLOOR, RESERVED_PCT * cap)
Default floor $2.50, default percentage 10%. Both env-overridable
(NEXTGEN_DAST_LLM_RESERVED_USD_FLOOR, NEXTGEN_DAST_LLM_RESERVED_PCT)
so ops can tune without rebuilding.

Why these defaults:
  - $2.50 covers roughly one consolidation summary (~$0.05) plus
    enrichment for ~50 unenriched findings at typical Sonnet-class
    pricing. Bounded headroom for the closing passes regardless of
    how big the agent run got.
  - 10% scales naturally with budget size. A $500 cap reserves $50
    of headroom -- proportional to the larger enrichment surface a
    big assessment typically produces.
  - max(floor, pct) means the floor protects small budgets where 10%
    would be too thin to cover even one consolidation call.

Policy for the four LLM consumers:

  enhanced_ai_testing   -- runs against `effective_cap_for_pass()`
                           which subtracts the reservation. Its own
                           in-class trip check stops it cleanly when
                           the slice is exhausted.
  agentic_ai_testing    -- same `effective_cap_for_pass()` slice.
                           Per-turn check at the top of the loop
                           bails out gracefully when the next
                           expected turn would push past the slice.
                           The agent emits a `budget_exhausted`
                           rationale instead of looping until the
                           HTTP cap.
  enrichment            -- ALWAYS runs while cap allows; logs a
                           warning + still proceeds if it would push
                           past the cap. Critical for finding
                           readability; an extra $1 of overrun beats
                           an assessment with stub remediation rows.
  consolidation         -- ALWAYS runs (one call, ~$0.05). Same
                           policy: logs a warning if over the cap,
                           does not block.

Implementation: a single in-process `dict[assessment_id, BudgetState]`
keyed by aid. Each LLM consumer calls `record(aid, in_t, out_t, model)`
after every call; consumers that want to gate read `remaining(aid)`,
`remaining_for_pass(aid)`, or `would_exhaust_pass(aid, projected_cost)`.

Thread-safety: lookups + updates run under a module-level lock so
two passes on different threads (the orchestrator runs them
sequentially today, but assessments can overlap) don't corrupt the
accumulator.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional

import db
import llm as llm_mod

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables (env-overridable)
# ---------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    """Read a float from the environment, falling back to default on
    missing / malformed values. Logs a warning so a typo doesn't go
    silent."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("llm_budget: ignoring malformed %s=%r, using %s",
                       name, raw, default)
        return default


# Minimum USD held back for downstream passes (consolidation +
# enrichment) regardless of how small the per-assessment cap is.
# Bounded headroom that protects the closing passes when the agent
# would otherwise eat into them.
RESERVED_USD_FLOOR = _env_float("NEXTGEN_DAST_LLM_RESERVED_USD_FLOOR", 2.50)

# Percentage of the per-assessment cap reserved for downstream
# passes. Scales with budget size so larger assessments
# automatically reserve proportionally more.
RESERVED_PCT = _env_float("NEXTGEN_DAST_LLM_RESERVED_PCT", 0.10)


# ---------------------------------------------------------------------------
# Per-assessment accumulator
# ---------------------------------------------------------------------------

class BudgetState:
    """Per-assessment LLM dollar accountant.

    Fields:
      aid          assessment id this accumulator belongs to
      cap_usd      hard upper bound; None = uncapped
      spent_usd    cumulative cost across every LLM consumer
      tripped      True once a consumer has been told to stop (the
                   in-class gate fires once and downstream passes
                   short-circuit on it)
      reservation  amount held back from the agentic pass / weakness
                   pass to keep consolidation + enrichment well-fed
    """
    def __init__(self, aid: int, cap_usd: Optional[float]):
        self.aid = int(aid)
        self.cap_usd: Optional[float] = (float(cap_usd)
                                          if cap_usd is not None else None)
        self.spent: float = 0.0
        self.tripped: bool = False
        self.reservation: float = compute_reservation(self.cap_usd)

    def add(self, cost: float) -> None:
        self.spent += float(cost or 0.0)

    def remaining(self) -> Optional[float]:
        if self.cap_usd is None:
            return None
        return max(0.0, float(self.cap_usd) - self.spent)

    def remaining_for_pass(self) -> Optional[float]:
        """Remaining USD a budget-gated pass (agentic, weakness) can
        spend. Subtracts the reservation so the closing passes
        always have headroom. Returns None when uncapped."""
        rem = self.remaining()
        if rem is None:
            return None
        return max(0.0, rem - self.reservation)

    def would_exhaust_pass(self, projected_cost: float) -> bool:
        """True iff one more call of `projected_cost` would push the
        pass over its slice. Always False when uncapped."""
        rfp = self.remaining_for_pass()
        if rfp is None:
            return False
        return projected_cost >= rfp

    def trip(self) -> None:
        self.tripped = True

    def to_dict(self) -> dict:
        return {
            "aid": self.aid,
            "cap_usd": self.cap_usd,
            "spent_usd": round(self.spent, 6),
            "remaining_usd": (round(self.remaining(), 6)
                              if self.cap_usd is not None else None),
            "remaining_for_pass_usd": (
                round(self.remaining_for_pass(), 6)
                if self.cap_usd is not None else None),
            "reservation_usd": round(self.reservation, 6),
            "tripped": self.tripped,
        }


def compute_reservation(cap_usd: Optional[float]) -> float:
    """Apply the hybrid floor+percentage rule. None cap -> 0
    reservation (uncapped budgets don't need a reservation since
    nothing can starve nothing)."""
    if cap_usd is None:
        return 0.0
    floor = max(0.0, RESERVED_USD_FLOOR)
    pct_share = max(0.0, RESERVED_PCT * float(cap_usd))
    return max(floor, pct_share)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_registry: dict[int, BudgetState] = {}


def _resolve_cap(aid: int) -> Optional[float]:
    """Per-assessment cap precedence:
      1. assessments.enhanced_ai_budget_usd (admin-supplied for this scan)
      2. config['advanced_ai_budget_default_usd'] (system default)
      3. None (uncapped; only happens on a fresh DB before the seed
         insert lands).
    """
    a = db.query_one(
        "SELECT enhanced_ai_budget_usd FROM assessments WHERE id=%s",
        (aid,))
    if a and a.get("enhanced_ai_budget_usd") is not None:
        try:
            return float(a["enhanced_ai_budget_usd"])
        except (TypeError, ValueError):
            pass
    row = db.query_one(
        "SELECT value FROM config "
        "WHERE `key`='advanced_ai_budget_default_usd'")
    if row and row.get("value"):
        try:
            return float(row["value"])
        except (TypeError, ValueError):
            return None
    return None


def get(aid: int) -> BudgetState:
    """Look up (and create on first miss) the budget accumulator for
    an assessment. Idempotent -- repeat calls within the same scan
    return the same object so per-call cost adds accumulate
    correctly."""
    with _lock:
        state = _registry.get(int(aid))
        if state is None:
            state = BudgetState(aid, _resolve_cap(aid))
            _registry[int(aid)] = state
        return state


def reset(aid: int) -> None:
    """Drop the cached accumulator. Used by tests and by the
    orchestrator when an assessment is restarted from scratch."""
    with _lock:
        _registry.pop(int(aid), None)


def record(aid: int, *, in_tokens: int, out_tokens: int,
           model: str, cached_in_tokens: int = 0) -> float:
    """Record an LLM call's cost against the assessment's accumulator
    and return the cost (so callers can also store it on per-call
    rows without recomputing). Always succeeds; the accumulator's
    `tripped` flag is set by callers that want to gate, not by this
    function."""
    c = llm_mod.cost(in_tokens, out_tokens, model, cached_in_tokens)
    state = get(aid)
    state.add(c)
    return c


# ---------------------------------------------------------------------------
# Cost projection
# ---------------------------------------------------------------------------

# Best-effort cost projection for "one more agentic turn." Used by the
# per-turn guard so the loop can exit cleanly before the next call
# rather than running it and noticing afterward that we overshot.
# Conservative: assume the LLM hits max_tokens on output and a
# moderate input size; the real cost is usually lower.
def project_turn_cost(model: str, *, in_tokens_estimate: int = 2000,
                       out_tokens_estimate: int = 2048) -> float:
    """Estimate the USD cost of one not-yet-issued LLM turn. Used by
    `would_exhaust_pass()` checks at the top of an agent loop. Tuned
    to slightly overestimate so the guard fires before a runaway
    call rather than after."""
    return llm_mod.cost(in_tokens_estimate, out_tokens_estimate, model)


# ---------------------------------------------------------------------------
# Soft-warning helpers
# ---------------------------------------------------------------------------

def warn_if_over_cap(aid: int, *, context: str) -> None:
    """Emit a single log line when cumulative spend has pushed past
    the cap. Called by consolidation + enrichment which always run
    regardless of cap (their work is critical for assessment
    readability) but should leave a breadcrumb when they overrun.
    No-op when uncapped or still within cap."""
    state = get(aid)
    if state.cap_usd is None:
        return
    if state.spent <= state.cap_usd:
        return
    overrun = state.spent - state.cap_usd
    logger.warning(
        "llm_budget: aid=%s cap=$%.2f spent=$%.4f overrun=$%.4f context=%s "
        "(consolidation/enrichment ran anyway -- their work is critical "
        "for the assessment to be readable)",
        aid, state.cap_usd, state.spent, overrun, context)
