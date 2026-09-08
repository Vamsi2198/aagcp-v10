"""
aagcp/core/simulate.py — Phase 4. The junction between a plan and a
warehouse, and the only place in the loop that can say no on its own.

The forecast answers four questions about a Plan before anything runs:
how much is touched, who downstream depends on it, whether it can be
undone, and how much of that we actually measured rather than assumed.

Three rules govern what the answer is allowed to do:

  1. A clean forecast LOWERS the tier. It never authorises. Authorisation
     is a comparison between the tier and an autonomy budget somebody set
     in advance, plus a hard approval requirement for anything that cannot
     be undone. No amount of good news reaches past that.

  2. A forecast that could not complete is inconclusive. Every input is
     either MEASURED or UNMEASURED, and unmeasured inputs earn no credit
     and force approval. A dependency graph that could not be read is not
     a dependency graph that came back empty.

  3. Reversibility is asked of the executor, not inferred from the
     treatment. The compiler sets Operation.reversible from the treatment
     alone; the executor knows whether it can honestly reverse it on this
     engine. Where they disagree, the executor wins and the disagreement
     is recorded.

ON THE NUMBERS BELOW: the thresholds and the one-step credits in
TierRubric are a starting position, not a result. I did not derive them
from incident data and there is none to derive them from yet. They are
collected in one frozen object, versioned, and folded into the forecast
hash precisely so a customer can replace them and so any receipt says
which rubric produced it. Treat a tier as "what this rubric says",
never as "what the risk is".
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from .coverage import CoverageReport
from .plan import Operation, Plan

SIMULATE_VERSION = "simulate-1.0.0"


class RiskTier(IntEnum):
    LOW = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


class Measurement(str, Enum):
    """Two states here rather than three: a signal is either something we
    read or something we did not. Whether what we read was clean is a
    separate question, held in the signal's value."""
    MEASURED = "measured"
    UNMEASURED = "unmeasured"


class Decision(str, Enum):
    AUTONOMOUS = "AUTONOMOUS"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


# Cause codes for every approval requirement and every unmeasured signal.
CAUSE_IRREVERSIBLE = "IRREVERSIBLE_OPERATION"
CAUSE_REVERSIBILITY_UNPROVEN = "REVERSIBILITY_NOT_PROVEN"
CAUSE_TIER_EXCEEDS_BUDGET = "TIER_EXCEEDS_AUTONOMY_BUDGET"
CAUSE_FORECAST_INCOMPLETE = "FORECAST_INCOMPLETE"
CAUSE_GRAPH_UNAVAILABLE = "DEPENDENCY_GRAPH_UNAVAILABLE"
CAUSE_GRAPH_ERROR = "DEPENDENCY_GRAPH_ERROR"
CAUSE_ROWS_UNCOUNTED = "ROW_ESTIMATE_MISSING"
CAUSE_NO_EXECUTOR = "EXECUTOR_NOT_CONSULTED"
CAUSE_UNGOVERNED_COLUMNS = "UNGOVERNED_COLUMNS_IN_SCOPE"
CAUSE_COVERAGE_NOT_ASSESSED = "PHASE_0_COVERAGE_NOT_ASSESSED"
CAUSE_COVERAGE_PLAN_MISMATCH = "COVERAGE_REPORT_IS_FOR_A_DIFFERENT_PLAN"


# ---------------------------------------------------------------------
# Dependency graph. A protocol, not an implementation, because the real
# one is a catalog query and the control plane must never require it to
# be present in order to reach a safe answer.
# ---------------------------------------------------------------------

class DependencyGraph(Protocol):
    def consumers(self, object_fqn: str) -> Optional[List[str]]:
        """Direct dependents of one object. Return None — not [] — when the
        graph cannot answer for this object. The difference between 'nothing
        depends on this' and 'I could not find out' is the whole point."""
        ...


class StaticDependencyGraph:
    """In-memory edges, for tests and for catalogs already exported."""

    def __init__(self, edges: Dict[str, Sequence[str]], known: Sequence[str] = None):
        self.edges = {k: list(v) for k, v in edges.items()}
        # Objects the graph claims to know about. An object outside this set
        # gets None rather than [], because absence from an edge list is not
        # evidence of absence of dependents.
        self.known = set(known) if known is not None else set(self.edges)

    def consumers(self, object_fqn: str) -> Optional[List[str]]:
        if object_fqn not in self.known:
            return None
        return list(self.edges.get(object_fqn, []))


class NullDependencyGraph:
    """No catalog wired up. Answers nothing, honestly."""

    def consumers(self, object_fqn: str) -> Optional[List[str]]:
        return None


def _closure(graph: DependencyGraph, roots: Sequence[str]
             ) -> Tuple[Dict[str, List[str]], List[dict]]:
    """Transitive dependents, cycle-safe. Returns (per-root consumers,
    unmeasured entries). An object whose consumers cannot be read stops
    that branch and is reported."""
    resolved: Dict[str, List[str]] = {}
    unmeasured: List[dict] = []
    for root in sorted(roots):
        seen, frontier, out = {root}, [root], []
        while frontier:
            node = frontier.pop()
            try:
                kids = graph.consumers(node)
            except Exception as exc:              # a catalog that throws
                unmeasured.append({"object": node, "cause": CAUSE_GRAPH_ERROR,
                                   "detail": str(exc)})
                continue
            if kids is None:
                unmeasured.append({"object": node, "cause": CAUSE_GRAPH_UNAVAILABLE,
                                   "detail": "graph has no answer for this object"})
                continue
            for k in kids:
                if k not in seen:
                    seen.add(k)
                    out.append(k)
                    frontier.append(k)
        resolved[root] = sorted(out)
    return resolved, unmeasured


# ---------------------------------------------------------------------
# Rubric
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class TierRubric:
    version: str = "rubric-1.0.0"
    rows_high: int = 1_000_000
    rows_moderate: int = 10_000
    tables_high: int = 50
    tables_moderate: int = 10
    consumers_high: int = 20
    max_credits: int = 2          # a CRITICAL prior can fall to MODERATE, no further
    priors: Tuple[Tuple[str, int], ...] = (
        ("drop_column", RiskTier.CRITICAL),
        ("erase", RiskTier.CRITICAL),
        ("tokenize", RiskTier.MODERATE),
        ("apply_masking_policy", RiskTier.MODERATE),
    )
    unknown_op_prior: int = RiskTier.HIGH   # never guess low on an op we don't know

    def prior_for(self, op_name: str) -> RiskTier:
        for name, tier in self.priors:
            if name == op_name:
                return RiskTier(tier)
        return RiskTier(self.unknown_op_prior)

    def to_dict(self) -> dict:
        return {"version": self.version, "rows_high": self.rows_high,
                "rows_moderate": self.rows_moderate,
                "tables_high": self.tables_high,
                "tables_moderate": self.tables_moderate,
                "consumers_high": self.consumers_high,
                "max_credits": self.max_credits,
                "priors": [[n, int(t)] for n, t in self.priors],
                "unknown_op_prior": int(self.unknown_op_prior)}


DEFAULT_RUBRIC = TierRubric()


# ---------------------------------------------------------------------
# Signals and forecast
# ---------------------------------------------------------------------

@dataclass
class Signal:
    name: str
    measurement: Measurement
    value: object = None
    detail: str = ""
    cause: str = ""
    floor: Optional[RiskTier] = None    # minimum tier this signal imposes
    credit: bool = False                # measured and clean -> one step down

    def to_dict(self):
        return {"name": self.name, "measurement": self.measurement.value,
                "value": self.value, "detail": self.detail, "cause": self.cause,
                "floor": int(self.floor) if self.floor else None,
                "credit": self.credit}


@dataclass
class Forecast:
    plan_hash: str
    dialect: str
    columns_affected: int
    tables_affected: List[str]
    rows_estimate: int
    downstream: Dict[str, List[str]]
    downstream_unmeasured: List[dict]
    reversibility: List[dict]
    signals: List[Signal]
    prior_tier: RiskTier
    tier: RiskTier
    credits_applied: List[str]
    floors_applied: List[dict]
    decision: Decision
    approval_reasons: List[dict]
    budget: RiskTier
    rubric: dict
    version: str = SIMULATE_VERSION

    # ---- rollups ---------------------------------------------------
    @property
    def complete(self) -> bool:
        return all(s.measurement is Measurement.MEASURED for s in self.signals)

    @property
    def unmeasured(self) -> List[Signal]:
        return [s for s in self.signals if s.measurement is Measurement.UNMEASURED]

    @property
    def irreversible_targets(self) -> List[str]:
        return sorted(r["target"] for r in self.reversibility
                      if r["can_reverse"] is False)

    @property
    def unproven_targets(self) -> List[str]:
        return sorted(r["target"] for r in self.reversibility
                      if r["can_reverse"] is None)

    @property
    def total_consumers(self) -> int:
        return len({c for v in self.downstream.values() for c in v})

    def to_dict(self) -> dict:
        return {
            "plan_hash": self.plan_hash, "dialect": self.dialect,
            "columns_affected": self.columns_affected,
            "tables_affected": list(self.tables_affected),
            "rows_estimate": self.rows_estimate,
            "downstream": {k: list(v) for k, v in sorted(self.downstream.items())},
            "downstream_unmeasured": list(self.downstream_unmeasured),
            "reversibility": list(self.reversibility),
            "signals": [s.to_dict() for s in self.signals],
            "prior_tier": int(self.prior_tier), "tier": int(self.tier),
            "credits_applied": list(self.credits_applied),
            "floors_applied": list(self.floors_applied),
            "decision": self.decision.value,
            "approval_reasons": list(self.approval_reasons),
            "budget": int(self.budget), "rubric": self.rubric,
            "complete": self.complete, "version": self.version,
        }

    @property
    def forecast_hash(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "F-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    def summary(self) -> dict:
        return {"forecast_hash": self.forecast_hash, "plan_hash": self.plan_hash,
                "tier": self.tier.label, "prior_tier": self.prior_tier.label,
                "decision": self.decision.value, "complete": self.complete,
                "columns": self.columns_affected, "tables": len(self.tables_affected),
                "rows_estimate": self.rows_estimate,
                "downstream_consumers": self.total_consumers,
                "irreversible": len(self.irreversible_targets),
                "reversibility_unproven": len(self.unproven_targets),
                "unmeasured_signals": [s.name for s in self.unmeasured]}

    def explain(self) -> str:
        lines = [
            f"{self.decision.value} — tier {self.tier.label} "
            f"against a budget of {self.budget.label} "
            f"(prior {self.prior_tier.label}, rubric {self.rubric['version']})",
            f"  {self.columns_affected} column(s) across "
            f"{len(self.tables_affected)} table(s), ~{self.rows_estimate:,} rows",
        ]
        if self.total_consumers:
            lines.append(f"  {self.total_consumers} downstream consumer(s)")
        if self.downstream_unmeasured:
            lines.append(f"  {len(self.downstream_unmeasured)} object(s) with an "
                         f"unreadable dependency graph — blast radius unknown")
        if self.irreversible_targets:
            lines.append(f"  irreversible: {', '.join(self.irreversible_targets)}")
        if self.unproven_targets:
            lines.append(f"  reversibility unproven: "
                         f"{', '.join(self.unproven_targets)}")
        for c in self.credits_applied:
            lines.append(f"  credit: {c}")
        for f in self.floors_applied:
            lines.append(f"  floor {RiskTier(f['tier']).label}: {f['reason']}")
        for r in self.approval_reasons:
            lines.append(f"  approval: {r['cause']} — {r['detail']}")
        if not self.complete:
            lines.append("  forecast is INCOMPLETE; it cannot be read as a pass")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# The junction
# ---------------------------------------------------------------------

class ReversibilityOracle(Protocol):
    def can_reverse(self, op: Operation) -> Tuple[Optional[bool], str]: ...


def simulate(plan: Plan,
             graph: DependencyGraph = None,
             executor: ReversibilityOracle = None,
             coverage: "CoverageReport" = None,
             budget: RiskTier = RiskTier.LOW,
             rubric: TierRubric = DEFAULT_RUBRIC) -> Forecast:
    """Deterministic given the same plan, graph answers and rubric."""
    graph = graph or NullDependencyGraph()
    signals: List[Signal] = []

    # ---- scale -----------------------------------------------------
    tables = plan.objects_touched()
    columns = len(plan.operations)
    rows = sum(o.row_estimate for o in plan.operations)
    uncounted = sorted(o.target for o in plan.operations if o.row_estimate <= 0)
    if uncounted:
        # A row_estimate of zero is ambiguous: an empty table and a table
        # nobody counted look identical here. Refusing to guess is the
        # difference between a forecast and a decoration.
        signals.append(Signal("scale.rows", Measurement.UNMEASURED, rows,
                              f"{len(uncounted)} operation(s) carry no row "
                              f"estimate: {', '.join(uncounted[:4])}"
                              + ("…" if len(uncounted) > 4 else ""),
                              cause=CAUSE_ROWS_UNCOUNTED))
    else:
        floor = (RiskTier.HIGH if rows >= rubric.rows_high else
                 RiskTier.MODERATE if rows >= rubric.rows_moderate else None)
        signals.append(Signal("scale.rows", Measurement.MEASURED, rows,
                              f"~{rows:,} rows", floor=floor,
                              credit=rows < rubric.rows_moderate))

    tfloor = (RiskTier.HIGH if len(tables) >= rubric.tables_high else
              RiskTier.MODERATE if len(tables) >= rubric.tables_moderate else None)
    signals.append(Signal("scale.tables", Measurement.MEASURED, len(tables),
                          f"{len(tables)} table(s), {columns} column(s)",
                          floor=tfloor))

    # ---- downstream ------------------------------------------------
    downstream, unmeasured_objs = _closure(graph, tables)
    total_consumers = len({c for v in downstream.values() for c in v})
    if unmeasured_objs:
        signals.append(Signal(
            "downstream.consumers", Measurement.UNMEASURED, total_consumers,
            f"{len(unmeasured_objs)} object(s) unreadable; "
            f"{total_consumers} consumer(s) found on the readable part",
            cause=unmeasured_objs[0]["cause"]))
    else:
        dfloor = (RiskTier.HIGH if total_consumers >= rubric.consumers_high else
                  RiskTier.MODERATE if total_consumers else None)
        signals.append(Signal(
            "downstream.consumers", Measurement.MEASURED, total_consumers,
            f"{total_consumers} downstream consumer(s)", floor=dfloor,
            credit=total_consumers == 0))

    # ---- reversibility ---------------------------------------------
    reversibility: List[dict] = []
    for o in plan.operations:
        if executor is None:
            reversibility.append({
                "target": o.target, "op": o.op, "treatment": o.treatment,
                "compiler_says": o.reversible,
                "can_reverse": (False if not o.reversible else None),
                "source": "compiler",
                "detail": ("treatment is irreversible" if not o.reversible
                           else "no executor consulted; reversibility unproven")})
            continue
        verdict, detail = executor.can_reverse(o)
        reversibility.append({
            "target": o.target, "op": o.op, "treatment": o.treatment,
            "compiler_says": o.reversible, "can_reverse": verdict,
            "source": "executor", "detail": detail,
            # Recorded because it is the interesting case: the compiler
            # promised something the engine cannot deliver.
            "disagreement": bool(o.reversible) and verdict is not True})

    irreversible = [r["target"] for r in reversibility if r["can_reverse"] is False]
    unproven = [r["target"] for r in reversibility if r["can_reverse"] is None]

    if executor is None:
        signals.append(Signal("reversibility", Measurement.UNMEASURED,
                              None, "executor not consulted",
                              cause=CAUSE_NO_EXECUTOR,
                              floor=RiskTier.HIGH if irreversible else None))
    else:
        signals.append(Signal(
            "reversibility", Measurement.MEASURED,
            {"irreversible": len(irreversible), "unproven": len(unproven)},
            f"{len(irreversible)} irreversible, {len(unproven)} unproven",
            floor=RiskTier.HIGH if irreversible else None,
            credit=not irreversible and not unproven))

    # ---- coverage (Phase 0) ------------------------------------------
    # This signal used to read plan.unresolved directly. That was a thinner
    # version of the same question: unresolved findings are one cause of
    # ungoverned columns, and they say nothing about columns nobody scanned.
    # The coverage report is now the only source, and its absence is an
    # unmeasured signal rather than a silent zero.
    if coverage is None:
        signals.append(Signal("coverage", Measurement.UNMEASURED, None,
                              "no Phase 0 assessment supplied; the share of "
                              "the estate this plan does not touch is unknown",
                              cause=CAUSE_COVERAGE_NOT_ASSESSED))
    elif coverage.plan_hash and coverage.plan_hash != plan.plan_hash:
        signals.append(Signal(
            "coverage", Measurement.UNMEASURED,
            {"coverage_plan": coverage.plan_hash, "plan": plan.plan_hash},
            "the coverage report was built against a different plan",
            cause=CAUSE_COVERAGE_PLAN_MISMATCH))
    else:
        c = coverage.counts
        ungoverned = len(coverage.ungoverned())
        clean = (c["inconclusive"] == 0 and ungoverned == 0
                 and not coverage.anomalies and coverage.denominator_verified)
        floor = None
        if not coverage.denominator_verified or coverage.anomalies:
            # We do not know what we did not find. Nothing below HIGH is
            # honest about that.
            floor = RiskTier.HIGH
        elif c["inconclusive"] or ungoverned:
            floor = RiskTier.MODERATE
        signals.append(Signal(
            "coverage", Measurement.MEASURED,
            {"verified": c["verified"], "observed": c["observed"],
             "inconclusive": c["inconclusive"], "excluded": c["excluded"],
             "ungoverned": ungoverned},
            f"{c['verified']} verified, {c['observed']} observed, "
            f"{c['inconclusive']} inconclusive, {c['excluded']} excluded; "
            f"{ungoverned} measured but ungoverned",
            cause=("" if clean else CAUSE_UNGOVERNED_COLUMNS),
            floor=floor, credit=clean))

    # ---- tier -------------------------------------------------------
    prior = max([rubric.prior_for(o.op) for o in plan.operations],
                default=RiskTier.LOW)

    credits = [s.name for s in signals
               if s.credit and s.measurement is Measurement.MEASURED]
    applied = credits[:rubric.max_credits]
    tier_value = int(prior) - len(applied)

    floors = [{"tier": int(s.floor), "reason": f"{s.name}: {s.detail}"}
              for s in signals if s.floor]
    if irreversible:
        floors.append({"tier": int(RiskTier.HIGH),
                       "reason": "an irreversible operation is in the plan"})
    if unproven:
        floors.append({"tier": int(RiskTier.MODERATE),
                       "reason": "reversibility could not be proven"})
    for f in floors:
        tier_value = max(tier_value, f["tier"])
    tier = RiskTier(max(int(RiskTier.LOW), min(int(RiskTier.CRITICAL), tier_value)))

    # ---- decision ---------------------------------------------------
    # Three independent gates. The forecast can lower the tier; it cannot
    # reach past any of these.
    reasons: List[dict] = []
    if irreversible:
        reasons.append({"cause": CAUSE_IRREVERSIBLE,
                        "detail": f"{len(irreversible)} operation(s) cannot be "
                                  f"undone: {', '.join(sorted(irreversible)[:3])}"})
    if unproven:
        reasons.append({"cause": CAUSE_REVERSIBILITY_UNPROVEN,
                        "detail": f"{len(unproven)} operation(s) whose reversal "
                                  f"is conditional or unimplemented"})
    incomplete = [s for s in signals if s.measurement is Measurement.UNMEASURED]
    if incomplete:
        reasons.append({"cause": CAUSE_FORECAST_INCOMPLETE,
                        "detail": "unmeasured: "
                                  + ", ".join(s.name for s in incomplete)})
    if tier > budget:
        reasons.append({"cause": CAUSE_TIER_EXCEEDS_BUDGET,
                        "detail": f"tier {tier.label} exceeds budget "
                                  f"{RiskTier(budget).label}"})

    decision = Decision.APPROVAL_REQUIRED if reasons else Decision.AUTONOMOUS

    return Forecast(
        plan_hash=plan.plan_hash, dialect=plan.dialect,
        columns_affected=columns, tables_affected=tables, rows_estimate=rows,
        downstream=downstream, downstream_unmeasured=unmeasured_objs,
        reversibility=reversibility, signals=signals,
        prior_tier=prior, tier=tier, credits_applied=applied,
        floors_applied=floors, decision=decision, approval_reasons=reasons,
        budget=RiskTier(budget), rubric=rubric.to_dict())
