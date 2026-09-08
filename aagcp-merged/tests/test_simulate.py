"""Invariants for the simulate junction. python3 test_simulate.py

The gate is only worth having if it holds when the news is good. Most of
these tests hand it a clean forecast and check that it still refuses.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import assess, Column, Inventory, Inspection
from aagcp.core.simulate import (simulate, RiskTier, Decision, Measurement,
                           StaticDependencyGraph, NullDependencyGraph,
                           TierRubric)
from aagcp.core.executors import SnowflakeExecutor, PostgresExecutor
from aagcp.core.executors.mock import MockEngine

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


def slots(**kw):
    d = dict(action="mask", scope_kind="schema", scope_value="SALES.PUBLIC",
             scope_exclude=[], policy_id="dpdp", audience=["DPO"], confidence=0.95)
    d.update(kw); return d

INTENT = from_slots(slots(), REGISTRY)

# A small, fully counted, fully governed plan — the best case there is.
SMALL = [
    Finding("ACME", "PUBLIC", "lookup", "email", "email", "EMAIL", .99, 400),
    Finding("ACME", "PUBLIC", "lookup", "mobile", "phone", "PHONE", .98, 400),
]
SMALL_PLAN = compile_plan(INTENT, SMALL, "snowflake")

BIG = [
    Finding("ACME", "PUBLIC", "customers", "email", "email", "EMAIL", .99, 2_400_000),
    Finding("ACME", "PUBLIC", "customers", "mobile", "phone", "PHONE", .98, 2_400_000),
]
BIG_PLAN = compile_plan(INTENT, BIG, "snowflake")


def cov(plan, findings, extra_columns=(), rows=400, policy_id="dpdp"):
    """Fixture: a fully scanned, fully asserted inventory covering exactly
    the columns named. Written out explicitly rather than derived inside the
    library, because deriving an inventory from the findings you already
    have is the denominator lie Phase 0 exists to prevent."""
    cols = [Column(f.database, f.schema, f.table, f.column, "VARCHAR", rows)
            for f in findings] + list(extra_columns)
    insp = [Inspection(c.target, "content_sample", 5000,
                       next((f.identifier_key for f in findings
                             if f"{f.fqn}.{f.column}" == c.target), ""), 0.99)
            for c in cols]
    return assess(Inventory(tuple(cols), source="test catalog", complete=True),
                  insp, (), policy=REGISTRY[policy_id], plan=plan,
                  findings=findings)


SMALL_COV = cov(SMALL_PLAN, SMALL)
BIG_COV = cov(BIG_PLAN, BIG, rows=2_400_000)

ISOLATED = StaticDependencyGraph({}, known=["ACME.PUBLIC.lookup",
                                            "ACME.PUBLIC.customers",
                                            "ACME.PUBLIC.orders"])
CONNECTED = StaticDependencyGraph(
    {"ACME.PUBLIC.customers": ["ACME.MART.dim_customer"],
     "ACME.MART.dim_customer": ["ACME.MART.rpt_churn", "ACME.BI.exec_dash"]},
    known=["ACME.PUBLIC.customers", "ACME.MART.dim_customer",
           "ACME.MART.rpt_churn", "ACME.BI.exec_dash", "ACME.PUBLIC.lookup",
           "ACME.PUBLIC.orders"])


def sf(plan=None):
    """Executor whose undo statements build fine — reversibility provable."""
    return SnowflakeExecutor(MockEngine())


print("\n=== BEST CASE: clean forecast, low tier, autonomy allowed ===")
f = simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(), coverage=SMALL_COV,
             budget=RiskTier.MODERATE)
check("forecast is complete", f.complete, str(f.summary()["unmeasured_signals"]))
check("prior was MODERATE for masking", f.prior_tier is RiskTier.MODERATE,
      f.prior_tier.label)
check("credits pulled the tier down", f.tier < f.prior_tier,
      f"{f.prior_tier.label} -> {f.tier.label} via {f.credits_applied}")
check("decision is AUTONOMOUS under budget", f.decision is Decision.AUTONOMOUS,
      f.explain().splitlines()[0])

print("\n=== A CLEAN FORECAST NEVER AUTHORISES ===")
f2 = simulate(BIG_PLAN, graph=ISOLATED, executor=sf(), coverage=BIG_COV,
              budget=RiskTier.MODERATE)
check("forecast is clean", f2.complete, str(f2.summary()["unmeasured_signals"]))
check("credits were earned", f2.credits_applied != [], str(f2.credits_applied))
check("tier still exceeds the budget -> approval",
      f2.decision is Decision.APPROVAL_REQUIRED
      and any(r["cause"] == "TIER_EXCEEDS_AUTONOMY_BUDGET"
              for r in f2.approval_reasons),
      f"tier {f2.tier.label} vs MODERATE; {[r['cause'] for r in f2.approval_reasons]}")

pci = from_slots(slots(policy_id="pci_dss"), REGISTRY)
PCI_F = SMALL + [Finding("ACME", "PUBLIC", "orders", "cvv", "cav2", "", .9, 300)]
pci_plan = compile_plan(pci, PCI_F, "snowflake")
pci_cov = cov(pci_plan, PCI_F, policy_id="pci_dss")
f3 = simulate(pci_plan, graph=ISOLATED, executor=sf(), coverage=pci_cov,
              budget=RiskTier.CRITICAL)
check("irreversible forces approval even at the maximum budget",
      f3.decision is Decision.APPROVAL_REQUIRED, f3.explain().splitlines()[0])
check("the reason is named",
      any(r["cause"] == "IRREVERSIBLE_OPERATION" for r in f3.approval_reasons),
      str([r["cause"] for r in f3.approval_reasons]))
check("irreversible holds a HIGH floor even with credits",
      f3.tier >= RiskTier.HIGH, f3.tier.label)

print("\n=== INCOMPLETE IS NEVER A PASS ===")
f4 = simulate(SMALL_PLAN, graph=NullDependencyGraph(), executor=sf(),
              coverage=SMALL_COV, budget=RiskTier.CRITICAL)
check("no dependency graph -> forecast incomplete", not f4.complete,
      str(f4.summary()["unmeasured_signals"]))
check("downstream is the only thing unmeasured",
      f4.summary()["unmeasured_signals"] == ["downstream.consumers"],
      str(f4.summary()["unmeasured_signals"]))
check("incomplete forces approval at any budget",
      f4.decision is Decision.APPROVAL_REQUIRED,
      str([r["cause"] for r in f4.approval_reasons]))
check("unmeasured downstream earns no credit",
      "downstream.consumers" not in f4.credits_applied, str(f4.credits_applied))
check("tier is not lowered by an unread graph", f4.tier >= f.tier,
      f"{f4.tier.label} vs {f.tier.label}")

class ThrowingGraph:
    def consumers(self, object_fqn):
        raise RuntimeError("catalog timeout")

f5 = simulate(SMALL_PLAN, graph=ThrowingGraph(), executor=sf(), coverage=SMALL_COV)
check("a graph that throws does not crash the forecast", not f5.complete)
check("the throw is recorded as a cause",
      f5.downstream_unmeasured[0]["cause"] == "DEPENDENCY_GRAPH_ERROR",
      f5.downstream_unmeasured[0]["detail"])

UNC = [Finding("ACME", "PUBLIC", "lookup", "email", "email", "EMAIL", .99, 0)]
uncounted = compile_plan(INTENT, UNC, "snowflake")
f6 = simulate(uncounted, graph=ISOLATED, executor=sf(),
              coverage=cov(uncounted, UNC, rows=0))
check("a zero row estimate is unmeasured, not small", not f6.complete,
      str(f6.summary()["unmeasured_signals"]))
check("no small-scale credit for an uncounted table",
      "scale.rows" not in f6.credits_applied, str(f6.credits_applied))

print("\n=== PHASE 0 IS THE ONLY SOURCE FOR COVERAGE ===")
f7 = simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(), coverage=None,
              budget=RiskTier.CRITICAL)
check("no coverage report -> the signal is unmeasured",
      any(s.name == "coverage" and s.measurement is Measurement.UNMEASURED
          for s in f7.signals))
check("its cause is named", any(r["cause"] == "FORECAST_INCOMPLETE"
                                for r in f7.approval_reasons))
check("an unassessed estate is never autonomous",
      f7.decision is Decision.APPROVAL_REQUIRED, f7.explain().splitlines()[0])
check("plan.unresolved is no longer a signal of its own",
      not any(s.name == "plan.unresolved" for s in f7.signals),
      str([s.name for s in f7.signals]))

f8 = simulate(BIG_PLAN, graph=ISOLATED, executor=sf(), coverage=SMALL_COV,
              budget=RiskTier.CRITICAL)
check("a coverage report for a different plan is rejected",
      any(s.name == "coverage" and s.cause == "COVERAGE_REPORT_IS_FOR_A_DIFFERENT_PLAN"
          for s in f8.signals),
      str([(s.name, s.cause) for s in f8.signals if s.name == "coverage"]))

# Ungoverned columns now reach the forecast through Phase 0, not through
# a second reading of plan.unresolved.
MIXED_F = SMALL + [Finding("ACME", "PUBLIC", "lookup", "cvv", "cav2", "", .9, 400)]
mixed = compile_plan(INTENT, MIXED_F, "snowflake")
mixed_cov = cov(mixed, MIXED_F)
f9 = simulate(mixed, graph=ISOLATED, executor=sf(), coverage=mixed_cov,
              budget=RiskTier.CRITICAL)
check("the ungoverned column is visible in coverage",
      len(mixed_cov.ungoverned()) == 1,
      str([e.target for e in mixed_cov.ungoverned()]))
check("it holds a MODERATE floor through the coverage signal",
      f9.tier >= RiskTier.MODERATE
      and any(fl["reason"].startswith("coverage") for fl in f9.floors_applied),
      f"{f9.tier.label}; {[fl['reason'][:24] for fl in f9.floors_applied]}")
check("an unverified denominator holds a HIGH floor",
      simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(),
               coverage=assess(
                   Inventory(tuple(Column(f.database, f.schema, f.table,
                                          f.column, "VARCHAR", 400) for f in SMALL),
                             source="partial crawl", complete=None),
                   [Inspection(f"{f.fqn}.{f.column}", "content_sample", 5000,
                               f.identifier_key, .99) for f in SMALL],
                   policy=REGISTRY["dpdp"], plan=SMALL_PLAN, findings=SMALL),
               budget=RiskTier.CRITICAL).tier >= RiskTier.HIGH)

print("\n=== BLAST RADIUS ===")
f10 = simulate(BIG_PLAN, graph=CONNECTED, executor=sf(), coverage=BIG_COV,
               budget=RiskTier.CRITICAL)
check("transitive consumers are followed", f10.total_consumers == 3,
      str(sorted({c for v in f10.downstream.values() for c in v})))
check("2.4m rows raises the floor to HIGH", f10.tier >= RiskTier.HIGH,
      f10.explain().splitlines()[0])
check("consumers block the no-downstream credit",
      "downstream.consumers" not in f10.credits_applied, str(f10.credits_applied))

cyclic = StaticDependencyGraph(
    {"ACME.PUBLIC.lookup": ["v1"], "v1": ["v2"], "v2": ["ACME.PUBLIC.lookup"]},
    known=["ACME.PUBLIC.lookup", "v1", "v2"])
f11 = simulate(SMALL_PLAN, graph=cyclic, executor=sf(), coverage=SMALL_COV)
check("a cycle in the graph terminates and excludes the root",
      f11.total_consumers == 2,
      str(sorted({c for v in f11.downstream.values() for c in v})))

print("\n=== EXECUTOR OVERRIDES THE COMPILER ON REVERSIBILITY ===")
pg_plan = compile_plan(INTENT, SMALL, "postgres")
fp = simulate(pg_plan, graph=ISOLATED, executor=PostgresExecutor(MockEngine()),
              coverage=cov(pg_plan, SMALL), budget=RiskTier.CRITICAL)
row = fp.reversibility[0]
check("compiler said reversible", row["compiler_says"] is True)
check("executor answers None, not True", row["can_reverse"] is None, row["detail"][:60])
check("the disagreement is recorded", row["disagreement"] is True)
check("unproven reversibility forces approval",
      any(r["cause"] == "REVERSIBILITY_NOT_PROVEN" for r in fp.approval_reasons),
      str([r["cause"] for r in fp.approval_reasons]))
check("snowflake proves the same treatment reversible",
      f.reversibility[0]["can_reverse"] is True)
check("no executor at all -> reversibility unmeasured",
      any(s.name == "reversibility" and s.measurement is Measurement.UNMEASURED
          for s in simulate(SMALL_PLAN, graph=ISOLATED, executor=None,
                            coverage=SMALL_COV).signals))

print("\n=== DETERMINISM AND THE RUBRIC ===")
a = simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(), coverage=SMALL_COV)
b = simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(), coverage=SMALL_COV)
check("same inputs, same forecast hash", a.forecast_hash == b.forecast_hash,
      a.forecast_hash)
strict = TierRubric(version="rubric-strict", rows_moderate=100, max_credits=0)
c = simulate(SMALL_PLAN, graph=ISOLATED, executor=sf(), coverage=SMALL_COV,
             rubric=strict)
check("a different rubric gives a different hash", c.forecast_hash != a.forecast_hash)
check("the rubric that produced the tier is in the forecast",
      c.rubric["version"] == "rubric-strict", c.rubric["version"])
check("no credits under a rubric that grants none", c.credits_applied == [],
      str(c.credits_applied))
check("tier is a rubric output, not a fact",
      c.tier != a.tier, f"{a.tier.label} under default, {c.tier.label} under strict")

print("\n=== SAMPLE FORECAST ===")
print("  " + simulate(pci_plan, graph=CONNECTED, executor=sf(), coverage=pci_cov,
                      budget=RiskTier.MODERATE).explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
