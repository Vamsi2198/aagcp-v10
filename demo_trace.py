"""Trace one full request REQ-1 through every phase, printing the journal."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import assess, Column, Inventory, Inspection
from aagcp.core.simulate import RiskTier, Decision, StaticDependencyGraph
from aagcp.core.executors import SnowflakeExecutor
from aagcp.core.executors.mock import MockEngine
from aagcp.core.journal import Journal, Principal
from aagcp.core.orchestrator import Orchestrator

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="SALES.PUBLIC", scope_exclude=[],
                         policy_id="dpdp", audience=["DPO"], confidence=0.95),
                    REGISTRY)
FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email", "email", "EMAIL", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "mobile", "phone", "PHONE", .98, 184000),
]
COLUMNS = [Column("ACME", "PUBLIC", "customers", f.column, "VARCHAR", 184000)
           for f in FINDINGS]
INV = Inventory(tuple(COLUMNS), source="snowflake catalog", complete=True)
INSP = [Inspection(c.target, "content_sample", 5000, f.identifier_key, .99)
        for c, f in zip(COLUMNS, FINDINGS)]
GRAPH = StaticDependencyGraph({}, known=["ACME.PUBLIC.customers"])

def engine():
    from aagcp.core.executors.snowflake import _policy_name
    p = compile_plan(INTENT, FINDINGS, "snowflake")
    return MockEngine(queries={
        "aagcp:prestate": [],
        "POLICY_REFERENCES": [(_policy_name(o),) for o in p.operations],
        "INFORMATION_SCHEMA.COLUMNS": []})

tmp = tempfile.mkdtemp(prefix="aagcp-trace-")
j = Journal(os.path.join(tmp, "trace.jsonl"))
o = Orchestrator(j)

# 1. OBSERVE — coverage is assessed and its hash is the FIRST thing recorded
cov = o.observe("REQ-1", INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
                principal=ANALYST)
print("coverage:", cov.rate("estate").render())

# 2. ANALYZE — a digest of exactly which findings entered the pipeline
o.analyze("REQ-1", FINDINGS, principal=ANALYST)

# 3. PLAN — the compiler turns intent+findings into SQL-bound operations
plan = o.plan("REQ-1", INTENT, FINDINGS, principal=ANALYST)
print(f"plan: {len(plan.operations)} operation(s), hash {plan.plan_hash}")

# 4. SIMULATE — coverage report feeds the risk forecast
cov = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan, findings=FINDINGS)
ex = SnowflakeExecutor(engine())
f = o.simulate("REQ-1", plan, graph=GRAPH, executor=ex, coverage=cov,
               budget=RiskTier.LOW, principal=ANALYST)
print("forecast:", f.tier.label, f.decision.value)
for sig in f.signals:
    print(f"  signal {sig.name:24s} {sig.measurement.value:10s} {sig.detail}")

# 5. APPROVE — separation of duties: the requester (ANALYST) cannot approve
o.approve("REQ-1", f, DPO)

# 6. EXECUTE — attempt is journaled BEFORE the warehouse runs
receipt = o.execute("REQ-1", plan, ex, principal=ANALYST)
print("receipt:", receipt.verdict.value, f"({len(receipt.operations)} operation(s))")

# 7. VERIFY — post-checks against the live warehouse
o.verify("REQ-1", receipt, passed=True,
         evidence={"controls_confirmed": len(receipt.operations)})

# 8. LEARN — scores predictions; does NOT tune the rubric
lesson = o.learn("REQ-1", f, receipt)

# 9. CLOSE — a closed request never reopens
o.close("REQ-1", receipt, principal=ANALYST, lesson=lesson)

print("\n=== the journal for REQ-1 (what an auditor replays) ===")
for e in j.entries:
    p = {k: v for k, v in e.payload.items()}
    who = e.principal["principal_id"] if e.principal else "(system)"
    print(f"seq {e.seq}  {e.phase.value:16s} {e.subject_hash}  by {who}")
    for k, v in p.items():
        print(f"           {k}: {v}")
print("\nchain ok:", j.verify_chain() == [], "| bindings ok:", j.verify_bindings("REQ-1") == [])
