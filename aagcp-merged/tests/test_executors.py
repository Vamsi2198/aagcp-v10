"""Invariants for the executor layer. python3 test_executors.py

The interesting tests are all failure tests. A layer that only works when
nothing goes wrong is not an execution layer, it is a script.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.executors import (SnowflakeExecutor, PostgresExecutor, StagePolicy,
                            FailurePolicy, ExecutionVerdict, OperationStatus,
                            StatementStatus)
from aagcp.core.executors.snowflake import _policy_name
from aagcp.core.executors.mock import MockEngine, Rule

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


def slots(**kw):
    d = dict(action="mask", scope_kind="schema", scope_value="SALES.PUBLIC",
             scope_exclude=[], policy_id="dpdp", audience=["DPO"], confidence=0.95)
    d.update(kw); return d

INTENT = from_slots(slots(), REGISTRY, utterance="mask pii in sales")

FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "aadhaar_no", "aadhaar", "IN_AADHAAR", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "email",      "email",   "EMAIL", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "mobile",     "phone",   "PHONE", .98, 184000),
    Finding("ACME", "PUBLIC", "lookup",    "contact_em", "email",   "EMAIL", .95, 900),
]
PLAN = compile_plan(INTENT, FINDINGS, "snowflake")
POLICIES = [_policy_name(o) for o in PLAN.operations]


def sf_engine(rules=(), attached=None):
    """Snowflake-shaped mock. `attached` is what POLICY_REFERENCES reports
    at verification time; prestate is answered separately and empty."""
    return MockEngine(rules=rules, queries={
        "aagcp:prestate": [],
        "POLICY_REFERENCES": [(n,) for n in (POLICIES if attached is None else attached)],
        "INFORMATION_SCHEMA.COLUMNS": [],
    })


print("\n=== PREVIEW: reads, never writes ===")
eng = sf_engine()
pv = SnowflakeExecutor(eng).preview(PLAN)
check("preview issues no DDL", eng.ddl() == [], str(eng.ddl()[:1]))
check("preview is executable", pv.executable, str(pv.capability_errors))
check("preview counts every statement",
      pv.statements == sum(len(o.statements) for o in PLAN.operations),
      str(pv.statements))

print("\n=== CANARY: deterministic, smallest blast radius first ===")
c1 = SnowflakeExecutor(sf_engine()).select_canary(PLAN, StagePolicy())
c2 = SnowflakeExecutor(sf_engine()).select_canary(PLAN, StagePolicy())
check("canary selection is stable across runs", c1 == c2, str(c1))
check("canary picks the smallest table",
      c1 == ["ACME.PUBLIC.lookup.contact_em"], str(c1))

print("\n=== DIALECT MISMATCH: refused before anything runs ===")
pg_plan = compile_plan(INTENT, FINDINGS, "postgres")
eng = sf_engine()
r = SnowflakeExecutor(eng).execute_staged(pg_plan)
check("wrong dialect refuses", r.verdict is ExecutionVerdict.REFUSED, r.verdict.value)
check("refusal touched nothing", eng.ddl() == [])
check("refusal carries a cause",
      r.refusal["cause"] == "PLAN_DIALECT_DOES_NOT_MATCH_EXECUTOR", r.refusal["cause"])

print("\n=== HAPPY PATH ===")
eng = sf_engine()
r = SnowflakeExecutor(eng).execute_staged(PLAN)
check("all applied and verified -> COMPLETE",
      r.verdict is ExecutionVerdict.COMPLETE, r.explain())
check("every operation verified", all(o.verified is True for o in r.operations))
check("canary ran before the remainder",
      [o.stage for o in r.operations] == ["canary"] + ["remainder"] * 3,
      str([o.stage for o in r.operations]))

print("\n=== THE 400/12 CASE: partial failure keeps what landed ===")
# The canary passes, then one column's ALTER is rejected.
eng = sf_engine(rules=[Rule("MODIFY COLUMN \"mobile\"", message="insufficient privileges")])
r = SnowflakeExecutor(eng).execute_staged(PLAN, StagePolicy(on_failure=FailurePolicy.CONTINUE))
mobile = [o for o in r.operations if o.target.endswith("mobile")][0]
check("verdict is PARTIAL, not FAILED and not COMPLETE",
      r.verdict is ExecutionVerdict.PARTIAL, r.explain())
check("the failing operation is PARTIALLY_APPLIED, not FAILED",
      mobile.status is OperationStatus.PARTIALLY_APPLIED, mobile.status.value)
check("its CREATE is recorded APPLIED and nothing after is attempted",
      [s.status for s in mobile.statements] ==
      [StatementStatus.APPLIED, StatementStatus.FAILED],
      str([s.status.value for s in mobile.statements]))
check("orphan policy object recorded as residue",
      len(mobile.residual_artifacts) == 1, str(mobile.residual_artifacts))
check("HALT is not the default that reverts — no UNSET was issued",
      not any("UNSET" in s for s in eng.ddl()))
check("the other three columns stay governed",
      len([o for o in r.operations if o.effective_ok]) == 3,
      str(r.summary()))

print("\n=== HALT: default stops after the first bad operation ===")
eng = sf_engine(rules=[Rule("MODIFY COLUMN \"aadhaar_no\"", message="locked")])
r = SnowflakeExecutor(eng).execute_staged(PLAN)   # default HALT
check("HALT leaves later operations NOT_ATTEMPTED",
      any(o.status is OperationStatus.NOT_ATTEMPTED for o in r.operations),
      str(r.summary()))

print("\n=== CANARY FAILS: the remainder is never touched ===")
eng = sf_engine(rules=[Rule("lookup", message="object does not exist")])
r = SnowflakeExecutor(eng).execute_staged(PLAN)
check("verdict is HALTED_AT_CANARY",
      r.verdict is ExecutionVerdict.HALTED_AT_CANARY, r.explain())
check("nothing outside the canary was attempted",
      all(o.status is OperationStatus.NOT_ATTEMPTED
          for o in r.operations if o.stage == "remainder"))
check("no DDL ran against customers",
      not any("customers" in s for s in eng.ddl()), str(eng.ddl()))

print("\n=== UNKNOWN: transport loss is neither pass nor fail ===")
eng = sf_engine(rules=[Rule("MODIFY COLUMN \"email\"", kind="transport",
                            message="connection reset")])
r = SnowflakeExecutor(eng).execute_staged(PLAN, StagePolicy(on_failure=FailurePolicy.CONTINUE))
email = [o for o in r.operations if o.target.endswith(".email")][0]
check("operation status is UNKNOWN", email.status is OperationStatus.UNKNOWN)
check("UNKNOWN dominates the verdict",
      r.verdict is ExecutionVerdict.INCONCLUSIVE, r.explain())
check("UNKNOWN is never COMPLETE and never FAILED",
      r.verdict not in (ExecutionVerdict.COMPLETE, ExecutionVerdict.FAILED))

print("\n=== I1 ANALOGUE: applied but unverified is not applied ===")
# Verification lookup itself errors; the DDL all succeeded.
eng = sf_engine(rules=[Rule("aagcp:verify", message="no privilege on INFORMATION_SCHEMA")])
r = SnowflakeExecutor(eng).execute_staged(PLAN, StagePolicy(on_failure=FailurePolicy.CONTINUE))
check("unverifiable success is INCONCLUSIVE, not COMPLETE",
      r.verdict is ExecutionVerdict.INCONCLUSIVE, r.explain())
check("verified is None, not False",
      all(o.verified is None for o in r.operations if o.stage != "none"),
      str([o.verified for o in r.operations]))

print("\n=== Verification says the control is absent ===")
eng = sf_engine(attached=[])     # policy attached to nothing
r = SnowflakeExecutor(eng).execute_staged(PLAN)
check("statements succeeded but control missing -> not COMPLETE",
      r.verdict is not ExecutionVerdict.COMPLETE, r.explain())
check("verified is False", r.operations[0].verified is False,
      r.operations[0].verify_detail)

print("\n=== ROLLBACK is explicit, and refuses what it cannot undo ===")
eng = sf_engine()
ex = SnowflakeExecutor(eng)
r = ex.execute_staged(PLAN)
eng.reset()
rb = ex.rollback(r, PLAN)
check("rollback UNSETs the policy from the column",
      all("UNSET MASKING POLICY" in s for s in eng.ddl()), str(eng.ddl()[:1]))
check("rollback never DROPs the shared policy object",
      not any("DROP MASKING POLICY" in s for s in eng.ddl()))
check("verdict is ROLLED_BACK", rb.verdict is ExecutionVerdict.ROLLED_BACK,
      rb.verdict.value)

pci = from_slots(slots(policy_id="pci_dss"), REGISTRY)
pci_findings = FINDINGS + [Finding("ACME", "PUBLIC", "orders", "cvv", "cav2", "", .9, 42000)]
pci_plan = compile_plan(pci, pci_findings, "snowflake")
pci_pols = [_policy_name(o) for o in pci_plan.operations
            if o.op == "apply_masking_policy"]
eng = MockEngine(queries={"aagcp:prestate": [],
                          "POLICY_REFERENCES": [(n,) for n in pci_pols],
                          "INFORMATION_SCHEMA.COLUMNS": []})
ex = SnowflakeExecutor(eng)
r = ex.execute_staged(pci_plan)
rb = ex.rollback(r, pci_plan)
check("rollback refuses the irreversible DROP",
      rb.refusal is not None
      and any(x["cause"] == "IRREVERSIBLE_OPERATION" for x in rb.refusal["all"]),
      str(rb.refusal and rb.refusal["all"][:1]))

eng = sf_engine(rules=[Rule("MODIFY COLUMN \"email\"", kind="transport", message="reset")])
ex = SnowflakeExecutor(eng)
r = ex.execute_staged(PLAN, StagePolicy(on_failure=FailurePolicy.CONTINUE))
rb = ex.rollback(r, PLAN)
check("rollback refuses an operation in an unknown state",
      any(x["cause"] == "UNKNOWN_STATE_NOT_ROLLBACK_SAFE" for x in rb.refusal["all"]),
      str([x["cause"] for x in rb.refusal["all"]]))

print("\n=== POSTGRES: a REVOKE it cannot reverse is a refusal ===")
pg_eng = MockEngine(queries={
    "aagcp:prestate": [("PUBLIC", "SELECT")],
    "pg_views": [("customers_governed",), ("lookup_governed",)],
    "column_privileges": [],          # PUBLIC no longer holds SELECT
    "information_schema.columns": [],
})
pex = PostgresExecutor(pg_eng)
pr = pex.execute_staged(pg_plan)
check("postgres reaches COMPLETE on the happy path",
      pr.verdict is ExecutionVerdict.COMPLETE, pr.explain())
pg_eng.reset()
prb = pex.rollback(pr, pg_plan)
check("rollback re-grants from the captured snapshot",
      any("GRANT SELECT" in s for s in pg_eng.ddl()), str(pg_eng.ddl()[:2]))

blind = MockEngine(rules=[Rule("aagcp:prestate", message="no access to column_privileges")])
check("postgres refuses to execute without a grant snapshot",
      PostgresExecutor(blind).execute_staged(pg_plan).verdict is ExecutionVerdict.REFUSED)
check("snowflake only warns when prestate is unavailable",
      SnowflakeExecutor(
          MockEngine(rules=[Rule("aagcp:prestate", message="no access")],
                     queries={"POLICY_REFERENCES": [(n,) for n in POLICIES],
                              "INFORMATION_SCHEMA.COLUMNS": []})
      ).preview(PLAN).executable)

print("\n=== POSTGRES residue: the view that implies a control ===")
pg_eng2 = MockEngine(rules=[Rule("REVOKE", message="must be owner")], queries={
    "aagcp:prestate": [("PUBLIC", "SELECT")],
    "pg_views": [("customers_governed",), ("lookup_governed",)],
    "column_privileges": [], "information_schema.columns": []})
pr2 = PostgresExecutor(pg_eng2).execute_staged(pg_plan, StagePolicy(on_failure=FailurePolicy.CONTINUE))
check("view created + revoke failed is recorded as residue",
      all(o.residual_artifacts for o in pr2.operations
          if o.status is OperationStatus.PARTIALLY_APPLIED),
      str(pr2.operations[0].residual_artifacts))

print("\n=== SCALE: 400 statements, 12 rejected ===")
# 200 columns across 20 tables, two statements each.
big_findings = [
    Finding("ACME", "PUBLIC", f"t{i // 10:02d}", f"email_{i:03d}", "email",
            "EMAIL", .99, 1000 + i)
    for i in range(200)
]
big_plan = compile_plan(INTENT, big_findings, "snowflake")
def big_engine(doomed):
    return MockEngine(
        rules=[Rule(f'MODIFY COLUMN "{c}"', message="insufficient privileges")
               for c in doomed],
        queries={"aagcp:prestate": [],
                 "POLICY_REFERENCES": [(_policy_name(big_plan.operations[0]),)],
                 "INFORMATION_SCHEMA.COLUMNS": []})

check("400 statements planned",
      sum(len(o.statements) for o in big_plan.operations) == 400,
      str(sum(len(o.statements) for o in big_plan.operations)))

# (a) The twelve failures all sit outside the canary. The canary is clean,
#     the run proceeds, and twelve columns end up half-governed.
outside = [f"email_{i:03d}" for i in (33, 41, 58, 66, 77, 89, 101, 120, 140, 155, 177, 199)]
eng_a = big_engine(outside)
a_big = SnowflakeExecutor(eng_a).execute_staged(
    big_plan, StagePolicy(on_failure=FailurePolicy.CONTINUE))
sa = a_big.summary()
check("12 operations partially applied", sa["partially_applied"] == 12, str(sa))
check("188 applied and verified", sa["applied"] == 188, str(sa["applied"]))
check("verdict is PARTIAL", a_big.verdict is ExecutionVerdict.PARTIAL, a_big.explain())
check("one residual policy object per half-applied operation",
      sa["residual_artifacts"] == 12, str(sa["residual_artifacts"]))
check("nothing was reverted", not any("UNSET" in x for x in eng_a.ddl()))
print("  (a) failures outside the canary: " + a_big.explain())

# (b) Two of the same failures fall inside the canary — the smallest tables
#     are exactly where a permissions problem shows up first. 180 operations
#     are then never attempted, which is the canary paying for itself.
eng_b = big_engine([f"email_{i:03d}" for i in (7, 19, 33, 41)])
b_big = SnowflakeExecutor(eng_b).execute_staged(
    big_plan, StagePolicy(on_failure=FailurePolicy.CONTINUE))
sb = b_big.summary()
check("canary catch halts the run", b_big.verdict is ExecutionVerdict.HALTED_AT_CANARY,
      b_big.verdict.value)
check("180 operations never attempted", sb["not_attempted"] == 180, str(sb))
check("blast radius held to the canary",
      sb["partially_applied"] == 2, str(sb["partially_applied"]))
print("  (b) failures inside the canary: " + b_big.explain())

print("\n=== RECEIPT: reproducible, and does not measure the clock ===")
t = [1000.0]
def fake_clock():
    t[0] += 7.5
    return t[0]
a = SnowflakeExecutor(sf_engine(), clock=fake_clock).execute_staged(PLAN)
b = SnowflakeExecutor(sf_engine(), clock=lambda: 99999.0).execute_staged(PLAN)
check("same plan, same outcome, same receipt hash",
      a.receipt_hash == b.receipt_hash, a.receipt_hash)
check("timestamps differ while the hash does not",
      a.started_at != b.started_at)
check("receipt binds to the plan", a.plan_hash == PLAN.plan_hash, a.plan_hash)
check("statement records carry a digest of the exact text",
      all(s.sha8 for o in a.operations for s in o.statements))

print("\n=== SAMPLE RECEIPT ===")
eng = sf_engine(rules=[Rule("MODIFY COLUMN \"mobile\"", message="insufficient privileges"),
                       Rule("MODIFY COLUMN \"email\"", kind="transport", message="reset")])
r = SnowflakeExecutor(eng).execute_staged(PLAN, StagePolicy(on_failure=FailurePolicy.CONTINUE))
print("  " + r.explain())
for k, v in r.summary().items():
    print(f"    {k:24s} {v}")

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
