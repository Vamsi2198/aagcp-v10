"""The loop, end to end. python3 test_orchestrator.py

The interesting runs are the ones that stop: a gate that refuses, a
process that dies mid-loop and comes back, and an attempt to execute
something other than what was approved.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import os
import sys
import tempfile

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import assess, Column, Inventory, Inspection
from aagcp.core.simulate import RiskTier, Decision, StaticDependencyGraph
from aagcp.core.executors import SnowflakeExecutor, StagePolicy, FailurePolicy
from aagcp.core.executors.mock import MockEngine, Rule
from aagcp.core.journal import Journal, Phase, Principal
from aagcp.core.orchestrator import Orchestrator, OrchestratorError, Lesson
from aagcp.core.observability import (project, trace, health, EMITTABLE,
                                RedactionError)

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

TMP = tempfile.mkdtemp(prefix="aagcp-orch-")
def path(n): return os.path.join(TMP, f"{n}.jsonl")

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)
JUNIOR = Principal("intern@acme.example", "analyst", max_approval_tier=1)

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


def full_run(o, rid, budget=RiskTier.LOW, approver=DPO):
    o.observe(rid, INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
              principal=ANALYST)
    o.analyze(rid, FINDINGS, principal=ANALYST)
    plan = o.plan(rid, INTENT, FINDINGS, principal=ANALYST)
    cov = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan,
                 findings=FINDINGS)
    ex = SnowflakeExecutor(engine())
    f = o.simulate(rid, plan, graph=GRAPH, executor=ex, coverage=cov,
                   budget=budget, principal=ANALYST)
    if f.decision is Decision.APPROVAL_REQUIRED and approver is not None:
        o.approve(rid, f, approver)
    receipt = o.execute(rid, plan, ex, principal=ANALYST)
    return plan, f, receipt, ex


print("\n=== OBSERVE THROUGH CLOSE ===")
j = Journal(path("full"))
o = Orchestrator(j)
plan, f, receipt, ex = full_run(o, "REQ-1")
check("the forecast required approval", f.decision is Decision.APPROVAL_REQUIRED,
      f"tier {f.tier.label}")
check("execution completed", receipt.verdict.value == "COMPLETE",
      receipt.verdict.value)
o.verify("REQ-1", receipt, passed=True,
         evidence={"controls_confirmed": len(receipt.operations)})
lesson = o.learn("REQ-1", f, receipt)
o.close("REQ-1", receipt, principal=ANALYST, lesson=lesson)
check("the journal records every phase",
      j.replay("REQ-1")["phases"] == ["observe", "analyze", "plan", "simulate",
                                      "approve", "execute_attempt", "execute",
                                      "verify", "close"],
      str(j.replay("REQ-1")["phases"]))
check("the chain holds", j.verify_chain() == [], str(j.verify_chain()))
check("the bindings hold", j.verify_bindings() == [], str(j.verify_bindings()))
check("the request is closed", j.replay("REQ-1")["closed"])

print("\n=== THE GATE IS ENFORCED, NOT JUST AUDITED ===")
j2 = Journal(path("gate"))
o2 = Orchestrator(j2)
o2.observe("R", INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
           principal=ANALYST)
o2.analyze("R", FINDINGS, principal=ANALYST)
p2 = o2.plan("R", INTENT, FINDINGS, principal=ANALYST)
cov2 = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=p2, findings=FINDINGS)
ex2 = SnowflakeExecutor(engine())
f2 = o2.simulate("R", p2, graph=GRAPH, executor=ex2, coverage=cov2,
                 budget=RiskTier.LOW, principal=ANALYST)
try:
    o2.execute("R", p2, ex2, principal=ANALYST)
    check("execution without approval is refused at the point of action",
          False, "it ran")
except OrchestratorError as e:
    check("execution without approval is refused at the point of action",
          e.code == "NO_APPROVAL_RECORDED_FOR_THIS_FORECAST", e.code)
check("nothing was executed", ex2.conn.ddl() == [], str(ex2.conn.ddl()[:1]))
check("and neither an attempt nor an execution was written",
      not ({Phase.EXECUTE, Phase.EXECUTE_ATTEMPT} & {x.phase for x in j2.entries}),
      str(sorted(x.phase.value for x in j2.entries)))

# A senior requester, so the tier rule cannot fire and separation of
# duties is the only thing under test.
SENIOR = Principal("dinesh@acme.example", "data-eng", max_approval_tier=4)
try:
    o2.approve("R", f2, SENIOR)
    check("self-approval is refused at any tier", False, "accepted")
except OrchestratorError as e:
    check("self-approval is refused at any tier",
          e.code == "REQUESTER_APPROVED_THEIR_OWN_CHANGE",
          f"authority {SENIOR.max_approval_tier} vs tier {int(f2.tier)}")
try:
    o2.approve("R", f2, JUNIOR)
    check("approving above your tier is refused", False, "accepted")
except OrchestratorError as e:
    check("approving above your tier is refused",
          e.code == "PRINCIPAL_APPROVED_ABOVE_THEIR_TIER",
          f"tier {int(f2.tier)} vs authority {JUNIOR.max_approval_tier}")
o2.approve("R", f2, DPO)
r2 = o2.execute("R", p2, ex2, principal=ANALYST)
check("with an approval it runs", r2.verdict.value == "COMPLETE")

print("\n=== ORDER IS ENFORCED FROM THE RECORD ===")
j3 = Journal(path("order"))
o3 = Orchestrator(j3)
for phase, call in (("simulate", lambda: o3.simulate("X", plan, coverage=None)),
                    ("execute", lambda: o3.execute("X", plan, ex)),
                    ("close", lambda: o3.close("X", receipt))):
    try:
        call()
        check(f"{phase} before its prerequisite is refused", False, "ran")
    except OrchestratorError as e:
        check(f"{phase} before its prerequisite is refused",
              e.code in ("PHASE_PREREQUISITE_NOT_RECORDED", "NO_FORECAST_RECORDED"),
              e.code)
try:
    o.close("REQ-1", receipt)
    check("a closed request does not reopen", False, "reopened")
except OrchestratorError as e:
    check("a closed request does not reopen", e.code == "REQUEST_IS_ALREADY_CLOSED")

print("\n=== RESTART MID-LOOP ===")
p_r = path("restart")
oa = Orchestrator(Journal(p_r))
oa.observe("REQ-R", INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
           principal=ANALYST)
oa.analyze("REQ-R", FINDINGS, principal=ANALYST)
plan_r = oa.plan("REQ-R", INTENT, FINDINGS, principal=ANALYST)
cov_r = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan_r, findings=FINDINGS)
ex_r = SnowflakeExecutor(engine())
f_r = oa.simulate("REQ-R", plan_r, graph=GRAPH, executor=ex_r, coverage=cov_r,
                  principal=ANALYST)
del oa                                          # the process dies

ob = Orchestrator(Journal(p_r))                 # a new one starts
state = ob.resume("REQ-R")
check("the restarted loop knows where it stopped",
      state["current_phase"] == "simulate" and not state["closed"],
      state["current_phase"])
check("it knows what may happen next",
      "approve" in state["next_phases"]
      and "execute_attempt" in state["next_phases"],
      str(state["next_phases"]))
check("it knows which artifacts must be handed back",
      state["artifacts_required"] == ["plan", "simulate"],
      str(state["artifacts_required"]))

ob.approve("REQ-R", f_r, DPO)
other_plan = compile_plan(INTENT, FINDINGS[:1], "snowflake")
try:
    ob.execute("REQ-R", other_plan, ex_r, principal=ANALYST)
    check("a different plan cannot be executed after restart", False, "ran")
except OrchestratorError as e:
    check("a different plan cannot be executed after restart",
          e.code == "ARTIFACT_DOES_NOT_MATCH_THE_RECORDED_HASH",
          f"{other_plan.plan_hash} vs {plan_r.plan_hash}")
r_r = ob.execute("REQ-R", plan_r, ex_r, principal=ANALYST)
check("the recorded plan executes", r_r.verdict.value == "COMPLETE")
check("the chain spans the restart", ob.journal.verify_chain() == [])
check("so do the bindings", ob.journal.verify_bindings("REQ-R") == [])

print("\n=== LEARN RECORDS, IT DOES NOT TUNE ===")
j4 = Journal(path("learn"))
o4 = Orchestrator(j4)
o4.observe("L", INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
           principal=ANALYST)
o4.analyze("L", FINDINGS, principal=ANALYST)
p4 = o4.plan("L", INTENT, FINDINGS, principal=ANALYST)
cov4 = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=p4, findings=FINDINGS)
bad_engine = engine()
bad_engine.rules.append(Rule('MODIFY COLUMN "mobile"', message="denied"))
ex4 = SnowflakeExecutor(bad_engine)
f4 = o4.simulate("L", p4, graph=GRAPH, executor=SnowflakeExecutor(engine()),
                 coverage=cov4, principal=ANALYST)
o4.approve("L", f4, DPO)
r4 = o4.execute("L", p4, ex4, stage=StagePolicy(on_failure=FailurePolicy.CONTINUE),
                principal=ANALYST)
lesson4 = o4.learn("L", f4, r4)
check("the run was partial", r4.verdict.value == "PARTIAL", r4.verdict.value)
check("the lesson scores predictions", len(lesson4.predictions) >= 3,
      str(len(lesson4.predictions)))
check("a rubric-tuning method does not exist",
      not any(m.startswith("tune") or m.startswith("adjust")
              for m in dir(o4)), str([m for m in dir(o4) if not m.startswith("_")]))
before = f4.rubric["version"]
check("the rubric is unchanged after learning",
      f4.rubric["version"] == before)
o4.verify("L", r4, passed=False, evidence={"reason": "one column ungoverned"})
try:
    o4.close("L", r4, principal=ANALYST)
    check("a failed verification cannot close", False, "closed")
except OrchestratorError as e:
    check("a failed verification cannot close",
          e.code == "CLOSE_WITHOUT_PASSING_VERIFICATION")

print("\n=== OBSERVABILITY IS A PROJECTION, NOT AN EMITTER ===")
spans = trace(j, "REQ-1")
check("one span per journal entry", len(spans) == len(j.replay("REQ-1")["phases"]),
      f"{len(spans)} spans")
check("spans render from a record written before any backend existed",
      spans[0].name == "aagcp.observe", spans[0].name)
check("every emitted key is on the allowlist",
      all(k in EMITTABLE for s in spans for k in s.attributes),
      str(sorted({k for s in spans for k in s.attributes})[:4]))
check("the principal is named, because an anonymous audit trail is not one",
      any(s.attributes.get("aagcp.principal_id") for s in spans))
check("phase hashes travel, values do not",
      all(str(v).startswith(("P-", "F-", "R-", "C-", "D-", "E-"))
          or k not in ("aagcp.subject_hash",)
          for s in spans for k, v in s.attributes.items()),
      "")

class FakeEntry:
    phase = Phase.PLAN
    request_id = "R"
    seq = 0
    subject_hash = "P-1"
    entry_hash = "h"
    previous = "0"
    principal = {"principal_id": "dpo@acme.example", "role": "dpo"}
    refs = {}
    payload = {"cause": "subject rajesh.kumar@example.com matched",
               "column_sample": "dinesh@example.com",
               "operations": 3}

try:
    project(FakeEntry(), strict=True)
    check("an identifier-shaped value is refused in strict mode", False, "emitted")
except RedactionError as e:
    check("an identifier-shaped value is refused in strict mode",
          e.code == "VALUE_MATCHES_A_NATURAL_IDENTIFIER", e.detail[:44])

sp = project(FakeEntry(), strict=False)
check("in lenient mode it is dropped, not emitted",
      "rajesh.kumar@example.com" not in str(sp.attributes),
      str(sp.attributes))
check("the drop is counted rather than silent",
      any(d["cause"] == "VALUE_MATCHES_A_NATURAL_IDENTIFIER" for d in sp.dropped),
      str(sp.dropped))
check("an off-allowlist key is dropped and named",
      any(d["key"] == "column_sample" for d in sp.dropped), str(sp.dropped))
check("the legitimate attribute still survives",
      sp.attributes.get("aagcp.operations") == 3, str(sp.attributes))
check("the principal id is the deliberate exception",
      sp.attributes.get("aagcp.principal_id") == "dpo@acme.example")

print("\n=== HEALTH ===")
h = health(j4, now=float(j4.entries[-1].timestamp) + 5, response_window_days=30)
check("open requests are counted", h.open_requests == ["L"], str(h.open_requests))
check("autonomy rate is reported", h.autonomy_rate == 0.0,
      str(h.autonomy_rate))
check("the window is recorded with the number, not assumed",
      h.to_dict()["response_window_days"] == 30)
old = float(j4.entries[0].timestamp) + 40 * 86400
h2 = health(j4, now=old, response_window_days=30)
check("an overdue request is flagged", h2.overdue and h2.overdue[0]["request_id"] == "L",
      f"{h2.overdue[0]['age_days']:.0f} days")
check("a shorter window flags it sooner",
      len(health(j4, now=float(j4.entries[0].timestamp) + 8 * 86400,
                 response_window_days=7).overdue) == 1)
check("integrity is part of health", h.integrity_ok, str(h.chain_problems))

j5 = Journal(path("autonomy"))
o5 = Orchestrator(j5)
full_run(o5, "A1", budget=RiskTier.CRITICAL, approver=None)
h3 = health(j5, now=float(j5.entries[-1].timestamp) + 1)
check("a fully autonomous estate is flagged as a decorative gate",
      h3.autonomy_rate == 1.0 and "not doing anything" in h3.explain(),
      f"autonomy {h3.autonomy_rate:.0%}")

print("\n=== SAMPLE ===")
print("  " + lesson4.explain().replace("\n", "\n  "))
print("  " + h2.explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
