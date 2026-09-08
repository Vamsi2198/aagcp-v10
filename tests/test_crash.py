"""Crash consistency. python3 tests/test_crash.py

Four kill points, each a real subprocess terminated with os._exit(9): no
finally blocks, no flush, no cleanup. Then a fresh process opens the same
journal and has to work out what happened.

The question at every point is the same one: does the record agree with
the warehouse, and does the restart avoid doing anything twice.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aagcp.core.journal import Journal, Phase
from aagcp.core.orchestrator import Orchestrator, OrchestratorError
from aagcp.core.plan import compile_plan

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_crash_worker.py")
RID = "CRASH-1"


class Run:
    def __init__(self, label):
        self.dir = tempfile.mkdtemp(prefix=f"aagcp-crash-{label}-")
        self.journal = os.path.join(self.dir, "journal.jsonl")
        self.state = os.path.join(self.dir, "warehouse.json")

    def go(self, kill_at="none"):
        p = subprocess.run(
            [sys.executable, WORKER, self.journal, self.state, kill_at],
            capture_output=True, text=True, timeout=120)
        return p

    @property
    def j(self):
        return Journal(self.journal)

    @property
    def orch(self):
        return Orchestrator(self.j)

    @property
    def warehouse(self):
        if not os.path.exists(self.state):
            return {"attached": [], "statements": []}
        return json.loads(open(self.state).read())

    def phases(self):
        return [e.phase.value for e in self.j.entries if e.request_id == RID]


print("\n=== 0. THE HAPPY PATH, UNINTERRUPTED ===")
r = Run("happy")
p = r.go("none")
check("the worker completes", p.returncode == 0, p.stderr[-160:] or "ok")
check("it reaches CLOSE", "close" in r.phases(), str(r.phases()))
check("both columns are governed in the warehouse",
      len(r.warehouse["attached"]) == 2, str(r.warehouse["attached"]))
check("the chain is consistent", r.j.verify_chain() == [], str(r.j.verify_chain()))
check("the bindings are coherent",
      r.j.verify_bindings(RID) == [], str(r.j.verify_bindings(RID)))
check("attempt and execution are both recorded, once each",
      r.phases().count("execute_attempt") == 1
      and r.phases().count("execute") == 1, str(r.phases()))
check("the evidence chain is complete",
      r.orch.resume(RID)["phases"] ==
      ["observe", "analyze", "plan", "simulate", "approve",
       "execute_attempt", "execute", "verify", "close"],
      str(r.orch.resume(RID)["phases"]))

print("\n=== 1. KILL AFTER AUTHORIZATION ===")
r = Run("authz")
p = r.go("after_authorization")
check("the process died", p.returncode != 0, f"rc={p.returncode}")
st = r.orch.resume(RID)
check("authorized", "approve" in st["phases"], str(st["phases"]))
check("not executed", not st["executed"] and "execute" not in st["phases"])
check("nothing reached the warehouse",
      r.warehouse["attached"] == [], str(r.warehouse["attached"]))
check("no reconciliation is owed", not st["needs_reconciliation"])
p2 = r.go("none")
check("the restart completes the run", p2.returncode == 0, p2.stdout[-120:])
check("it closes", "close" in r.phases(), str(r.phases()))
check("and executed exactly once",
      r.phases().count("execute") == 1, str(r.phases()))

print("\n=== 2. KILL AFTER THE WAREHOUSE CHANGED, BEFORE THE JOURNAL ===")
r = Run("window")
p = r.go("after_execution_before_journal")
check("the process died", p.returncode != 0, f"rc={p.returncode}")
check("the warehouse HAS changed",
      len(r.warehouse["attached"]) == 2, str(r.warehouse["attached"]))
check("the journal has no execution",
      "execute" not in r.phases(), str(r.phases()))
check("but it does have the attempt",
      "execute_attempt" in r.phases(),
      "the write-ahead record is the only reason this is recoverable")
st = r.orch.resume(RID)
check("the restart knows reconciliation is owed",
      st["needs_reconciliation"] and st["next_phases"] == ["reconcile"],
      str(st["next_phases"]))
check("and says why", "may have been changed" in st.get("warning", ""),
      st.get("warning", "")[:56])

before = list(r.warehouse["statements"])
p2 = r.go("none")
after = r.warehouse["statements"]
check("the restart process exits cleanly", p2.returncode == 0,
      (p2.stderr or p2.stdout)[-200:])
check("the restart issued NO further DDL", after == before,
      f"{len(before)} statements before, {len(after)} after")
check("it recorded a reconciliation, not a second execution",
      "reconcile" in r.phases() and "execute" not in r.phases(),
      str(r.phases()))
check("the reconciled receipt says the plan is applied",
      r.orch.receipt_for(RID).verdict.value == "COMPLETE",
      r.orch.receipt_for(RID).verdict.value)
check("the receipt is marked as reconciled, not run",
      r.orch.receipt_for(RID).reconciled is True)
check("the run still closes", "close" in r.phases(), str(r.phases()))
check("bindings stay coherent", r.j.verify_bindings(RID) == [],
      str(r.j.verify_bindings(RID)))

print("\n=== 3. KILL AFTER EXECUTION, BEFORE VERIFICATION ===")
r = Run("preverify")
p = r.go("after_execution")
check("the process died", p.returncode != 0, f"rc={p.returncode}")
st = r.orch.resume(RID)
check("the execution is preserved", st["executed"], str(st["phases"]))
check("no reconciliation is owed", not st["needs_reconciliation"])
check("the receipt survived the process that made it",
      st["receipt_available"] and r.orch.receipt_for(RID) is not None)
check("it rehydrates to its recorded hash",
      r.orch.receipt_for(RID).receipt_hash ==
      [e.subject_hash for e in r.j.entries
       if e.phase is Phase.EXECUTE][-1],
      r.orch.receipt_for(RID).receipt_hash)
before = list(r.warehouse["statements"])
p2 = r.go("none")
check("the restart process exits cleanly", p2.returncode == 0,
      (p2.stderr or p2.stdout)[-200:])
check("verification resumes without re-executing",
      r.warehouse["statements"] == before
      and r.phases().count("execute") == 1, str(r.phases()))
check("it closes", "close" in r.phases())

print("\n=== 4. KILL AFTER VERIFICATION, BEFORE SETTLEMENT ===")
r = Run("presettle")
p = r.go("after_verify")
check("the process died", p.returncode != 0, f"rc={p.returncode}")
st = r.orch.resume(RID)
check("the verification is preserved", "verify" in st["phases"],
      str(st["phases"]))
check("the request is still open", not st["closed"])
before = list(r.warehouse["statements"])
p2 = r.go("none")
check("the restart process exits cleanly", p2.returncode == 0,
      (p2.stderr or p2.stdout)[-200:])
check("it settles without re-executing",
      "close" in r.phases() and r.phases().count("execute") == 1
      and r.warehouse["statements"] == before, str(r.phases()))
check("and without re-verifying",
      r.phases().count("verify") == 1, str(r.phases()))

print("\n=== 5. EXECUTING TWICE IS REFUSED OUTRIGHT ===")
r = Run("double")
r.go("none")
from aagcp.core.executors import SnowflakeExecutor
sys.path.insert(0, os.path.dirname(WORKER))
import _crash_worker as W
orch = r.orch
try:
    orch.execute(RID, W.PLAN, SnowflakeExecutor(W.RecordingEngine(r.state)))
    check("a replayed execute call is refused", False, "it ran again")
except OrchestratorError as e:
    check("a replayed execute call is refused",
          e.code in ("THIS_PLAN_HAS_ALREADY_BEEN_EXECUTED",
                     "REQUEST_IS_ALREADY_CLOSED"), e.code)

r2 = Run("unresolved")
r2.go("after_execution_before_journal")
try:
    Orchestrator(r2.j).execute(RID, W.PLAN,
                               SnowflakeExecutor(W.RecordingEngine(r2.state)))
    check("executing over an unresolved attempt is refused", False, "it ran")
except OrchestratorError as e:
    check("executing over an unresolved attempt is refused",
          e.code == "AN_EARLIER_ATTEMPT_WAS_NEVER_RESOLVED", e.detail[:60])

print("\n=== 6. A FORGED DOUBLE EXECUTION IS CAUGHT BY THE AUDIT ===")
r = Run("forged")
r.go("none")
j = r.j
ex = [e for e in j.entries if e.phase is Phase.EXECUTE][0]
j.append(RID, Phase.EXECUTE, ex.subject_hash, refs=dict(ex.refs),
         payload={"verdict": "COMPLETE"})
check("two executions against one attempt are caught",
      any(x["cause"] == "MORE_THAN_ONE_EXECUTION_FOR_ONE_ATTEMPT"
          for x in j.verify_bindings(RID)),
      str([x["cause"] for x in j.verify_bindings(RID)]))
j2 = Journal(os.path.join(Run("orphan").dir, "j.jsonl"))
j2.append("R", Phase.EXECUTE, "R-1", refs={"attempt_id": "never"},
          payload={"verdict": "COMPLETE"})
check("an execution with no attempt is caught",
      any(x["cause"] == "EXECUTION_WITH_NO_PRECEDING_ATTEMPT"
          for x in j2.verify_bindings()),
      str([x["cause"] for x in j2.verify_bindings()]))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
