"""
tests/_crash_worker.py — a process that runs the loop and dies where told.

Invoked by test_crash.py as a real subprocess and killed with os._exit(9),
which runs no finally blocks, flushes no buffers and gives the journal no
chance to tidy up after itself. A test that simulates a crash by deleting
Python objects tests the object graph; this tests the file on disk.

The DDL side is a mock, but the mock records what it executed to a
sidecar file, so after the kill the test can ask the only question that
matters: did the warehouse change, and does the journal know?
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aagcp.core.coverage import assess, Column, Inspection, Inventory
from aagcp.core.executors import SnowflakeExecutor, StagePolicy
from aagcp.core.executors.mock import MockEngine
from aagcp.core.executors.snowflake import _policy_name
from aagcp.core.intent import from_slots
from aagcp.core.journal import Journal, Principal
from aagcp.core.orchestrator import Orchestrator
from aagcp.core.plan import ColumnFinding, compile_plan
from aagcp.core.policy import REGISTRY
from aagcp.core.simulate import NullDependencyGraph, RiskTier

ANALYST = Principal("engineer@acme.example", "data-eng", 0)
DPO = Principal("dpo@acme.example", "privacy-officer", 4)
RID = "CRASH-1"

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="DEMO_DB.DEMO_SCHEMA", scope_exclude=[],
                         policy_id="dpdp", audience=["DPO"], confidence=0.95),
                    REGISTRY)
FINDINGS = [
    ColumnFinding("DEMO_DB", "DEMO_SCHEMA", "customers", "email", "email",
                  "EMAIL", 0.99, 1000),
    ColumnFinding("DEMO_DB", "DEMO_SCHEMA", "customers", "mobile", "phone",
                  "PHONE", 0.98, 1000),
]
COLS = [Column(f.database, f.schema, f.table, f.column, "VARCHAR",
               f.row_estimate) for f in FINDINGS]
INV = Inventory(tuple(COLS), source="crash fixture", complete=True)
INSP = [Inspection(c.target, "content_sample", 5000, f.identifier_key, 0.99)
        for c, f in zip(COLS, FINDINGS)]

PLAN = compile_plan(INTENT, FINDINGS, "snowflake")
POLICIES = [_policy_name(o) for o in PLAN.operations]


class RecordingEngine(MockEngine):
    """A mock warehouse whose applied state persists across the crash, the
    way a real one does. `attached` is the set of columns actually governed;
    it is written to disk on every statement, so a kill mid-run leaves the
    same partial state a warehouse would."""

    def __init__(self, state_path):
        self.state_path = state_path
        state = (json.loads(open(state_path).read())
                 if os.path.exists(state_path) else
                 {"attached": [], "statements": []})
        super().__init__(queries={
            "aagcp:prestate": [],
            "POLICY_REFERENCES": [(p,) for p in state["attached"]],
            "INFORMATION_SCHEMA.COLUMNS": []})
        self.state = state

    def cursor(self):
        engine = self

        class Cur:
            def execute(self, sql):
                engine.executed.append(sql)
                if sql.lstrip().upper().startswith("--"):
                    pass
                if "SET MASKING POLICY" in sql:
                    for p in POLICIES:
                        if p in sql and p not in engine.state["attached"]:
                            engine.state["attached"].append(p)
                if not sql.lstrip().startswith("--"):
                    engine.state["statements"].append(sql)
                engine._flush()
                self._rows = engine.rows_for(sql)

            def fetchall(self):
                return getattr(self, "_rows", [])
        return Cur()

    def rows_for(self, sql):
        if "aagcp:prestate" in sql:
            return []
        if "POLICY_REFERENCES" in sql:
            return [(p,) for p in self.state["attached"]]
        return []

    def _flush(self):
        with open(self.state_path, "w") as fh:
            json.dump(self.state, fh)
            fh.flush()
            os.fsync(fh.fileno())


def die(where):
    print(f"[worker] killed at {where}", flush=True)
    os._exit(9)


def main():
    journal_path, state_path, kill_at = sys.argv[1], sys.argv[2], sys.argv[3]
    journal = Journal(journal_path)
    orch = Orchestrator(journal)
    engine = RecordingEngine(state_path)
    executor = SnowflakeExecutor(engine)

    state = orch.resume(RID)

    # --- resume path ---------------------------------------------------
    if state.get("known"):
        if state.get("needs_reconciliation"):
            receipt = orch.reconcile(RID, PLAN, executor, principal=ANALYST)
            print(f"[worker] reconciled: {receipt.verdict.value}", flush=True)
        elif not state.get("executed"):
            orch.execute(RID, PLAN, executor, stage=StagePolicy(),
                         principal=ANALYST)
            print("[worker] executed on resume", flush=True)

        if "verify" not in state["phases"]:
            receipt = orch.receipt_for(RID)
            passed = (receipt.verdict.value == "COMPLETE"
                      and all(o.verified is True for o in receipt.operations))
            orch.verify(RID, passed=passed,
                        evidence={"verified":
                                  sum(1 for o in receipt.operations
                                      if o.verified is True)},
                        principal=DPO)
            print(f"[worker] verified passed={passed}", flush=True)
            if kill_at == "after_verify":
                die("after_verify")

        if "close" not in orch.resume(RID)["phases"]:
            receipt = orch.receipt_for(RID)
            if all(o.verified is True for o in receipt.operations):
                orch.close(RID, principal=ANALYST)
                print("[worker] closed", flush=True)
            else:
                print("[worker] not closable", flush=True)
        return 0

    # --- fresh path ----------------------------------------------------
    orch.observe(RID, INV, INSP, policy=REGISTRY["dpdp"], findings=FINDINGS,
                 principal=ANALYST)
    orch.analyze(RID, FINDINGS, principal=ANALYST)
    plan = orch.plan(RID, INTENT, FINDINGS, principal=ANALYST)
    coverage = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan,
                      findings=FINDINGS)
    forecast = orch.simulate(RID, plan, graph=NullDependencyGraph(),
                             executor=executor, coverage=coverage,
                             budget=RiskTier.LOW, principal=ANALYST)
    orch.approve(RID, forecast, DPO)
    print("[worker] approved", flush=True)
    if kill_at == "after_authorization":
        die("after_authorization")

    if kill_at == "after_execution_before_journal":
        # The exact crash window: write the attempt, apply the DDL, die
        # before the outcome is recorded. Reached by driving the two halves
        # by hand rather than through execute(), which is atomic from the
        # caller's side.
        from aagcp.core.journal import Phase
        from aagcp.core.orchestrator import _digest
        sim = orch._last(RID, Phase.SIMULATE)
        attempt_id = _digest([RID, plan.plan_hash, sim.subject_hash,
                              len(orch._entries(RID))])
        journal.append(RID, Phase.EXECUTE_ATTEMPT, plan.plan_hash,
                       principal=ANALYST,
                       refs={"attempt_id": attempt_id,
                             "forecast_hash": sim.subject_hash,
                             "plan_hash": plan.plan_hash},
                       payload={"operations": len(plan.operations)})
        executor.execute_staged(plan, stage=StagePolicy())
        die("after_execution_before_journal")

    receipt = orch.execute(RID, plan, executor, stage=StagePolicy(),
                           principal=ANALYST)
    print(f"[worker] executed: {receipt.verdict.value}", flush=True)
    if kill_at == "after_execution":
        die("after_execution")

    passed = (receipt.verdict.value == "COMPLETE"
              and all(o.verified is True for o in receipt.operations))
    orch.verify(RID, receipt, passed=passed,
                evidence={"verified": sum(1 for o in receipt.operations
                                          if o.verified is True)},
                principal=DPO)
    print(f"[worker] verified passed={passed}", flush=True)
    if kill_at == "after_verify":
        die("after_verify")

    if passed:
        orch.close(RID, receipt, principal=ANALYST)
        print("[worker] closed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
