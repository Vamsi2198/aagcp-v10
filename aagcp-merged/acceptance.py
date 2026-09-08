"""
acceptance.py — your acceptance test, as something a script asserts rather
than something we conclude.

    python3 acceptance.py --config platform.yaml            # live
    python3 acceptance.py --dry-run                         # offline, mocked

The clauses, verbatim from the brief:

  install AAGCP, connect a non-production Snowflake account, define a PII
  policy, submit a change, receive a quantified simulation, approve it as
  a named user, execute it, survive a process restart, verify the
  resulting state, and retrieve an immutable audit trail — without
  touching your source code.

Each is a gate below. A gate either passes, fails with a reason, or is
SKIPPED with the thing that is missing named. It does not average. The
summary is the worst outcome across all of them, because an acceptance
test that reports 9 of 11 is a progress bar, not an acceptance test.

Two clauses are worded in ways this harness deliberately does not honour:

  "define a PII policy" — the harness loads one from the config file. If
  policies still had to be written in Python this gate would fail, which
  is the point of it.

  "immutable audit trail" — asserted as TAMPER-EVIDENT, not immutable, and
  the gate additionally requires that a checkpoint was exported. A chain
  the operator holds and can rewrite is not evidence, and there is a test
  in test_journal.py that rebuilds one to prove it. A harness that ticked
  "immutable" for a local file would be lying on the most important line.

The restart is a real one when --exec-restart is passed: the process
re-execs itself between SIMULATE and EXECUTE. Without it the restart is
simulated by discarding every object and reopening the journal, which
tests the same code path and is honest about being less.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aagcp.core.coverage import assess, Column, Inspection, Inventory
from aagcp.core.executors import SnowflakeExecutor, StagePolicy
from aagcp.core.executors.mock import MockEngine
from aagcp.core.intent import from_slots
from aagcp.core.journal import Journal, Phase, Principal
from aagcp.core.observability import health, trace
from aagcp.core.orchestrator import Orchestrator, OrchestratorError
from aagcp.core.plan import ColumnFinding as Finding
from aagcp.core.policy import REGISTRY, Policy, Identifier, Treatment
from aagcp.core.simulate import (Decision, RiskTier, NullDependencyGraph,
                           StaticDependencyGraph)

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
RESULTS = []


def gate(name, status, detail=""):
    RESULTS.append((name, status, detail))
    mark = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP"}[status]
    print(f"  {mark}  {name}" + (f"\n        {detail}" if detail else ""))


def policy_from_config(cfg) -> Policy:
    """Clause: define a PII policy without touching source. Identifiers
    come from the config; a treatment with no citation is refused here the
    same way policy.py refuses one."""
    spec = cfg.get("policy")
    if not spec:
        return REGISTRY["dpdp"]
    ids = []
    for i in spec.get("identifiers", []):
        if not i.get("citation"):
            raise ValueError(f"identifier {i.get('key')} has no citation")
        ids.append(Identifier(key=i["key"], label=i.get("label", i["key"]),
                              treatment=Treatment(i["treatment"]),
                              citation=i["citation"]))
    return Policy(policy_id=spec["id"], name=spec.get("name", spec["id"]),
                  authority=spec.get("authority") or spec.get("regime", ""),
                  identifiers=tuple(ids),
                  closed_list=bool(spec.get("closed_list", False)),
                  note=spec.get("note", ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--journal", default="./aagcp-acceptance.jsonl")
    ap.add_argument("--exec-restart", action="store_true")
    ap.add_argument("--phase", default="start")
    args = ap.parse_args()

    request_id = "ACCEPT-1"
    analyst = Principal("engineer@acme.example", "data-eng", 0)
    dpo = Principal("dpo@acme.example", "privacy-officer", 4)

    print(f"\nAAGCP acceptance — {'dry run' if args.dry_run else 'live'}\n")

    # --- 1. install ---------------------------------------------------
    try:
        import aagcp.core as core, platform as plat  # noqa
        gate("installs and imports without source edits", PASS,
             f"core + platform importable from {Path(__file__).parent}")
    except Exception as exc:
        gate("installs and imports without source edits", FAIL, str(exc))
        return summarise()

    # --- 2. connect ---------------------------------------------------
    conn, cfg = None, {}
    if args.dry_run or not args.config:
        conn = MockEngine(queries={"aagcp:prestate": [],
                                   "POLICY_REFERENCES": [],
                                   "INFORMATION_SCHEMA.COLUMNS": []})
        gate("connects to a non-production Snowflake account", SKIP,
             "--dry-run: using MockEngine. Nothing below this line has "
             "touched a warehouse.")
    else:
        try:
            cfg = plat.load_config(args.config)
            conn = plat.snowflake_from_config(args.config)
            conn.connect()
            cur = conn.cursor()
            cur.execute("SELECT CURRENT_ROLE(), CURRENT_WAREHOUSE();")
            role, wh = cur.fetchall()[0]
            gate("connects to a non-production Snowflake account", PASS,
                 f"role={role} warehouse={wh}")
        except Exception as exc:
            gate("connects to a non-production Snowflake account", FAIL,
                 f"{type(exc).__name__}: {exc}")
            return summarise()

    # --- 3. define a policy from config -------------------------------
    try:
        policy = policy_from_config(cfg)
        gate("defines a PII policy without touching source", PASS,
             f"{policy.policy_id}: {len(policy.identifiers)} identifier(s), "
             f"every one carrying a citation")
    except Exception as exc:
        gate("defines a PII policy without touching source", FAIL, str(exc))
        return summarise()

    # --- 4. submit a change -------------------------------------------
    journal = Journal(args.journal)
    orch = Orchestrator(journal)
    reg = {policy.policy_id: policy}
    try:
        intent = from_slots(
            dict(action="mask", scope_kind="schema",
                 scope_value=f"{cfg.get('platform', {}).get('database', 'DEMO_DB')}"
                             f".{cfg.get('platform', {}).get('schema', 'DEMO_SCHEMA')}",
                 scope_exclude=[], policy_id=policy.policy_id,
                 audience=["DPO"], confidence=0.95), reg)
        findings = [
            Finding("DEMO_DB", "DEMO_SCHEMA", "customers", "email", "email",
                    "EMAIL", 0.99, 1000),
            Finding("DEMO_DB", "DEMO_SCHEMA", "customers", "mobile", "phone",
                    "PHONE", 0.98, 1000),
        ]
        cols = [Column(f.database, f.schema, f.table, f.column, "VARCHAR",
                       f.row_estimate) for f in findings]
        inv = Inventory(tuple(cols), source="acceptance fixture", complete=True)
        insp = [Inspection(c.target, "content_sample", 5000, f.identifier_key,
                           0.99) for c, f in zip(cols, findings)]
        orch.observe(request_id, inv, insp, policy=policy, findings=findings,
                     principal=analyst)
        orch.analyze(request_id, findings, principal=analyst)
        plan = orch.plan(request_id, intent, findings, principal=analyst)
        gate("submits a change", PASS,
             f"plan {plan.plan_hash}, {len(plan.operations)} operation(s)")
    except Exception as exc:
        gate("submits a change", FAIL, f"{type(exc).__name__}: {exc}")
        return summarise()

    # --- 5. quantified simulation -------------------------------------
    executor = SnowflakeExecutor(conn)
    try:
        coverage = assess(inv, insp, policy=policy, plan=plan,
                          findings=findings)
        forecast = orch.simulate(
            request_id, plan,
            # No dependency catalog is wired in a demo account, and
            # pretending otherwise is what makes an acceptance test flatter
            # the system: with a fully-known graph this fixture forecasts
            # LOW/AUTONOMOUS and the authorization clause never fires.
            # NullDependencyGraph is the true state of a fresh install.
            graph=NullDependencyGraph(),
            executor=executor, coverage=coverage, budget=RiskTier.LOW,
            principal=analyst)
        gate("receives a quantified simulation", PASS,
             f"tier {forecast.tier.label}, {forecast.decision.value}, "
             f"{forecast.columns_affected} column(s), "
             f"~{forecast.rows_estimate:,} rows, "
             f"{forecast.total_consumers} downstream, "
             f"complete={forecast.complete}")
    except Exception as exc:
        gate("receives a quantified simulation", FAIL,
             f"{type(exc).__name__}: {exc}")
        return summarise()

    # --- 6. authorization enforced ------------------------------------
    if forecast.decision is not Decision.APPROVAL_REQUIRED:
        gate("the forecast demands approval for this change", FAIL,
             f"decision was {forecast.decision.value}; the authorization "
             f"clauses below cannot be exercised on a change the system is "
             f"entitled to make unattended. Lower the autonomy budget or "
             f"use a change with real blast radius.")
        return summarise()
    try:
        orch.execute(request_id, plan, executor, principal=analyst)
        gate("refuses to execute without an approval", FAIL,
             "it executed unapproved")
        return summarise()
    except OrchestratorError as exc:
        if exc.code == "NO_APPROVAL_RECORDED_FOR_THIS_FORECAST":
            gate("refuses to execute without an approval", PASS, exc.code)
        else:
            gate("refuses to execute without an approval", FAIL, exc.code)

    try:
        orch.approve(request_id, forecast, analyst)
        gate("refuses self-approval", FAIL, "the requester approved")
    except OrchestratorError as exc:
        gate("refuses self-approval", PASS, exc.code)

    orch.approve(request_id, forecast, dpo)
    gate("approves as a named user", PASS,
         f"{dpo.principal_id} ({dpo.role}), tier authority "
         f"{dpo.max_approval_tier} against forecast tier "
         f"{int(forecast.tier)}")

    # --- 7. restart ----------------------------------------------------
    if args.exec_restart and args.phase == "start":
        os.execv(sys.executable, [sys.executable, __file__, "--phase",
                                  "resumed", "--journal", args.journal]
                 + (["--dry-run"] if args.dry_run else
                    ["--config", args.config]))

    plan_hash_before = plan.plan_hash
    del orch, journal
    journal = Journal(args.journal)
    orch = Orchestrator(journal)
    state = orch.resume(request_id)
    if state["known"] and state["current_phase"] == "approve":
        gate("survives a process restart", PASS,
             f"reopened at '{state['current_phase']}' from "
             f"{state['entries']} journal entries"
             + ("; re-exec" if args.exec_restart else
                "; in-process reopen, not a real fork"))
    else:
        gate("survives a process restart", FAIL, json.dumps(state)[:180])
        return summarise()

    # --- 8. execute ----------------------------------------------------
    try:
        receipt = orch.execute(request_id, plan, executor,
                               stage=StagePolicy(), principal=analyst)
        ok = receipt.verdict.value in ("COMPLETE", "PARTIAL",
                                       "HALTED_AT_CANARY", "INCONCLUSIVE")
        gate("executes against the data system", PASS if ok else FAIL,
             receipt.explain())
    except Exception as exc:
        gate("executes against the data system", FAIL,
             f"{type(exc).__name__}: {exc}")
        return summarise()

    if plan.plan_hash != plan_hash_before:
        gate("executes the plan that was approved", FAIL, "plan hash moved")
    else:
        gate("executes the plan that was approved", PASS,
             f"{plan.plan_hash} matches the recorded and approved plan")

    # --- 8b. idempotency ----------------------------------------------
    try:
        orch.execute(request_id, plan, executor, principal=analyst)
        gate("refuses to execute the same plan twice", FAIL, "it ran again")
    except OrchestratorError as exc:
        gate("refuses to execute the same plan twice", PASS, exc.code)
    st = orch.resume(request_id)
    gate("the execution is recoverable after a restart",
         PASS if st.get("receipt_available") and not st.get("needs_reconciliation")
         else FAIL,
         f"receipt rehydrates from the journal; "
         f"attempt resolved={not st.get('needs_reconciliation')}")

    # --- 9. independent verification ----------------------------------
    passed = receipt.verdict.value == "COMPLETE" and all(
        o.verified is True for o in receipt.operations)
    orch.verify(request_id, receipt, passed=passed,
                evidence={"verified_operations":
                          sum(1 for o in receipt.operations
                              if o.verified is True),
                          "unverified":
                          sum(1 for o in receipt.operations
                              if o.verified is not True)})
    if args.dry_run:
        gate("independently verifies the resulting state", SKIP,
             "MockEngine answers the verification query, so this confirms "
             "the code path and nothing about a warehouse")
    else:
        gate("independently verifies the resulting state",
             PASS if passed else FAIL,
             f"re-read the catalog: "
             f"{sum(1 for o in receipt.operations if o.verified is True)} of "
             f"{len(receipt.operations)} controls confirmed")

    # --- 10. refuses to close if anything is wrong ---------------------
    if not passed:
        try:
            orch.close(request_id, receipt, principal=analyst)
            gate("refuses to close if anything is wrong", FAIL, "it closed")
        except OrchestratorError as exc:
            gate("refuses to close if anything is wrong", PASS, exc.code)
    else:
        lesson = orch.learn(request_id, forecast, receipt)
        orch.close(request_id, receipt, principal=analyst, lesson=lesson)
        gate("refuses to close if anything is wrong", PASS,
             "nothing was wrong; the negative path is asserted in "
             "test_orchestrator.py and test_erase_executors.py")

    # --- 11. audit trail ----------------------------------------------
    chain = journal.verify_chain()
    binds = journal.verify_bindings(request_id)
    cp = journal.checkpoint()
    cp_path = Path(args.journal).with_suffix(".checkpoint.json")
    cp_path.write_text(json.dumps(cp.to_dict(), indent=2))
    if chain or binds:
        gate("retrieves a tamper-evident audit trail", FAIL,
             json.dumps((chain + binds)[:2]))
    else:
        gate("retrieves a tamper-evident audit trail", PASS,
             f"{len(journal.entries)} linked entries, head {cp.head[:16]}…, "
             f"bindings coherent, checkpoint written to {cp_path.name}")
        gate("audit trail is IMMUTABLE", SKIP,
             "not asserted and not true. The chain is tamper-evident only "
             "against parties who cannot rewrite the file; test_journal.py "
             "contains a rewrite that passes verify_chain cleanly. This "
             "becomes evidence when the checkpoint head is witnessed by "
             "someone other than the operator, which nothing here does.")

    spans = trace(journal, request_id)
    h = health(journal, now=time.time())
    gate("emits redacted telemetry from the record", PASS,
         f"{len(spans)} spans, {sum(len(s.dropped) for s in spans)} "
         f"attribute(s) dropped by the allowlist; autonomy "
         f"{h.autonomy_rate:.0%}, integrity "
         f"{'ok' if h.integrity_ok else 'BROKEN'}")

    return summarise()


def summarise() -> int:
    print("\n" + "=" * 64)
    fails = [r for r in RESULTS if r[1] == FAIL]
    skips = [r for r in RESULTS if r[1] == SKIP]
    print(f"{len(RESULTS)} gates: {len(RESULTS) - len(fails) - len(skips)} "
          f"pass, {len(fails)} fail, {len(skips)} skipped")
    if fails:
        print("\nFAILED — not acceptable:")
        for n, _, d in fails:
            print(f"  {n}\n    {d[:200]}")
    if skips:
        print("\nSKIPPED — unproven, and the summary is not a pass:")
        for n, _, d in skips:
            print(f"  {n}\n    {d[:200]}")
    verdict = ("NOT ACCEPTED" if fails else
               "UNPROVEN" if skips else "ACCEPTED")
    print(f"\nverdict: {verdict}")
    return 1 if fails or skips else 0


if __name__ == "__main__":
    sys.exit(main())
