"""Live API playground for aagcp/api.py.

Full mode:  drives observe/analyze/plan/simulate in-process against a journal
             file, then serves the HTTP API on 127.0.0.1:8099.
--serve-only: restart simulation — same journal file, EMPTY in-memory registry,
             to demonstrate FORECAST_NOT_IN_MEMORY / PLAN_NOT_IN_MEMORY.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import assess, Column, Inventory, Inspection
from aagcp.core.simulate import StaticDependencyGraph
from aagcp.core.executors import SnowflakeExecutor
from aagcp.core.executors.mock import MockEngine
from aagcp.core.executors.snowflake import _policy_name
from aagcp.core.journal import Journal, Principal
from aagcp.core.orchestrator import Orchestrator
from aagcp import api

HOST, PORT = "127.0.0.1", 8099
JPATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "demo-api-journal.jsonl")
BASE = f"http://{HOST}:{PORT}"

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)
TOKENS = {"tk-analyst": ANALYST, "tk-dpo": DPO}

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="SALES.PUBLIC", scope_exclude=[],
                         policy_id="dpdp", audience=["DPO"], confidence=0.95),
                    REGISTRY)
FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email",  "email", "EMAIL", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "mobile", "phone", "PHONE", .98, 184000),
]
COLUMNS = [Column("ACME", "PUBLIC", "customers", f.column, "VARCHAR", 184000)
           for f in FINDINGS]
INV = Inventory(tuple(COLUMNS), source="snowflake catalog", complete=True)
INSP = [Inspection(c.target, "content_sample", 5000, f.identifier_key, .99)
        for c, f in zip(COLUMNS, FINDINGS)]
GRAPH = StaticDependencyGraph({}, known=["ACME.PUBLIC.customers"])


def executor_factory(policy_names):
    return lambda: SnowflakeExecutor(MockEngine(
        queries={"aagcp:prestate": [],
                 "POLICY_REFERENCES": [(n,) for n in policy_names],
                 "INFORMATION_SCHEMA.COLUMNS": []}))


def main():
    serve_only = "--serve-only" in sys.argv
    registry = api.Registry(tokens=TOKENS)

    if not serve_only:
        if os.path.exists(JPATH):
            os.remove(JPATH)
        j = Journal(JPATH)
        o = Orchestrator(j)
        o.observe("REQ-DEMO", INV, INSP, policy=REGISTRY["dpdp"],
                  findings=FINDINGS, principal=ANALYST)
        o.analyze("REQ-DEMO", FINDINGS, principal=ANALYST)
        plan = o.plan("REQ-DEMO", INTENT, FINDINGS, principal=ANALYST)
        cov = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan,
                     findings=FINDINGS)
        names = [_policy_name(op) for op in plan.operations]
        ex = executor_factory(names)()
        f = o.simulate("REQ-DEMO", plan, graph=GRAPH, executor=ex, coverage=cov,
                       principal=ANALYST)
        registry.plans["REQ-DEMO"] = plan
        registry.forecasts["REQ-DEMO"] = f
        registry.executor_factory = executor_factory(names)
        print(f"in-process phases done: forecast {f.tier.label} "
              f"{f.decision.value}, awaiting approval\n")

    server, thread = api.serve(JPATH, registry, HOST, PORT)
    mode = "RESTARTED (empty in-memory registry)" if serve_only else "full"
    print(f"=== aagcp API listening on {BASE}  [{mode}] ===\n")
    print("tokens:  tk-analyst  (dinesh@acme.example, tier 0 — requester)")
    print("         tk-dpo      (dpo@acme.example, tier 4 — approver)\n")
    print("try, in order:\n")
    print(f"  curl {BASE}/healthz")
    print(f"  curl {BASE}/checkpoint")
    print(f"  curl -i {BASE}/requests                      # no token -> 401")
    print(f'  curl -H "Authorization: Bearer tk-analyst" {BASE}/requests')
    print(f'  curl -H "Authorization: Bearer tk-analyst" {BASE}/requests/REQ-DEMO')
    print(f'  curl -H "Authorization: Bearer tk-analyst" {BASE}/requests/REQ-DEMO/audit')
    print(f'  curl -X POST -H "Authorization: Bearer tk-analyst" '
          f'{BASE}/requests/REQ-DEMO/approve          # self-approval -> 409')
    print(f'  curl -X POST -H "Authorization: Bearer tk-dpo" '
          f'{BASE}/requests/REQ-DEMO/approve')
    print(f'  curl -X POST -H "Authorization: Bearer tk-analyst" '
          f'{BASE}/requests/REQ-DEMO/execute')
    print(f'  curl -X POST -H "Authorization: Bearer tk-dpo" -d '
          f"'{{\"passed\": true}}' {BASE}/requests/REQ-DEMO/verify")
    print(f'  curl -H "Authorization: Bearer tk-analyst" '
          f'{BASE}/requests/REQ-DEMO/audit             # full audit trail')
    print(f'  curl -X POST -H "Authorization: Bearer tk-analyst" '
          f'{BASE}/requests/REQ-DEMO/close')
    print("\nCtrl+C to stop.")
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
