"""Walk-through demo of aagcp/core/executors/base.py — the execution engine."""
from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.executors import SnowflakeExecutor, StagePolicy, FailurePolicy
from aagcp.core.executors.mock import MockEngine, Rule
from aagcp.core.executors.snowflake import _policy_name

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="SALES.PUBLIC", scope_exclude=[],
                         policy_id="hipaa_safe_harbor", audience=["DPO"],
                         confidence=0.95),
                    REGISTRY)
FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email",   "email", "EMAIL", .99, 1000),
    Finding("ACME", "PUBLIC", "customers", "phone",   "phone", "PHONE", .98, 50000),
    Finding("ACME", "PUBLIC", "patients",  "headshot","photo", "PHOTO", .97, 200),
]
PLAN = compile_plan(INTENT, FINDINGS, "snowflake")
NAMES = [_policy_name(o) for o in PLAN.operations]


def eng(rules=()):
    return MockEngine(rules=rules,
                      queries={"aagcp:prestate": [],
                               "POLICY_REFERENCES": [],
                               "INFORMATION_SCHEMA.COLUMNS": []})


print("=== 1. PREVIEW — read-only, issues no DDL ===")
ex = SnowflakeExecutor(eng())
pre = ex.preview(PLAN)
print("operations:", [o.target for o in PLAN.operations])
print("canary targets (smallest row estimate first):", pre.canary_targets)
print("irreversible targets:", pre.irreversible_targets)
print("executable:", pre.executable, "| mutating DDL issued:", len(ex.conn.ddl()))

print("\n=== 2. HAPPY RUN — canary then remainder ===")
ex = SnowflakeExecutor(MockEngine(queries={"aagcp:prestate": [],
                                           "POLICY_REFERENCES": [(n,) for n in NAMES],
                                           "INFORMATION_SCHEMA.COLUMNS": []}))
r = ex.execute_staged(PLAN)
print(r.explain())
print("receipt hash:", r.receipt_hash)

print("\n=== 3. STATEMENT REJECTED MID-PLAN — default policy is HALT ===")
rules = [Rule('MODIFY COLUMN "email"', message="insufficient privilege")]
names = [n for n in NAMES if "EMAIL" not in n]
ex = SnowflakeExecutor(MockEngine(rules=rules,
                                  queries={"aagcp:prestate": [],
                                           "POLICY_REFERENCES": [(n,) for n in names],
                                           "INFORMATION_SCHEMA.COLUMNS": []}))
r = ex.execute_staged(PLAN)
print(r.explain())
for o in r.operations:
    print(f"  {o.target}: {o.status.value} (stage={o.stage}) residual={o.residual_artifacts}")

print("\n=== 4. TRANSPORT LOST — outcome unobserved, UNKNOWN dominates ===")
rules = [Rule("AAGCP_EMAIL_TOKENIZE_DPO", kind="transport",
              message="connection dropped", limit=1)]
names = [n for n in NAMES if "EMAIL" not in n]
ex = SnowflakeExecutor(MockEngine(rules=rules,
                                  queries={"aagcp:prestate": [],
                                           "POLICY_REFERENCES": [(n,) for n in names],
                                           "INFORMATION_SCHEMA.COLUMNS": []}))
r = ex.execute_staged(PLAN)
print(r.explain())
print("verdict:", r.verdict.value, "— never COMPLETE, never FAILED")
rb = ex.rollback(r, PLAN)
print("rollback verdict:", rb.verdict.value, "| refusal:", rb.refusal)

print("\n=== 5. ROLLBACK IS EXPLICIT AND REFUSES IRREVERSIBLE OPS ===")
ex = SnowflakeExecutor(MockEngine(queries={"aagcp:prestate": [],
                                           "POLICY_REFERENCES": [(n,) for n in NAMES],
                                           "INFORMATION_SCHEMA.COLUMNS": []}))
r = ex.execute_staged(PLAN)
rb = ex.rollback(r, PLAN)
print(rb.explain())
print("refusal:", rb.refusal["cause"], "—", rb.refusal["detail"])
for o in rb.operations:
    print(f"  {o.target}: {o.status.value}")

print("\n=== 6. RECONCILE AFTER CRASH — verify, never re-run ===")
ex = SnowflakeExecutor(MockEngine(queries={"aagcp:prestate": [],
                                           "POLICY_REFERENCES": [(n,) for n in NAMES],
                                           "INFORMATION_SCHEMA.COLUMNS": []}))
r = ex.reconcile(PLAN)
print(r.explain(), "| reconciled:", r.reconciled)
print("mutating DDL issued during reconcile:", len(ex.conn.ddl()), "statements")
