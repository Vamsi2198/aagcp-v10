"""Walk-through demo of aagcp/core/plan.py — the deterministic compiler."""
from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan, DIALECTS, coverage_gap

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="SALES.PUBLIC", scope_exclude=[],
                         policy_id="hipaa_safe_harbor", audience=["DPO"],
                         confidence=0.95),
                    REGISTRY)

# Findings spanning several treatments, plus one identifier nobody governs
FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email",     "email", "EMAIL",   .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "phone",     "phone", "PHONE",   .98, 184000),
    Finding("ACME", "PUBLIC", "customers", "ssn",       "ssn",   "SSN",     .97, 184000),
    Finding("ACME", "PUBLIC", "customers", "ip_addr",   "ip",    "IP",      .96, 184000),
    Finding("ACME", "PUBLIC", "patients",  "headshot",  "photo", "PHOTO",   .95, 12000),
    Finding("ACME", "PUBLIC", "customers", "loyalty_id","loyalty","LOYALTY", .94, 184000),
]

print("=== SNOWFLAKE ===")
p1 = compile_plan(INTENT, FINDINGS, "snowflake")
for o in p1.operations:
    print(f"\nop: {o.op} on {o.target} [{o.identifier_key} -> {o.treatment}]")
    print(f"  citation: {o.citation}   reversible: {o.reversible}")
    for s in o.statements:
        print("  " + s.replace("\n", "\n  "))
print("\nunresolved (reported, never silently dropped):")
for u in p1.unresolved:
    print(f"  {u['column']}: {u['cause']} — {u['detail']}")
print(f"\nplan_hash: {p1.plan_hash}")

print("\n=== determinism: compile again, shuffled input order ===")
import random
fs = FINDINGS[:]
random.shuffle(fs)
p2 = compile_plan(INTENT, fs, "snowflake")
print(f"first:  {p1.plan_hash}\nsecond: {p2.plan_hash}\nsame? {p1.plan_hash == p2.plan_hash}")

print("\n=== POSTGRES — same intent, different mechanism ===")
p3 = compile_plan(INTENT, FINDINGS, "postgres")
o = p3.operations[0]
print(f"op on {o.target} [{o.treatment}]:")
for s in o.statements:
    print("  " + s.replace("\n", "\n  "))
print(f"\nplan_hash differs (dialect is part of it): {p3.plan_hash != p1.plan_hash}")

print("\n=== coverage_gap: HIPAA is a closed list of 18 identifiers ===")
gap = coverage_gap(REGISTRY["hipaa_safe_harbor"], FINDINGS)
print(f"{len(gap)} required identifier(s) matched nothing:")
for g in gap[:4]:
    print(f"  {g['identifier_key']:14s} ({g['label']}) — {g['detail'][:60]}...")
