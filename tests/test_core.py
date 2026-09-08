"""Invariants for the intent/policy/plan spine. python3 test_core.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys
from aagcp.core.intent import (Intent, Scope, Action, ScopeKind, IntentError,
                         from_slots, validate)
from aagcp.core.policy import REGISTRY, describe_registry, Treatment
from aagcp.core.plan import Finding, compile_plan, coverage_gap, DIALECTS

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

print("\n=== POLICY REGISTRY ===")
print("  " + describe_registry().replace("\n", "\n  "))
check("HIPAA has all 18 Safe Harbor identifiers",
      len(REGISTRY["hipaa_safe_harbor"].identifiers) == 18,
      str(len(REGISTRY["hipaa_safe_harbor"].identifiers)))
check("every identifier carries a citation",
      all(i.citation for p in REGISTRY.values() for i in p.identifiers))
check("same column, different regimes, different treatment",
      REGISTRY["hipaa_safe_harbor"].by_key()["dates"].treatment is Treatment.GENERALIZE
      and REGISTRY["pci_dss"].by_key()["expiry"].treatment is Treatment.RETAIN)

print("\n=== INTENT: the model never gets past a bad slot ===")
def slots(**kw):
    d = dict(action="mask", scope_kind="schema", scope_value="SALES.PUBLIC",
             scope_exclude=[], policy_id="dpdp", audience=["DPO"], confidence=0.95)
    d.update(kw); return d

i = from_slots(slots(), REGISTRY, utterance="mask pii in sales")
check("valid slots produce an Intent", i.intent_id.startswith("I-"), i.describe())
check("intent id is stable", i.intent_id == from_slots(slots(), REGISTRY).intent_id)

for name, kw, code in (
    ("unknown policy",       dict(policy_id="ccpa"),                 "UNKNOWN_POLICY"),
    ("low confidence",       dict(confidence=0.4),                   "LOW_CONFIDENCE"),
    ("scope missing value",  dict(scope_kind="table", scope_value=""),"SCOPE_INCOMPLETE"),
    ("sql injection in scope",dict(scope_value="X; DROP TABLE Y"),   "SCOPE_NOT_AN_IDENTIFIER"),
    ("erase on a schema",    dict(action="erase"),                   "ERASE_SCOPE_MUST_BE_SUBJECT"),
):
    try:
        from_slots(slots(**kw), REGISTRY); check(name + " rejected", False, "accepted!")
    except IntentError as e:
        check(name + " rejected", e.code == code, e.code)

print("\n=== PLAN: deterministic, no model in the path ===")
fs = [
    Finding("ACME","PUBLIC","customers","aadhaar_no","aadhaar","IN_AADHAAR",0.99,184000),
    Finding("ACME","PUBLIC","customers","email","email","EMAIL_ADDRESS",0.99,184000),
    Finding("ACME","PUBLIC","customers","mobile","phone","PHONE_NUMBER",0.98,184000),
    Finding("ACME","PUBLIC","orders","cvv","cav2","",0.9,42000),
    Finding("ACME","PUBLIC","orders","loyalty_tier","loyalty","",0.8,42000),
]
p1 = compile_plan(i, fs, "snowflake")
p2 = compile_plan(i, list(reversed(fs)), "snowflake")
check("plan hash stable across input order", p1.plan_hash == p2.plan_hash, p1.plan_hash)
check("summary", p1.summary()["operations"] == 3, str(p1.summary()))
check("ungoverned identifier reported, not silently dropped",
      any(u["cause"] == "IDENTIFIER_NOT_IN_POLICY" for u in p1.unresolved),
      str([u["identifier_key"] for u in p1.unresolved]))
check("cvv not governed by dpdp -> unresolved",
      "cav2" in [u["identifier_key"] for u in p1.unresolved])

pci = from_slots(slots(policy_id="pci_dss"), REGISTRY)
ppci = compile_plan(pci, fs, "snowflake")
drops = [o for o in ppci.operations if o.op == "drop_column"]
check("PCI SAD compiles to DROP, not mask", len(drops) == 1 and not drops[0].reversible,
      drops[0].target if drops else "none")
check("irreversible ops surfaced", len(ppci.irreversible_ops) == 1)

print("\n=== PORTABILITY: one Intent, two warehouses ===")
pg = compile_plan(i, fs, "postgres")
check("postgres compiles the same intent", len(pg.operations) == len(p1.operations))
check("different SQL, different hash", pg.plan_hash != p1.plan_hash)
check("no masking-policy DDL in postgres",
      not any("MASKING POLICY" in s for o in pg.operations for s in o.statements))

print("\n=== COVERAGE GAP (Phase 0 in miniature) ===")
hip = from_slots(slots(policy_id="hipaa_safe_harbor"), REGISTRY)
gap = coverage_gap(REGISTRY["hipaa_safe_harbor"], fs)
check("closed-list regime reports unmatched identifiers", len(gap) == 16, str(len(gap)))
check("gap carries the citation", all(g["citation"] for g in gap))

print("\n=== SAMPLE OUTPUT ===")
for o in p1.operations[:2]:
    print(f"\n  {o.target}  [{o.treatment}]  {o.citation}")
    for s in o.statements:
        print("    " + s.replace("\n", "\n    "))

print("\n" + "="*62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
