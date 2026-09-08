"""Invariants for Phase 0 coverage. python3 test_coverage.py

The whole module exists to stop one sentence being sayable: "we cover
94%." These tests are mostly attempts to say it.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import (assess, Column, Inventory, Inspection, ExclusionRule,
                           Thresholds, Partition, Governance, CoverageRate,
                           CoverageRateError)

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


def slots(**kw):
    d = dict(action="mask", scope_kind="schema", scope_value="SALES.PUBLIC",
             scope_exclude=[], policy_id="dpdp", audience=["DPO"], confidence=0.95)
    d.update(kw); return d

INTENT = from_slots(slots(), REGISTRY)

COLUMNS = [
    Column("ACME", "PUBLIC", "customers", "email",     "VARCHAR", 184000),
    Column("ACME", "PUBLIC", "customers", "mobile",    "VARCHAR", 184000),
    Column("ACME", "PUBLIC", "customers", "aadhaar_no", "VARCHAR", 184000),
    Column("ACME", "PUBLIC", "customers", "notes",     "VARCHAR", 184000),
    Column("ACME", "PUBLIC", "customers", "avatar",    "BINARY",  184000),
    Column("ACME", "PUBLIC", "orders",    "cvv",       "VARCHAR", 42000),
    Column("ACME", "PUBLIC", "orders",    "total",     "NUMBER",  42000),
    Column("ACME", "PUBLIC", "orders",    "coupon",    "VARCHAR", 42000),
    Column("ACME", "STAGING", "tmp_load", "raw",       "VARCHAR", 9000),
]
COMPLETE_INV = Inventory(tuple(COLUMNS), source="snowflake catalog",
                         complete=True, detail="full crawl 2026-09-07")
UNASSERTED_INV = Inventory(tuple(COLUMNS), source="snowflake catalog",
                           complete=None)

INSPECTIONS = [
    Inspection("ACME.PUBLIC.customers.email", "content_sample", 5000, "email", 0.99),
    Inspection("ACME.PUBLIC.customers.mobile", "content_sample", 5000, "phone", 0.97),
    Inspection("ACME.PUBLIC.customers.aadhaar_no", "name_hint", 0, "aadhaar", 0.0),
    Inspection("ACME.PUBLIC.customers.notes", "content_sample", 40, "", 0.9),
    Inspection("ACME.PUBLIC.customers.avatar", "content_sample", 5000, "", 0.95),
    Inspection("ACME.PUBLIC.orders.cvv", "content_sample", 5000, "cav2", 0.55),
    Inspection("ACME.PUBLIC.orders.total", "content_sample", 5000, "", 0.99),
    # tmp_load.raw has no inspection at all
]

FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email", "email", "EMAIL", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "mobile", "phone", "PHONE", .97, 184000),
    Finding("ACME", "PUBLIC", "orders", "cvv", "cav2", "", .55, 42000),
]
PLAN = compile_plan(INTENT, FINDINGS, "snowflake")

EXCLUSIONS = [
    ExclusionRule("EX-01", "ACME.STAGING.*", "SYSTEM_OBJECT",
                  authority="platform-team/RUNBOOK-4412",
                  detail="staging schema truncated nightly"),
]


print("\n=== PARTITIONS: everything lands in exactly one ===")
r = assess(COMPLETE_INV, INSPECTIONS, EXCLUSIONS,
           policy=REGISTRY["dpdp"], plan=PLAN, findings=FINDINGS)
check("nothing disappears", r.conserved(), str(r.counts))
check("partitions sum to the inventory", r.total == len(COLUMNS), str(r.total))
check("content sample at confidence -> VERIFIED",
      r.counts["verified"] == 3, str(r.counts))
check("name hint only -> OBSERVED, not verified",
      [e.target for e in r.partition(Partition.OBSERVED)]
      == ["ACME.PUBLIC.customers.aadhaar_no"],
      str([e.target for e in r.partition(Partition.OBSERVED)]))

causes = sorted(e.cause for e in r.partition(Partition.INCONCLUSIVE))
check("small sample is inconclusive, not clean", "SAMPLE_TOO_SMALL" in causes)
check("low confidence is inconclusive", "DETECTOR_CONFIDENCE_BELOW_THRESHOLD" in causes)
check("an unreadable type is inconclusive, not excluded",
      "TYPE_NOT_INSPECTABLE" in causes, str(causes))
check("never scanned is inconclusive, not clean", "NOT_SCANNED" in causes)

print("\n=== EXCLUDED IS A DECISION, INCONCLUSIVE IS A GAP ===")
ex = r.partition(Partition.EXCLUDED)
check("the staging column is excluded", len(ex) == 1, str([e.target for e in ex]))
check("the exclusion names its authority",
      ex[0].authority == "platform-team/RUNBOOK-4412", ex[0].authority)
check("the register itemises it",
      r.exclusion_register[0]["target"] == "ACME.STAGING.tmp_load.raw",
      str(r.exclusion_register))
try:
    ExclusionRule("EX-02", "X.*", "SYSTEM_OBJECT", authority="")
    check("an exclusion without an authority is rejected", False, "accepted")
except ValueError as e:
    check("an exclusion without an authority is rejected", True, str(e)[:44])

print("\n=== THE RATE CANNOT BE SEPARATED FROM THE REGISTER ===")
rate = r.rate("in_scope")
check("in_scope removes only the excluded",
      rate.denominator == len(COLUMNS) - 1, str(rate.denominator))
check("the rate carries its exclusions", len(rate.exclusions) == 1,
      str(len(rate.exclusions)))
check("serialising a rate emits the register",
      rate.to_dict()["exclusions"] and "value" in rate.to_dict())
try:
    CoverageRate(basis="fake", numerator=7, denominator=7,
                 counts={}, exclusions=(), excluded_count=3)
    check("a rate with hidden exclusions is rejected", False, "accepted")
except CoverageRateError as e:
    check("a rate with hidden exclusions is rejected", True, str(e)[:52])
try:
    CoverageRate(basis="fake", numerator=9, denominator=7, counts={})
    check("a numerator above its denominator is rejected", False, "accepted")
except CoverageRateError:
    check("a numerator above its denominator is rejected", True)

check("estate basis leaves exclusions in the denominator",
      r.rate("estate").denominator == len(COLUMNS)
      and r.rate("estate").excluded_count == 0,
      str(r.rate("estate").denominator))
check("the two bases give different numbers",
      r.rate("estate").value != r.rate("in_scope").value,
      f"{r.rate('estate').value:.3f} vs {r.rate('in_scope').value:.3f}")

print("\n=== THE DENOMINATOR PROBLEM ===")
u = assess(UNASSERTED_INV, INSPECTIONS, EXCLUSIONS,
           policy=REGISTRY["dpdp"], plan=PLAN, findings=FINDINGS)
check("an unasserted inventory is not a verified denominator",
      not u.denominator_verified)
check("its rates render as a ceiling",
      "at least" in u.rate("in_scope").render(), u.rate("in_scope").render())
check("an asserted inventory does not",
      "at least" not in r.rate("in_scope").render(), r.rate("in_scope").render())
check("same partitions, different honesty",
      u.counts == r.counts and u.report_hash != r.report_hash)

empty = assess(Inventory((), source="empty", complete=True))
check("zero columns is no answer, not 100%",
      empty.rate("in_scope").value is None, str(empty.rate("in_scope").render()))

print("\n=== ANOMALIES: the inventory can be wrong ===")
orphan = assess(COMPLETE_INV,
                list(INSPECTIONS) + [Inspection("ACME.PUBLIC.ghost.col",
                                                "content_sample", 5000, "email", .99)],
                EXCLUSIONS, policy=REGISTRY["dpdp"], plan=PLAN, findings=FINDINGS)
check("an inspection with no inventory entry is an anomaly",
      any(a["cause"] == "INSPECTION_WITHOUT_INVENTORY_ENTRY"
          for a in orphan.anomalies), str(orphan.anomalies[:1]))
dupes = assess(Inventory(tuple(COLUMNS) + (COLUMNS[0],), source="x", complete=True))
check("a duplicated column is an anomaly, not a silent inflation",
      any(a["cause"] == "DUPLICATE_INVENTORY_ENTRY" for a in dupes.anomalies))

print("\n=== MEASUREMENT AND GOVERNANCE ARE DIFFERENT QUESTIONS ===")
check("cvv is measured-inconclusive and ungoverned by dpdp",
      any(e.target.endswith("orders.cvv")
          and e.partition is Partition.INCONCLUSIVE
          and e.governance is Governance.UNGOVERNED for e in r.entries),
      str([(e.partition.value, e.governance.value) for e in r.entries
           if e.target.endswith("orders.cvv")]))
check("the ungoverned cause comes from the compiler, not a new vocabulary",
      any(e.governance_cause == "IDENTIFIER_NOT_IN_POLICY"
          for e in r.ungoverned()),
      str([e.governance_cause for e in r.ungoverned()]))
check("a column with nothing identifying is NOT_APPLICABLE, not ungoverned",
      any(e.target.endswith("orders.total")
          and e.governance is Governance.NOT_APPLICABLE for e in r.entries))
check("the governed rate has its own denominator",
      r.rate("governed").denominator == len(r.ungoverned())
      + len([e for e in r.entries if e.governance is Governance.GOVERNED]),
      r.rate("governed").render())

print("\n=== IT REUSES coverage_gap RATHER THAN RESTATING IT ===")
hip = assess(COMPLETE_INV, INSPECTIONS, EXCLUSIONS,
             policy=REGISTRY["hipaa_safe_harbor"], plan=PLAN, findings=FINDINGS)
check("closed-list identifier gap is carried in the report",
      len(hip.identifier_gap) == 16, str(len(hip.identifier_gap)))
check("the gap keeps its citations", all(g["citation"] for g in hip.identifier_gap))

print("\n=== THRESHOLDS ARE AN INPUT, NOT A FACT ===")
strict = Thresholds(version="strict", min_sample_rows=100,
                    min_confidence=0.80, min_sample_fraction=0.10)
s = assess(COMPLETE_INV, INSPECTIONS, EXCLUSIONS,
           policy=REGISTRY["dpdp"], plan=PLAN, findings=FINDINGS,
           thresholds=strict)
check("a proportional sample rule moves columns out of VERIFIED",
      s.counts["verified"] < r.counts["verified"],
      f"{r.counts['verified']} -> {s.counts['verified']}")
check("the thresholds that produced it are in the report",
      s.thresholds["version"] == "strict", s.thresholds["version"])
check("different thresholds, different hash", s.report_hash != r.report_hash)

print("\n=== DETERMINISM ===")
a = assess(COMPLETE_INV, INSPECTIONS, EXCLUSIONS, policy=REGISTRY["dpdp"],
           plan=PLAN, findings=FINDINGS)
b = assess(COMPLETE_INV, list(reversed(INSPECTIONS)), EXCLUSIONS,
           policy=REGISTRY["dpdp"], plan=PLAN, findings=FINDINGS)
check("input order does not change the report", a.report_hash == b.report_hash,
      a.report_hash)

print("\n=== SAMPLE REPORT ===")
print("  " + r.explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
