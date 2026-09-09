"""Walk-through demo of aagcp/core/coverage.py on a tiny fake estate."""
from aagcp.core.coverage import (
    Column, Inventory, Inspection, ExclusionRule, Thresholds,
    CoverageRate, CoverageRateError, Partition, assess,
)
from aagcp.core.plan import Plan, Operation, ColumnFinding
from aagcp.core.policy import REGISTRY

T = lambda db, sch, tbl, col, dt="", rows=0: Column(db, sch, tbl, col, dt, rows)

# --- the estate: 6 columns discovered by the catalog -------------------
inventory = Inventory(
    columns=(
        T("hosp", "app", "patients", "email"),                # will be VERIFIED
        T("hosp", "app", "patients", "phone"),                # sample too small
        T("hosp", "app", "patients", "ssn"),                  # name-hint only
        T("hosp", "imaging", "studies", "pixel_data", "BLOB"),# unreadable type
        T("hosp", "app", "orders", "clerk_note"),             # never scanned
        T("hosp", "legacy", "archive", "dead_patient_ssn"),   # legally held
    ),
    source="snowflake information_schema",
    complete=None,        # nobody asserted the catalog is complete!
)

# --- what the scanner actually did --------------------------------------
inspections = (
    Inspection("hosp.app.patients.email",  method="content_sample",
               sampled_rows=5000, identifier_key="email", confidence=0.97),
    Inspection("hosp.app.patients.phone",  method="content_sample",
               sampled_rows=40, identifier_key="phone", confidence=0.91),
    Inspection("hosp.app.patients.ssn",    method="name_hint",
               identifier_key="ssn", confidence=0.60),
    # an orphan: we scanned a table the catalog does not list at all
    Inspection("hosp.shadow.tokens", method="content_sample",
               sampled_rows=500, identifier_key="other_unique", confidence=0.99),
)

# --- one deliberate exclusion, with a named authority -------------------
exclusions = (
    ExclusionRule(rule_id="LH-112", pattern="hosp.legacy.*",
                  cause="LEGAL_HOLD", authority="Office of Counsel, ticket LEGAL-112",
                  detail="patient litigation hold; do not touch until 2027"),
)

# --- the plan the compiler produced --------------------------------------
hipaa = REGISTRY["hipaa_safe_harbor"]
plan = Plan(
    intent_id="int-1", policy_id="hipaa_safe_harbor",
    operations=[
        Operation(op="apply_masking_policy",
                  target="hosp.app.patients.email",
                  treatment="tokenize", identifier_key="email",
                  citation="164.514(b)(2)(i)(F)"),
    ],
    unresolved=[
        {"column": "hosp.app.patients.phone", "cause": "TREATMENT_AMBIGUOUS",
         "identifier_key": "phone"},
    ],
)
findings = (
    ColumnFinding("hosp", "app", "patients", "email", "email", "EMAIL_ADDRESS", 0.97),
    ColumnFinding("hosp", "app", "patients", "phone", "phone", "PHONE_NUMBER", 0.91),
    ColumnFinding("hosp", "app", "patients", "ssn", "ssn", "US_SSN", 0.60),
)

report = assess(inventory, inspections, exclusions,
                policy=hipaa, plan=plan, findings=findings)

print("=== per-column entries ===")
for e in report.entries:
    print(f"{e.target:42s} {e.partition.value:12s} {e.cause:22s} gov={e.governance.value}")

print("\n=== counts / conservation ===")
print(report.counts, "| total:", report.total, "| conserved:", report.conserved())

print("\n=== the three rates ===")
for r in report.rates():
    print(" ", r.render())

print("\n=== explain() ===")
print(report.explain())

print("\n=== guard rails ===")
try:
    ExclusionRule(rule_id="X-1", pattern="hosp.*", cause="EXPLICIT_SCOPE_EXCLUSION",
                  authority="")  # no authority -> must raise
except ValueError as ex:
    print("ExclusionRule with no authority raises:", ex)
try:
    CoverageRate(basis="in_scope", numerator=1, denominator=5, counts={},
                 exclusions=(), excluded_count=2)  # register missing -> must raise
except CoverageRateError as ex:
    print("CoverageRate with hidden exclusions raises:", ex)
