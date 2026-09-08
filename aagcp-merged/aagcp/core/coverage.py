"""
aagcp/core/coverage.py — Phase 0. What did we actually look at.

Every governance claim rests on a denominator, and the denominator is
where the lying happens. "We govern 94% of sensitive columns" is not a
finding until three things are stated: what the 100% was, how it was
counted, and what was taken out of it before the division. A percentage
without its exclusion register is a number that has been smoothed.

So this module refuses to hand back a bare float. A rate is an object
carrying its numerator, its denominator, the partition counts that make
up that denominator, the itemised exclusions removed from it, and a flag
saying whether the denominator itself was ever verified. CoverageRate
raises at construction if you try to build one with excluded items and no
register. That is not a stylistic preference — it is the only way the
guarantee survives contact with a dashboard six months from now.

FOUR PARTITIONS, and every column in the inventory lands in exactly one:

  VERIFIED      content was sampled, a determination was reached, and the
                sample was large enough and the detector confident enough
                to stand behind it
  OBSERVED      we know the column exists and something about it, but
                nothing in it was read — a name-hint match is metadata
                evidence, not measurement
  INCONCLUSIVE  we tried and could not determine: scan failed, sample too
                small, confidence too low, type not inspectable
  EXCLUDED      deliberately out of scope, by a named authority

The distinction between EXCLUDED and INCONCLUSIVE carries the weight. A
column somebody decided not to scan is a policy decision with an owner.
A column that could not be scanned is an unmeasured channel. Collapsing
them lets an estate reach 100% coverage by failing to look, which is the
same failure the erasure verifier prevents by capping Pinecone at
INCONCLUSIVE_UNMEASURED: unmeasured is never clean.

THE DEEPEST VERSION of the denominator problem is not solved here and is
not solvable by inspection: you cannot count what discovery never found.
An inventory whose source does not assert completeness produces rates
flagged denominator_verified=False, and they render as "of at least N"
rather than "of N". A shadow database nobody catalogued is invisible to
every number in this file, and the flag is how that stays visible.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from .plan import Finding, Plan, coverage_gap
from .policy import Policy

COVERAGE_VERSION = "coverage-1.0.0"


class Partition(str, Enum):
    VERIFIED = "verified"
    OBSERVED = "observed"
    INCONCLUSIVE = "inconclusive"
    EXCLUDED = "excluded"


class Governance(str, Enum):
    GOVERNED = "governed"
    UNGOVERNED = "ungoverned"
    NOT_APPLICABLE = "not_applicable"     # nothing identifying was found
    NOT_ASSESSED = "not_assessed"         # no plan supplied to compare against


# ---- cause codes -----------------------------------------------------
# Measurement causes
CAUSE_CONTENT_SAMPLED = "CONTENT_SAMPLED"
CAUSE_NAME_HINT_ONLY = "NAME_HINT_ONLY"
CAUSE_NOT_SCANNED = "NOT_SCANNED"
CAUSE_SCAN_FAILED = "SCAN_FAILED"
CAUSE_SAMPLE_TOO_SMALL = "SAMPLE_TOO_SMALL"
CAUSE_LOW_CONFIDENCE = "DETECTOR_CONFIDENCE_BELOW_THRESHOLD"
CAUSE_TYPE_NOT_INSPECTABLE = "TYPE_NOT_INSPECTABLE"
CAUSE_NO_METHOD = "NO_INSPECTION_METHOD"
# Structural causes
CAUSE_ORPHAN_INSPECTION = "INSPECTION_WITHOUT_INVENTORY_ENTRY"
CAUSE_ORPHAN_FINDING = "FINDING_WITHOUT_INVENTORY_ENTRY"
CAUSE_DUPLICATE_INVENTORY = "DUPLICATE_INVENTORY_ENTRY"
CAUSE_DENOMINATOR_UNVERIFIED = "DISCOVERY_COMPLETENESS_NOT_ASSERTED"
# Exclusion causes
CAUSE_SCOPE_EXCLUSION = "EXPLICIT_SCOPE_EXCLUSION"
CAUSE_LEGAL_HOLD = "LEGAL_HOLD"
CAUSE_SYSTEM_OBJECT = "SYSTEM_OBJECT"
CAUSE_CUSTOMER_DECLARED = "CUSTOMER_DECLARED_OUT_OF_SCOPE"

# Types whose contents a column-level detector cannot honestly read. These
# are INCONCLUSIVE, never EXCLUDED — they are in scope and unmeasurable,
# which is a gap to close, not a decision somebody made.
UNINSPECTABLE_TYPES = frozenset({
    "BINARY", "VARBINARY", "BLOB", "GEOGRAPHY", "GEOMETRY", "VECTOR",
})


# ---------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Column:
    """One column in the estate, as discovered. This is the unit the
    denominator counts."""
    database: str
    schema: str
    table: str
    column: str
    data_type: str = ""
    row_estimate: int = 0

    @property
    def fqn(self) -> str:
        return f"{self.database}.{self.schema}.{self.table}"

    @property
    def target(self) -> str:
        return f"{self.fqn}.{self.column}"


@dataclass(frozen=True)
class Inventory:
    """The denominator, and where it came from.

    `complete` is deliberately three-valued. True means the source asserts
    it enumerated everything reachable. False means it knows it did not.
    None means nobody said — which is the common case and is treated as
    False for the purpose of every rate, because an unasserted claim is
    not a claim.
    """
    columns: Tuple[Column, ...]
    source: str = "unknown"
    complete: Optional[bool] = None
    detail: str = ""

    @property
    def denominator_verified(self) -> bool:
        return self.complete is True

    def by_target(self) -> Dict[str, Column]:
        return {c.target: c for c in self.columns}


@dataclass(frozen=True)
class Inspection:
    """What the scanner did to one column. Absence of an Inspection is not
    a clean column; it is an unscanned one."""
    target: str
    method: str = "none"          # content_sample | name_hint | none
    sampled_rows: int = 0
    identifier_key: str = ""
    confidence: float = 0.0
    error: str = ""


@dataclass(frozen=True)
class ExclusionRule:
    """An exclusion with no named authority is how a coverage number gets
    gamed, so the constructor refuses one."""
    rule_id: str
    pattern: str                  # exact target/fqn, or a prefix ending in '*'
    cause: str
    authority: str                # person, ticket, or clause that decided it
    detail: str = ""

    def __post_init__(self):
        if not self.authority:
            raise ValueError(
                f"exclusion '{self.rule_id}' has no authority; every "
                f"exclusion must name who decided it")
        if not self.cause:
            raise ValueError(f"exclusion '{self.rule_id}' has no cause code")

    def matches(self, target: str) -> bool:
        if self.pattern.endswith("*"):
            return target.startswith(self.pattern[:-1])
        return target == self.pattern


@dataclass(frozen=True)
class Thresholds:
    """Where 'we looked' becomes 'we know'. Confidence: these are chosen
    defaults, not derived from data. Versioned and folded into the report
    hash so a receipt says which thresholds produced it."""
    version: str = "thresholds-1.0.0"
    min_sample_rows: int = 100
    min_confidence: float = 0.80
    # A sample is also judged against the table: 100 rows out of 50 million
    # is a sample of nothing. 0 disables the proportional check.
    min_sample_fraction: float = 0.0

    def to_dict(self):
        return {"version": self.version, "min_sample_rows": self.min_sample_rows,
                "min_confidence": self.min_confidence,
                "min_sample_fraction": self.min_sample_fraction}


DEFAULT_THRESHOLDS = Thresholds()


# ---------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    target: str
    partition: Partition
    cause: str
    detail: str = ""
    method: str = ""
    confidence: float = 0.0
    identifier_key: str = ""
    governance: Governance = Governance.NOT_ASSESSED
    governance_cause: str = ""
    rule_id: str = ""
    authority: str = ""

    def to_dict(self):
        return {"target": self.target, "partition": self.partition.value,
                "cause": self.cause, "detail": self.detail,
                "method": self.method, "confidence": self.confidence,
                "identifier_key": self.identifier_key,
                "governance": self.governance.value,
                "governance_cause": self.governance_cause,
                "rule_id": self.rule_id, "authority": self.authority}


class CoverageRateError(ValueError):
    """Raised when a rate is constructed without the register that makes
    it readable."""


@dataclass(frozen=True)
class CoverageRate:
    """A percentage that cannot be separated from what was removed to get
    it. There is no __float__ and no bare `.percent` — every path to the
    number goes through an object carrying the register."""
    basis: str
    numerator: int
    denominator: int
    counts: Dict[str, int]
    exclusions: Tuple[dict, ...] = ()
    excluded_count: int = 0
    denominator_verified: bool = False
    note: str = ""

    def __post_init__(self):
        if self.excluded_count and not self.exclusions:
            raise CoverageRateError(
                f"basis '{self.basis}' removed {self.excluded_count} item(s) "
                f"from the denominator without an itemised register; a rate "
                f"cannot be returned apart from its exclusions")
        if len(self.exclusions) != self.excluded_count:
            raise CoverageRateError(
                f"basis '{self.basis}': register holds {len(self.exclusions)} "
                f"item(s) but {self.excluded_count} were removed")
        if self.numerator > self.denominator:
            raise CoverageRateError(
                f"basis '{self.basis}': numerator {self.numerator} exceeds "
                f"denominator {self.denominator}")

    @property
    def value(self) -> Optional[float]:
        """None on an empty denominator. Zero columns is not 100% coverage,
        and it is not 0% either — it is no answer."""
        if self.denominator == 0:
            return None
        return self.numerator / self.denominator

    def render(self) -> str:
        if self.value is None:
            return (f"{self.basis}: no denominator — nothing was in scope "
                    f"to measure")
        of = "at least " if not self.denominator_verified else ""
        s = (f"{self.basis}: {self.value:.1%} — {self.numerator} of {of}"
             f"{self.denominator}")
        if self.excluded_count:
            s += f", after removing {self.excluded_count} excluded (itemised)"
        if not self.denominator_verified:
            s += "; discovery completeness not asserted"
        return s

    def to_dict(self):
        return {"basis": self.basis, "numerator": self.numerator,
                "denominator": self.denominator, "value": self.value,
                "counts": dict(self.counts),
                "excluded_count": self.excluded_count,
                "exclusions": [dict(e) for e in self.exclusions],
                "denominator_verified": self.denominator_verified,
                "note": self.note, "rendered": self.render()}


@dataclass
class CoverageReport:
    entries: List[Entry]
    exclusion_register: List[dict]
    anomalies: List[dict]
    identifier_gap: List[dict]
    inventory_source: str
    denominator_verified: bool
    thresholds: dict
    policy_id: str = ""
    plan_hash: str = ""
    version: str = COVERAGE_VERSION

    # ---- partition access ------------------------------------------
    def partition(self, p: Partition) -> List[Entry]:
        return [e for e in self.entries if e.partition is p]

    @property
    def counts(self) -> Dict[str, int]:
        return {p.value: len(self.partition(p)) for p in Partition}

    @property
    def total(self) -> int:
        return len(self.entries)

    def ungoverned(self) -> List[Entry]:
        return [e for e in self.entries
                if e.governance is Governance.UNGOVERNED]

    def conserved(self) -> bool:
        """Every column lands in exactly one partition, and the partitions
        sum to the inventory. If this is ever False something vanished."""
        return sum(self.counts.values()) == self.total

    # ---- rates ------------------------------------------------------
    def rate(self, basis: str = "in_scope") -> CoverageRate:
        c = self.counts
        excluded = c[Partition.EXCLUDED.value]
        register = tuple(self.exclusion_register)

        if basis == "estate":
            # Nothing removed. The strictest number, and the only one that
            # is comparable across two estates with different exclusions.
            return CoverageRate(
                basis="estate", numerator=c[Partition.VERIFIED.value],
                denominator=self.total, counts=c,
                exclusions=(), excluded_count=0,
                denominator_verified=self.denominator_verified,
                note="verified columns over every column discovered, "
                     "exclusions left in the denominator")

        if basis == "in_scope":
            return CoverageRate(
                basis="in_scope", numerator=c[Partition.VERIFIED.value],
                denominator=self.total - excluded, counts=c,
                exclusions=register, excluded_count=excluded,
                denominator_verified=self.denominator_verified,
                note="verified columns over columns not deliberately excluded")

        if basis == "governed":
            # Of the columns where something identifying was actually found,
            # how many carry a treatment. Measurement and governance are
            # different questions and this is the second one.
            eligible = [e for e in self.entries
                        if e.governance in (Governance.GOVERNED,
                                            Governance.UNGOVERNED)]
            governed = [e for e in eligible
                        if e.governance is Governance.GOVERNED]
            return CoverageRate(
                basis="governed", numerator=len(governed),
                denominator=len(eligible), counts=c,
                exclusions=register, excluded_count=excluded,
                denominator_verified=self.denominator_verified,
                note="governed over columns with a detected identifier")

        raise ValueError(f"unknown basis '{basis}'")

    def rates(self) -> List[CoverageRate]:
        return [self.rate(b) for b in ("estate", "in_scope", "governed")]

    # ---- serialisation ---------------------------------------------
    def to_dict(self) -> dict:
        # The register is emitted alongside the rates, always, in the same
        # object. There is no serialisation path that produces one without
        # the other.
        return {
            "version": self.version, "policy_id": self.policy_id,
            "plan_hash": self.plan_hash,
            "inventory_source": self.inventory_source,
            "denominator_verified": self.denominator_verified,
            "thresholds": self.thresholds,
            "counts": self.counts, "total": self.total,
            "conserved": self.conserved(),
            "rates": [r.to_dict() for r in self.rates()],
            "exclusion_register": [dict(e) for e in self.exclusion_register],
            "anomalies": [dict(a) for a in self.anomalies],
            "identifier_gap": [dict(g) for g in self.identifier_gap],
            "entries": [e.to_dict() for e in self.entries],
        }

    @property
    def report_hash(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "C-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    def summary(self) -> dict:
        return {"report_hash": self.report_hash, "total": self.total,
                **self.counts,
                "ungoverned": len(self.ungoverned()),
                "anomalies": len(self.anomalies),
                "identifier_gap": len(self.identifier_gap),
                "denominator_verified": self.denominator_verified}

    def explain(self) -> str:
        lines = [f"{self.total} column(s) from {self.inventory_source}"]
        for r in self.rates():
            lines.append("  " + r.render())
        c = self.counts
        lines.append(f"  partitions — verified {c['verified']}, "
                     f"observed {c['observed']}, "
                     f"inconclusive {c['inconclusive']}, "
                     f"excluded {c['excluded']}")
        by_cause: Dict[str, int] = {}
        for e in self.partition(Partition.INCONCLUSIVE):
            by_cause[e.cause] = by_cause.get(e.cause, 0) + 1
        for cause, n in sorted(by_cause.items()):
            lines.append(f"    inconclusive: {n} × {cause}")
        for x in self.exclusion_register:
            lines.append(f"    excluded: {x['target']} — {x['cause']} "
                         f"[{x['rule_id']}, authority {x['authority']}]")
        if self.ungoverned():
            lines.append(f"  {len(self.ungoverned())} column(s) measured but "
                         f"not governed by {self.policy_id}")
        if self.identifier_gap:
            lines.append(f"  {len(self.identifier_gap)} policy identifier(s) "
                         f"matched nothing in the estate")
        for a in self.anomalies:
            lines.append(f"  anomaly: {a['cause']} — {a['detail']}")
        if not self.denominator_verified:
            lines.append("  denominator is unverified: discovery did not "
                         "assert completeness, so every rate above is a "
                         "ceiling, not a measurement")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# The assessment
# ---------------------------------------------------------------------

def _classify(col: Column, insp: Optional[Inspection],
              th: Thresholds) -> Tuple[Partition, str, str]:
    """One column, one partition, one cause. Order matters: the cheapest
    disqualifiers are checked before the expensive claims."""
    if insp is None:
        return (Partition.INCONCLUSIVE, CAUSE_NOT_SCANNED,
                "no inspection record exists for this column")

    if insp.error:
        return (Partition.INCONCLUSIVE, CAUSE_SCAN_FAILED, insp.error)

    if col.data_type.upper() in UNINSPECTABLE_TYPES:
        return (Partition.INCONCLUSIVE, CAUSE_TYPE_NOT_INSPECTABLE,
                f"a column-level detector cannot read {col.data_type}; "
                f"in scope and unmeasured")

    if insp.method == "content_sample":
        if insp.sampled_rows < th.min_sample_rows:
            return (Partition.INCONCLUSIVE, CAUSE_SAMPLE_TOO_SMALL,
                    f"{insp.sampled_rows} row(s) sampled, "
                    f"{th.min_sample_rows} required")
        if th.min_sample_fraction and col.row_estimate:
            frac = insp.sampled_rows / col.row_estimate
            if frac < th.min_sample_fraction:
                return (Partition.INCONCLUSIVE, CAUSE_SAMPLE_TOO_SMALL,
                        f"{insp.sampled_rows} of {col.row_estimate:,} rows "
                        f"({frac:.2%}) is below {th.min_sample_fraction:.2%}")
        if insp.confidence < th.min_confidence:
            return (Partition.INCONCLUSIVE, CAUSE_LOW_CONFIDENCE,
                    f"detector confidence {insp.confidence:.2f} below "
                    f"{th.min_confidence:.2f}")
        return (Partition.VERIFIED, CAUSE_CONTENT_SAMPLED,
                f"{insp.sampled_rows} row(s) sampled at "
                f"confidence {insp.confidence:.2f}")

    if insp.method == "name_hint":
        # Metadata evidence. The column name looked right and nothing in it
        # was read, so this is known-about, not measured.
        return (Partition.OBSERVED, CAUSE_NAME_HINT_ONLY,
                "matched on column name; no content was read")

    return (Partition.INCONCLUSIVE, CAUSE_NO_METHOD,
            f"inspection method '{insp.method}' does not determine anything")


def assess(inventory: Inventory,
           inspections: Sequence[Inspection] = (),
           exclusions: Sequence[ExclusionRule] = (),
           policy: Policy = None,
           plan: Plan = None,
           findings: Sequence[Finding] = (),
           thresholds: Thresholds = DEFAULT_THRESHOLDS) -> CoverageReport:
    """Deterministic given the same inventory, inspections and rules."""
    by_target = inventory.by_target()
    insp_by_target = {i.target: i for i in inspections}
    anomalies: List[dict] = []

    # Duplicates in the inventory would silently inflate a denominator.
    seen = set()
    for c in inventory.columns:
        if c.target in seen:
            anomalies.append({"cause": CAUSE_DUPLICATE_INVENTORY,
                              "target": c.target,
                              "detail": "appears more than once in the inventory"})
        seen.add(c.target)

    # A scanner that inspected something the catalog never listed means the
    # inventory is wrong, which means the denominator is wrong.
    for t in sorted(insp_by_target):
        if t not in by_target:
            anomalies.append({"cause": CAUSE_ORPHAN_INSPECTION, "target": t,
                              "detail": "inspected but absent from the "
                                        "inventory; the denominator is short"})

    # Governance map, built from the plan the compiler produced.
    governed_targets = set()
    ungoverned_causes: Dict[str, dict] = {}
    if plan is not None:
        governed_targets = {o.target for o in plan.operations}
        # Reuses the compiler's own cause codes rather than inventing a
        # parallel vocabulary for the same facts.
        for u in plan.unresolved:
            ungoverned_causes[u["column"]] = u
    finding_targets = {f"{f.fqn}.{f.column}" for f in findings}
    for t in sorted(finding_targets):
        if t not in by_target:
            anomalies.append({"cause": CAUSE_ORPHAN_FINDING, "target": t,
                              "detail": "a finding exists for a column the "
                                        "inventory does not contain"})

    entries: List[Entry] = []
    register: List[dict] = []

    for col in sorted(inventory.columns, key=lambda c: c.target):
        rule = next((r for r in exclusions if r.matches(col.target)), None)
        if rule is not None:
            # Excluded first, and on its own evidence. A column somebody
            # decided not to scan must not be reported as one that failed
            # to scan.
            entries.append(Entry(
                target=col.target, partition=Partition.EXCLUDED,
                cause=rule.cause, detail=rule.detail or rule.pattern,
                rule_id=rule.rule_id, authority=rule.authority,
                governance=Governance.NOT_APPLICABLE,
                governance_cause=CAUSE_SCOPE_EXCLUSION))
            register.append({"target": col.target, "rule_id": rule.rule_id,
                             "cause": rule.cause, "authority": rule.authority,
                             "detail": rule.detail or rule.pattern})
            continue

        insp = insp_by_target.get(col.target)
        partition, cause, detail = _classify(col, insp, thresholds)

        if plan is None:
            gov, gcause = Governance.NOT_ASSESSED, ""
        elif col.target in governed_targets:
            gov, gcause = Governance.GOVERNED, ""
        elif col.target in ungoverned_causes:
            u = ungoverned_causes[col.target]
            gov, gcause = Governance.UNGOVERNED, u["cause"]
        elif col.target in finding_targets:
            gov, gcause = Governance.UNGOVERNED, "IDENTIFIER_NOT_IN_POLICY"
        else:
            gov, gcause = Governance.NOT_APPLICABLE, ""

        entries.append(Entry(
            target=col.target, partition=partition, cause=cause, detail=detail,
            method=(insp.method if insp else ""),
            confidence=(insp.confidence if insp else 0.0),
            identifier_key=(insp.identifier_key if insp else ""),
            governance=gov, governance_cause=gcause))

    gap = coverage_gap(policy, list(findings)) if policy is not None else []

    return CoverageReport(
        entries=entries, exclusion_register=register, anomalies=anomalies,
        identifier_gap=gap,
        inventory_source=f"{inventory.source}"
                         + (f" ({inventory.detail})" if inventory.detail else ""),
        denominator_verified=inventory.denominator_verified,
        thresholds=thresholds.to_dict(),
        policy_id=(policy.policy_id if policy else
                   (plan.policy_id if plan else "")),
        plan_hash=(plan.plan_hash if plan else ""))
