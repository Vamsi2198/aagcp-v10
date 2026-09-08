"""
aagcp/core/plan.py — Intent + findings -> a typed plan -> dialect SQL.

No language model appears anywhere below this line. Given the same Intent
and the same findings, this produces byte-identical statements forever,
which is the property an attestation depends on: a receipt issued today
must be re-derivable in three years by someone who does not have your
model, your prompt, or your API key.

Portability falls out of the same design. A new warehouse is a Dialect
subclass with template strings — not another round of prompt engineering.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .intent import Intent, Action
from .policy import REGISTRY, Policy, Treatment, Identifier

RULESET_VERSION = "plan-1.0.0"


@dataclass(frozen=True)
class ColumnFinding:
    """One detected identifier in one column. Produced by ANALYZE
    (Presidio + column hints), consumed here. Never inferred by the LLM."""
    database: str
    schema: str
    table: str
    column: str
    identifier_key: str
    detector: str = ""
    confidence: float = 1.0
    row_estimate: int = 0

    @property
    def fqn(self) -> str:
        return f"{self.database}.{self.schema}.{self.table}"


@dataclass
class Operation:
    op: str                       # apply_masking_policy | drop_column | tokenize | ...
    target: str                   # fully qualified column
    treatment: str
    identifier_key: str
    citation: str
    audience: tuple = ()
    statements: List[str] = field(default_factory=list)
    reversible: bool = True
    row_estimate: int = 0

    def to_dict(self):
        d = asdict(self)
        d["audience"] = list(self.audience)
        return d


@dataclass
class Plan:
    intent_id: str
    policy_id: str
    operations: List[Operation]
    unresolved: List[dict] = field(default_factory=list)
    dialect: str = ""
    ruleset: str = RULESET_VERSION

    @property
    def plan_hash(self) -> str:
        body = json.dumps(
            {"intent": self.intent_id,
             "ops": [o.to_dict() for o in self.operations],
             "dialect": self.dialect, "ruleset": self.ruleset},
            sort_keys=True, separators=(",", ":"))
        return "P-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    @property
    def irreversible_ops(self) -> List[Operation]:
        return [o for o in self.operations if not o.reversible]

    def objects_touched(self) -> List[str]:
        return sorted({o.target.rsplit(".", 1)[0] for o in self.operations})

    def summary(self) -> dict:
        return {
            "plan_hash": self.plan_hash,
            "operations": len(self.operations),
            "objects": len(self.objects_touched()),
            "irreversible": len(self.irreversible_ops),
            "unresolved": len(self.unresolved),
            "rows_affected_estimate": sum(o.row_estimate for o in self.operations),
        }


# ---------------------------------------------------------------------
# Dialects
# ---------------------------------------------------------------------

class Dialect:
    name = "base"
    supports_masking_policy = False

    def quote(self, ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    def fq(self, f: ColumnFinding) -> str:
        return ".".join(self.quote(p) for p in (f.database, f.schema, f.table))

    def statements_for(self, f: ColumnFinding, ident: Identifier,
                       audience: tuple) -> List[str]:
        raise NotImplementedError


class SnowflakeDialect(Dialect):
    """Push-down: the warehouse executes, we never move rows.

    Snowflake masking policies are the right primitive — one policy object
    reused across many columns, evaluated at query time by role. That makes
    us a consumer of Snowflake's own feature rather than a competitor to it,
    which is also the reason they have no incentive to displace us.
    """
    name = "snowflake"
    supports_masking_policy = True

    BODY = {
        Treatment.REDACT:       "'***REDACTED***'",
        Treatment.MASK_PARTIAL: "CONCAT(REPEAT('*', GREATEST(LENGTH(val) - 4, 0)), RIGHT(val, 4))",
        Treatment.TOKENIZE:     "CONCAT('tok_', SHA2(CONCAT(val, '{salt}'), 256))",
        Treatment.HASH:         "SHA2(CONCAT(val, '{salt}'), 256)",
        Treatment.GENERALIZE:   "LEFT(val, 3)",
    }

    def policy_name(self, ident: Identifier, audience: tuple) -> str:
        tag = "_".join(sorted(a.lower() for a in audience)) or "none"
        return f"AAGCP_{ident.key.upper()}_{ident.treatment.value.upper()}_{tag.upper()}"

    def statements_for(self, f, ident, audience):
        col = self.quote(f.column)
        tbl = self.fq(f)

        if ident.treatment is Treatment.DROP:
            return [f"ALTER TABLE {tbl} DROP COLUMN {col};"]
        if ident.treatment is Treatment.RETAIN:
            return []

        pname = self.policy_name(ident, audience)
        body = self.BODY[ident.treatment].replace("{salt}", "$AAGCP_SALT")
        roles = " ".join(f"'{a.upper()}'," for a in audience).rstrip(",")
        guard = (f"WHEN CURRENT_ROLE() IN ({roles}) THEN val\n    " if audience else "")

        create = (
            f"CREATE MASKING POLICY IF NOT EXISTS {pname}\n"
            f"  AS (val STRING) RETURNS STRING ->\n"
            f"  CASE\n    {guard}ELSE {body}\n  END;"
        )
        apply = (f"ALTER TABLE {tbl} MODIFY COLUMN {col} "
                 f"SET MASKING POLICY {pname};")
        return [create, apply]


class PostgresDialect(Dialect):
    """Included to prove the abstraction. Postgres has no masking-policy
    object, so the same Intent compiles to a secured view plus a revoke —
    a different mechanism reaching the same guarantee."""
    name = "postgres"

    EXPR = {
        Treatment.REDACT:       "'***REDACTED***'",
        Treatment.MASK_PARTIAL: "repeat('*', greatest(length({c}) - 4, 0)) || right({c}, 4)",
        Treatment.TOKENIZE:     "'tok_' || encode(digest({c} || current_setting('aagcp.salt'), 'sha256'), 'hex')",
        Treatment.HASH:         "encode(digest({c} || current_setting('aagcp.salt'), 'sha256'), 'hex')",
        Treatment.GENERALIZE:   "left({c}, 3)",
    }

    def statements_for(self, f, ident, audience):
        col, tbl = self.quote(f.column), self.fq(f)
        view = self.quote(f"{f.table}_governed")
        if ident.treatment is Treatment.DROP:
            return [f"ALTER TABLE {tbl} DROP COLUMN {col};"]
        if ident.treatment is Treatment.RETAIN:
            return []
        expr = self.EXPR[ident.treatment].replace("{c}", col)
        stmts = [
            f"CREATE OR REPLACE VIEW {f.schema}.{view} AS\n"
            f"  SELECT *, {expr} AS {self.quote(f.column + '_masked')} FROM {tbl};",
            f"REVOKE SELECT ({col}) ON {tbl} FROM PUBLIC;",
        ]
        for role in audience:
            stmts.append(f"GRANT SELECT ({col}) ON {tbl} TO {self.quote(role)};")
        return stmts


DIALECTS = {d.name: d for d in (SnowflakeDialect(), PostgresDialect())}


# ---------------------------------------------------------------------
# The compiler
# ---------------------------------------------------------------------

IRREVERSIBLE = {Treatment.DROP, Treatment.HASH}


# aagcp.detect.detector.Finding is a SPAN in a piece of text
# (entity_type, value, start, end). This one is a COLUMN in a
# warehouse. They are different things that shared a name across the
# two codebases; the alias keeps existing callers working while the
# real name says which is which.
Finding = ColumnFinding

def compile_plan(intent: Intent, findings: List[ColumnFinding],
                 dialect_name: str = "snowflake",
                 registry: Dict[str, Policy] = None) -> Plan:
    """Deterministic. Same inputs, same plan_hash, forever."""
    registry = registry or REGISTRY
    policy = registry[intent.policy_id]
    idents = policy.by_key()
    dialect = DIALECTS[dialect_name]

    ops, unresolved = [], []
    # Sorted so two runs over the same findings emit operations in the same
    # order — otherwise the plan hash would depend on dict iteration.
    for f in sorted(findings, key=lambda x: (x.fqn, x.column, x.identifier_key)):
        ident = idents.get(f.identifier_key)
        if ident is None:
            unresolved.append({
                "column": f"{f.fqn}.{f.column}",
                "identifier_key": f.identifier_key,
                "cause": "IDENTIFIER_NOT_IN_POLICY",
                "detail": f"'{f.identifier_key}' is not governed by "
                          f"{policy.policy_id}; it is left untouched and reported.",
            })
            continue

        stmts = dialect.statements_for(f, ident, intent.audience)
        if not stmts:
            unresolved.append({
                "column": f"{f.fqn}.{f.column}",
                "identifier_key": f.identifier_key,
                "cause": "TREATMENT_IS_RETAIN",
                "detail": f"{ident.label} is in scope and deliberately retained "
                          f"({ident.citation}).",
            })
            continue

        ops.append(Operation(
            op="drop_column" if ident.treatment is Treatment.DROP
               else "apply_masking_policy",
            target=f"{f.fqn}.{f.column}",
            treatment=ident.treatment.value,
            identifier_key=ident.key,
            citation=ident.citation,
            audience=intent.audience,
            statements=stmts,
            reversible=ident.treatment not in IRREVERSIBLE,
            row_estimate=f.row_estimate,
        ))

    return Plan(intent_id=intent.intent_id, policy_id=policy.policy_id,
                operations=ops, unresolved=unresolved, dialect=dialect.name)


def coverage_gap(policy: Policy, findings: List[ColumnFinding]) -> List[dict]:
    """Phase 0 in miniature: which identifiers the regime requires that
    nothing in the estate matched. For a closed-list regime like HIPAA
    Safe Harbor, an unmatched identifier is either genuinely absent or
    undetected — and those are different, so it is reported rather than
    assumed."""
    seen = {f.identifier_key for f in findings}
    return [{
        "identifier_key": i.key,
        "label": i.label,
        "citation": i.citation,
        "cause": "NO_MATCH_IN_ESTATE",
        "detail": "Either absent from the estate or not detected. "
                  "De-identification cannot be claimed until this is resolved."
                  if policy.closed_list else
                  "Not detected in the scanned scope.",
    } for i in policy.identifiers if i.key not in seen]
