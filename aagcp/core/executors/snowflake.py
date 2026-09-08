"""
aagcp/core/executors/snowflake.py — push-down. We emit DDL, the warehouse
runs it, rows never move.

Two things here are load-bearing and easy to get wrong:

  * The masking policy object is SHARED. SnowflakeDialect names it from
    (identifier, treatment, audience), not from the column, so one policy
    governs every column with the same treatment. Rollback therefore
    UNSETs the policy from the column and leaves the object alone.
    Dropping it would silently un-govern every other column using it.

  * CREATE MASKING POLICY IF NOT EXISTS followed by a failed ALTER leaves
    an orphan policy object. It is inert — it governs nothing until a
    column references it — so it is a cleanup item, not an exposure. That
    distinction belongs in the receipt, which is why _residual_artifacts
    exists rather than a blanket "partial failure" flag.

Confidence: the DDL above is verified against the dialect in core/plan.py,
which is the only thing that produces it. The INFORMATION_SCHEMA
introspection below is INFERRED — POLICY_REFERENCES is the table function
I believe Snowflake exposes for this, but I have no live account here to
confirm the exact signature. It is isolated in two methods so a correction
is a two-line change and touches nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..plan import Operation, SnowflakeDialect
from ..policy import Treatment
from .base import (BaseExecutor, CapabilityError, StatementError,
                   TransportError, CAUSE_PRESTATE_MISSING)

_DIALECT = SnowflakeDialect()


@dataclass(frozen=True)
class _IdentShim:
    """Just enough of an Identifier to reuse the dialect's naming rule.
    Recomputing the policy name here instead would create a second source
    of truth that drifts the first time the rule changes."""
    key: str
    treatment: Treatment


def _policy_name(op: Operation) -> str:
    return _DIALECT.policy_name(
        _IdentShim(op.identifier_key, Treatment(op.treatment)),
        tuple(op.audience))


def _split_target(target: str) -> Tuple[str, str]:
    """'DB.SCHEMA.TABLE.COLUMN' -> ('DB.SCHEMA.TABLE', 'COLUMN')"""
    table, _, column = target.rpartition(".")
    return table, column


class SnowflakeExecutor(BaseExecutor):
    name = "snowflake-executor"
    dialect = "snowflake"
    supported_ops = ("apply_masking_policy", "drop_column")

    # ---- pre-state -------------------------------------------------
    def _capture_prestate(self, op: Operation) -> Optional[dict]:
        """A column may already carry a masking policy from an earlier run
        or from someone else's tooling. If it does, our rollback must not
        leave the column bare — it has to know what it displaced."""
        if op.op != "apply_masking_policy":
            return None
        table, column = _split_target(op.target)
        rows = self._query(
            f"-- aagcp:prestate\n"
            f"SELECT POLICY_NAME FROM TABLE("
            f"INFORMATION_SCHEMA.POLICY_REFERENCES("
            f"REF_ENTITY_NAME => '{table}', REF_ENTITY_DOMAIN => 'TABLE')) "
            f"WHERE REF_COLUMN_NAME = '{column}';")
        existing = [r[0] for r in rows] if rows else []
        return {"existing_policies": existing, "column": column, "table": table}

    # ---- verification ----------------------------------------------
    def _verify_operation(self, op: Operation) -> Tuple[Optional[bool], str]:
        if op.op == "drop_column":
            table, column = _split_target(op.target)
            rows = self._query(
                f"-- aagcp:verify\n"
                f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                f"WHERE TABLE_NAME = '{table.rsplit('.', 1)[-1]}' "
                f"AND COLUMN_NAME = '{column}';")
            if rows is None:
                return None, "column introspection returned nothing to read"
            return (len(rows) == 0), ("column is gone" if not rows
                                      else "column still present after DROP")

        expected = _policy_name(op)
        table, column = _split_target(op.target)
        rows = self._query(
            f"-- aagcp:verify\n"
            f"SELECT POLICY_NAME FROM TABLE("
            f"INFORMATION_SCHEMA.POLICY_REFERENCES("
            f"REF_ENTITY_NAME => '{table}', REF_ENTITY_DOMAIN => 'TABLE')) "
            f"WHERE REF_COLUMN_NAME = '{column}';")
        if rows is None:
            return None, "policy reference lookup unavailable"
        names = {r[0] for r in rows}
        if expected in names:
            return True, f"{expected} attached to {column}"
        return False, (f"{expected} not attached to {column}; "
                       f"found {sorted(names) or 'nothing'}")

    # ---- undo ------------------------------------------------------
    def _undo_statements(self, op: Operation, prestate: Optional[dict]) -> List[str]:
        table, column = _split_target(op.target)
        col = _DIALECT.quote(column)
        tbl = ".".join(_DIALECT.quote(p) for p in table.split("."))
        stmts = [f"ALTER TABLE {tbl} MODIFY COLUMN {col} UNSET MASKING POLICY;"]
        # Restore whatever we displaced. Without prestate we would leave the
        # column less governed than we found it and call that a rollback.
        for prior in (prestate or {}).get("existing_policies", []):
            if prior != _policy_name(op):
                stmts.append(f"ALTER TABLE {tbl} MODIFY COLUMN {col} "
                             f"SET MASKING POLICY {prior};")
        return stmts

    # ---- residue ---------------------------------------------------
    def _residual_artifacts(self, op: Operation, applied_upto: int) -> List[str]:
        if op.op == "apply_masking_policy" and applied_upto >= 1:
            return [f"masking policy {_policy_name(op)} created but not "
                    f"attached to {op.target} — inert, governs nothing, "
                    f"safe to drop if unreferenced"]
        return []
