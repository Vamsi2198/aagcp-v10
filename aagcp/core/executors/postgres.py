"""
aagcp/core/executors/postgres.py — the same Intent, a different mechanism.

Postgres has no masking-policy object, so PostgresDialect reaches the same
guarantee with a governed view plus a REVOKE. That changes what rollback
means, and the change is not cosmetic.

A REVOKE destroys information. Reversing it means re-granting — but to
whom? "GRANT SELECT ... TO PUBLIC" is only correct if PUBLIC held it
before, and we do not know that after the fact. So this executor captures
the grant list during preview and refuses to roll back without it. An
executor that guessed the prior grants would either over-grant (a fresh
exposure) or under-grant (a silent outage), and would report both as a
clean revert.

Confidence: the information_schema.column_privileges query below is
INFERRED. The view exists and carries grantee/privilege_type; I have not
run it here to confirm column names against a live server.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..plan import Operation, PostgresDialect
from .base import BaseExecutor, CapabilityError

_DIALECT = PostgresDialect()


def _split_target(target: str):
    """'DB.SCHEMA.TABLE.COLUMN' -> (db, schema, table, column)"""
    parts = target.split(".")
    return parts[0], parts[1], parts[2], ".".join(parts[3:])


class PostgresExecutor(BaseExecutor):
    name = "postgres-executor"
    dialect = "postgres"
    supported_ops = ("apply_masking_policy", "drop_column")
    prestate_required = True

    # ---- pre-state -------------------------------------------------
    def _capture_prestate(self, op: Operation) -> Optional[dict]:
        if op.op != "apply_masking_policy":
            return None
        _, schema, table, column = _split_target(op.target)
        rows = self._query(
            f"-- aagcp:prestate\n"
            f"SELECT grantee, privilege_type FROM information_schema.column_privileges "
            f"WHERE table_schema = '{schema}' AND table_name = '{table}' "
            f"AND column_name = '{column}';")
        return {"grants": [list(r) for r in (rows or [])],
                "schema": schema, "table": table, "column": column}

    # ---- verification ----------------------------------------------
    def _verify_operation(self, op: Operation) -> Tuple[Optional[bool], str]:
        _, schema, table, column = _split_target(op.target)

        if op.op == "drop_column":
            rows = self._query(
                f"-- aagcp:verify\n"
                f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema = '{schema}' AND table_name = '{table}' "
                f"AND column_name = '{column}';")
            if rows is None:
                return None, "column introspection unavailable"
            return (len(rows) == 0), ("column is gone" if not rows
                                      else "column still present after DROP")

        # Two conditions, both required: the governed view exists, and the
        # raw column is no longer readable by PUBLIC. Checking only the view
        # would pass a state where the underlying column is still exposed.
        view = f"{table}_governed"
        vrows = self._query(
            f"-- aagcp:verify\n"
            f"SELECT viewname FROM pg_views "
            f"WHERE schemaname = '{schema}' AND viewname = '{view}';")
        prows = self._query(
            f"-- aagcp:verify\n"
            f"SELECT grantee FROM information_schema.column_privileges "
            f"WHERE table_schema = '{schema}' AND table_name = '{table}' "
            f"AND column_name = '{column}' AND grantee = 'PUBLIC';")
        if vrows is None or prows is None:
            return None, "view or privilege lookup unavailable"
        if not vrows:
            return False, f"governed view {schema}.{view} not found"
        if prows:
            return False, f"PUBLIC still holds SELECT on {column}"
        return True, f"{schema}.{view} present and {column} revoked from PUBLIC"

    # ---- undo ------------------------------------------------------
    def _undo_statements(self, op: Operation, prestate: Optional[dict]) -> List[str]:
        _, schema, table, column = _split_target(op.target)
        if op.op == "apply_masking_policy" and prestate is None:
            raise CapabilityError(
                f"no grant snapshot for {op.target}; reversing the REVOKE "
                f"would be a guess at who held access before")

        col = _DIALECT.quote(column)
        tbl = ".".join(_DIALECT.quote(p) for p in (op.target.split(".")[:3]))
        stmts = [f"DROP VIEW IF EXISTS {_DIALECT.quote(schema)}."
                 f"{_DIALECT.quote(table + '_governed')};"]
        for grantee, privilege in prestate.get("grants", []):
            if privilege.upper() != "SELECT":
                continue
            target = "PUBLIC" if grantee.upper() == "PUBLIC" else _DIALECT.quote(grantee)
            stmts.append(f"GRANT SELECT ({col}) ON {tbl} TO {target};")
        return stmts

    def _residual_artifacts(self, op: Operation, applied_upto: int) -> List[str]:
        # Statement 0 creates the view, statement 1 revokes. A view that
        # exists while the REVOKE never landed is the dangerous half: the
        # masked view is present and the raw column is still readable, so
        # anyone auditing by looking for the view sees governance that is
        # not there.
        if op.op == "apply_masking_policy" and applied_upto == 1:
            _, schema, table, column = _split_target(op.target)
            return [f"governed view {schema}.{table}_governed exists but "
                    f"{column} was never revoked — the view implies a control "
                    f"that is not in force"]
        return []
