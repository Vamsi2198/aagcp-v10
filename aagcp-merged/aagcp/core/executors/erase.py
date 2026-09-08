"""
aagcp/core/executors/erase.py — executors that can actually run an
erasure plan.

compile_erasure_plan emits 'erase_rows' and 'erase_fields'. Neither was in
any executor's supported_ops, so an erasure was planned, forecast,
approved, and then refused at preview with
OPERATION_NOT_SUPPORTED_BY_EXECUTOR. The capability check was doing its job
and the claim above it was false.

Fixing it needed one thing the masking executors do not: the subject. A
masking policy verifies by asking the catalog whether it is attached, and
the catalog knows. An erasure verifies by asking whether the subject is
still there, which means the executor has to know who the subject is. So
these are constructed per-erasure and scoped to one subject, rather than
being a general executor that parses a WHERE clause back out of the DDL it
is about to run.

WHAT THE RE-QUERY IS AND IS NOT. structured_check() re-reads the table and
counts rows matching the subject. Zero rows is necessary and not
sufficient — it says the subject is not reachable by that key in that
table, which is a different claim from the data being gone. A row moved to
a history table, a clone taken before the delete, a Time Travel retention
window all leave the subject recoverable while the count reads zero.
Snowflake makes this concrete: DELETE leaves the rows readable through
AT(OFFSET) for the retention period, so the honest verdict immediately
after an erasure is that the subject is unreachable through the current
table and still recoverable through Time Travel. That is reported rather
than smoothed, because the alternative is a governance product that
certifies an erasure the warehouse can undo.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..erasure import EraseMode, StructuredCheck, Subject
from ..plan import Operation
from .base import (CAUSE_NOT_VERIFIED, BaseExecutor, CapabilityError,
                   StatementError, TransportError)
from .postgres import PostgresExecutor, _split_target as _pg_split
from .snowflake import SnowflakeExecutor, _split_target as _sf_split

CAUSE_TIME_TRAVEL = "ROWS_STILL_RECOVERABLE_THROUGH_TIME_TRAVEL"
CAUSE_REQUERY_FAILED = "SUBJECT_REQUERY_COULD_NOT_RUN"
CAUSE_SUBJECT_PRESENT = "SUBJECT_STILL_RETURNS_ROWS"
CAUSE_SUBJECT_ABSENT = "SUBJECT_RETURNS_NO_ROWS"

_ERASE_OPS = ("erase_rows", "erase_fields")


class _EraseMixin:
    """Shared behaviour. The dialect-specific parts are the re-query and
    the recoverability window."""

    def __init__(self, connection, subject: Subject, **kw):
        super().__init__(connection, **kw)
        if not isinstance(subject, Subject):
            raise CapabilityError(
                "an erase executor is scoped to one subject and must be "
                "given it; deriving the subject from the DDL would mean "
                "parsing SQL to find out what we are about to delete")
        self.subject = subject

    # Erasure has no pre-state worth capturing: there is no undo, so there
    # is nothing a snapshot would enable. Returning None here rather than
    # inheriting the masking executor's policy lookup keeps preview from
    # issuing a query whose answer could never be used.
    def _capture_prestate(self, op: Operation) -> Optional[dict]:
        if op.op in _ERASE_OPS:
            return None
        return super()._capture_prestate(op)

    def _undo_statements(self, op: Operation, prestate):
        if op.op in _ERASE_OPS:
            raise CapabilityError(
                f"{op.op} on {op.target} cannot be reversed by this executor; "
                f"recovery, where it exists at all, is an engine feature "
                f"outside the plan")
        return super()._undo_statements(op, prestate)

    # No _residual_artifacts override for the erase ops. Both compile to a
    # single atomic statement, so there is no half-applied state to name: a
    # failed UPDATE nulls nothing and a failed DELETE removes nothing. An
    # artifact describing a partially de-identified record would read well
    # and describe a state this compiler cannot produce. If erase_fields
    # ever compiles to more than one statement, that changes and this needs
    # to come back.

    # ---- the re-query -------------------------------------------------
    def structured_check(self, op: Operation) -> StructuredCheck:
        """Feeds ErasureRequest.record_structured_check. Three-valued:
        True still present, False not present by this key, None could not
        determine."""
        try:
            rows = self._count_subject(op)
        except (StatementError, TransportError) as exc:
            return StructuredCheck(op.target, None,
                                   f"{CAUSE_REQUERY_FAILED}: {exc}")
        if rows is None:
            return StructuredCheck(op.target, None,
                                   f"{CAUSE_REQUERY_FAILED}: the count "
                                   f"returned nothing to read")
        if rows > 0:
            return StructuredCheck(op.target, True,
                                   f"{CAUSE_SUBJECT_PRESENT}: {rows} row(s) "
                                   f"still match the subject key")
        # Zero rows. Whether that amounts to absence is a dialect question,
        # and on some engines the answer is "not yet".
        gone, detail = self._absence_verdict(op)
        return StructuredCheck(op.target, gone, detail)

    def _absence_verdict(self, op: Operation) -> Tuple[Optional[bool], str]:
        """(False = confirmed absent, None = cannot yet be called absent)."""
        return False, f"{CAUSE_SUBJECT_ABSENT}: 0 rows match the subject key"

    def _count_subject(self, op: Operation) -> Optional[int]:
        raise NotImplementedError

    def _verify_operation(self, op: Operation) -> Tuple[Optional[bool], str]:
        if op.op not in _ERASE_OPS:
            return super()._verify_operation(op)
        chk = self.structured_check(op)
        if chk.subject_present is None:
            return None, chk.detail
        return (not chk.subject_present), chk.detail


class SnowflakeEraseExecutor(_EraseMixin, SnowflakeExecutor):
    name = "snowflake-erase-executor"
    supported_ops = SnowflakeExecutor.supported_ops + _ERASE_OPS

    def __init__(self, connection, subject: Subject,
                 retention_days: Optional[int] = None, **kw):
        """retention_days is the table's DATA_RETENTION_TIME_IN_DAYS. None
        means it was not read, which is reported as unknown rather than
        assumed to be zero."""
        super().__init__(connection, subject, **kw)
        self.retention_days = retention_days

    def _count_subject(self, op: Operation) -> Optional[int]:
        table, column = _sf_split(op.target)
        tbl = ".".join(self.dialect_quote(p) for p in table.split("."))
        col = self.dialect_quote(column)
        rows = self._query(
            f"-- aagcp:verify\n"
            f"SELECT COUNT(*) FROM {tbl} WHERE {col} = {self.subject.literal};")
        if not rows:
            return None
        return int(rows[0][0])

    def dialect_quote(self, part: str) -> str:
        from ..plan import SnowflakeDialect
        return SnowflakeDialect().quote(part)

    def _absence_verdict(self, op: Operation):
        """Zero rows in the current table is NOT absence while Time Travel
        is open. AT(OFFSET) is a supported query interface, not a forensic
        recovery path — the subject is still readable by anyone with SELECT
        for the length of the retention window. Returning False here would
        let ErasureRequest close a request whose data the warehouse can
        hand back tomorrow, so the verdict is None: not yet determinable."""
        base = f"{CAUSE_SUBJECT_ABSENT}: 0 rows match the subject key"
        if self.retention_days is None:
            return None, (f"{base}; DATA_RETENTION_TIME_IN_DAYS was not read, "
                          f"so whether the rows remain readable through "
                          f"AT(OFFSET) is unknown and absence cannot be "
                          f"claimed")
        if self.retention_days > 0:
            return None, (f"{base}; {CAUSE_TIME_TRAVEL}: retention is "
                          f"{self.retention_days} day(s), so the rows stay "
                          f"readable through AT(OFFSET) and the erasure is "
                          f"not final until that window closes")
        return False, f"{base}; retention is 0 days, so no Time Travel copy remains"


class PostgresEraseExecutor(_EraseMixin, PostgresExecutor):
    name = "postgres-erase-executor"
    supported_ops = PostgresExecutor.supported_ops + _ERASE_OPS
    # The masking executor needs a grant snapshot to reverse a REVOKE.
    # Erasure reverses nothing, so demanding one would refuse plans for a
    # capability they never use.
    prestate_required = False

    def _count_subject(self, op: Operation) -> Optional[int]:
        _, schema, table, column = _pg_split(op.target)
        from ..plan import PostgresDialect
        q = PostgresDialect().quote
        rows = self._query(
            f"-- aagcp:verify\n"
            f"SELECT COUNT(*) FROM {q(schema)}.{q(table)} "
            f"WHERE {q(column)} = {self.subject.literal};")
        if not rows:
            return None
        return int(rows[0][0])

    def _absence_verdict(self, op: Operation):
        """Unlike Snowflake Time Travel, a deleted Postgres row is not
        reachable through any SQL interface — heap and WAL residue require
        forensic or backup recovery, which is a different class of exposure
        and not one a re-query can speak to. So absence is confirmed, with
        the residue named rather than implied."""
        return False, (f"{CAUSE_SUBJECT_ABSENT}: 0 rows match the subject "
                       f"key; the dead tuple remains in the heap until "
                       f"VACUUM and in any base backup or WAL segment "
                       f"already taken, neither of which is reachable by "
                       f"query")
