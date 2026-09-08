"""
aagcp/core/executors/mock.py — a cursor you can make fail on purpose.

The point is not to simulate a warehouse. It is to reach the states that
only appear when something goes wrong, and that are otherwise untestable
until they happen in a customer's account at 3am: a rejected statement in
the middle of a multi-statement operation, and a dropped connection where
the outcome is genuinely unobserved.

Rules are matched against the SQL text in order, first match wins, and
each rule can be limited to N firings so you can fail the third ALTER and
not the first two.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .base import StatementError, TransportError


@dataclass
class Rule:
    contains: str                    # substring match against the SQL
    kind: str = "error"              # "error" | "transport"
    message: str = "mock failure"
    limit: Optional[int] = None      # None = every time
    fired: int = 0

    def matches(self, sql: str) -> bool:
        if self.contains not in sql:
            return False
        return self.limit is None or self.fired < self.limit


class MockCursor:
    def __init__(self, engine: "MockEngine"):
        self.engine = engine
        self._rows: List[tuple] = []

    def execute(self, sql: str) -> None:
        self.engine.executed.append(sql)
        for rule in self.engine.rules:
            if rule.matches(sql):
                rule.fired += 1
                if rule.kind == "transport":
                    raise TransportError(rule.message)
                raise StatementError(rule.message)
        self._rows = self.engine.rows_for(sql)

    def fetchall(self) -> List[tuple]:
        return self._rows


class MockEngine:
    """Stands in for a connection. `queries` maps a substring to the rows a
    SELECT should return; anything unmatched returns []."""

    def __init__(self, rules: Sequence[Rule] = (),
                 queries: Optional[Dict[str, List[tuple]]] = None):
        self.rules: List[Rule] = list(rules)
        self.queries: Dict[str, List[tuple]] = dict(queries or {})
        self.executed: List[str] = []

    def cursor(self) -> MockCursor:
        return MockCursor(self)

    def rows_for(self, sql: str) -> List[tuple]:
        for needle, rows in self.queries.items():
            if needle in sql:
                return list(rows)
        return []

    # ---- convenience for tests ------------------------------------
    @staticmethod
    def _first_keyword(sql: str) -> str:
        for line in sql.splitlines():
            line = line.strip()
            if line and not line.startswith("--"):
                return line.split(None, 1)[0].upper()
        return ""

    def ddl(self) -> List[str]:
        """Only the mutating statements, in order. Introspection queries
        are tagged with a leading comment, so skip past comment lines
        before deciding — otherwise every tagged SELECT reads as DDL."""
        return [s for s in self.executed if self._first_keyword(s) != "SELECT"]

    def reset(self) -> None:
        self.executed.clear()
        for r in self.rules:
            r.fired = 0


def verifying_engine(policy_names: Sequence[str] = (),
                     rules: Sequence[Rule] = ()) -> MockEngine:
    """A Snowflake-shaped engine whose POLICY_REFERENCES lookup reports the
    given policies as attached — i.e. verification passes."""
    return MockEngine(
        rules=rules,
        queries={"POLICY_REFERENCES": [(n,) for n in policy_names],
                 "INFORMATION_SCHEMA.COLUMNS": []})
