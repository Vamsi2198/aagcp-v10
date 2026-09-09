"""
aagcp/real.py — the real-warehouse seam: connect, scan, execute.

This is the "real data in / real data out" layer. Everything it produces is
the same object vocabulary aagcp.core already consumes — Inventory,
Inspection, ColumnFinding — so the governed flow downstream is untouched.

Honesty notes:
  * The scan covers ONE schema of ONE database. Inventory.complete is False
    because an information_schema crawl does not assert estate completeness;
    every rate renders "at least N" and the forecast is floored accordingly.
  * Sampling is LIMIT-based (arbitrary rows), not statistical. Confidence is
    the measured match fraction over sampled values, never invented.
  * The adapter maps connector errors onto the executor's two-exception
    contract: ProgrammingError -> StatementError (definitely not applied),
    everything else connection-level -> TransportError (outcome unknown).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .core.coverage import Column, Inspection, Inventory
from .core.plan import Finding
from .core.executors.base import StatementError, TransportError
from .detect.patterns import GLOBAL_PATTERNS

try:
    import snowflake.connector
    from snowflake.connector.errors import ProgrammingError
    _CONNECTOR = True
except Exception:  # pragma: no cover
    _CONNECTOR = False

LOCAL_CREDENTIALS = "snowflake.local.json"   # gitignored; never committed

# detector entity -> policy identifier key (canonical across REGISTRY policies)
ENTITY_TO_KEY = {
    "EMAIL": "email",
    "US_PHONE": "phone", "IN_PHONE": "phone", "INTL_PHONE": "phone",
    "US_SSN": "ssn",
    "AADHAAR": "aadhaar", "PAN": "pan", "IN_VOTER_ID": "voter_id",
    "IN_PASSPORT": "passport", "IBAN": "bank", "CREDIT_CARD": "pan",
    "IPV4": "ip", "IPV6": "ip", "DOB": "dob", "MRN": "mrn", "PERSON": "name",
}

TEXT_TYPES = {"VARCHAR", "CHAR", "CHARACTER", "STRING", "TEXT"}
DATE_TYPES = {"DATE", "DATETIME", "TIMESTAMP", "TIMESTAMP_NTZ",
              "TIMESTAMP_LTZ", "TIMESTAMP_TZ"}
NAME_HINTS = [
    ("aadhaar", "aadhaar"), ("aadhar", "aadhaar"), ("uid", "aadhaar"),
    ("pan", "pan"), ("passport", "passport"), ("voter", "voter_id"),
    ("email", "email"), ("mail", "email"),
    ("phone", "phone"), ("mobile", "phone"), ("tel", "phone"),
    ("ssn", "ssn"), ("social", "ssn"),
    ("dob", "dob"), ("birth", "dob"),
    ("iban", "bank"), ("account", "bank"),
    ("ip", "ip"), ("name", "name"),
]


@dataclass(frozen=True)
class Credentials:
    account: str
    user: str
    password: str
    warehouse: str = "COMPUTE_WH"
    database: str = ""
    schema: str = "PUBLIC"
    role: str = "ACCOUNTADMIN"


def load_credentials(path: str = LOCAL_CREDENTIALS) -> Optional[Credentials]:
    """Env vars first, then a gitignored local JSON. Never hardcode creds."""
    data = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    env = {k: os.environ.get(k) for k in
           ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD",
            "SNOWFLAKE_WAREHOUSE", "SNOWFLAKE_DATABASE", "SNOWFLAKE_SCHEMA",
            "SNOWFLAKE_ROLE")}
    merged = {**{k.lower(): v for k, v in env.items() if v}, **data}
    if not merged.get("account") or not merged.get("user"):
        return None
    return Credentials(
        account=merged["account"], user=merged["user"],
        password=merged.get("password", ""),
        warehouse=merged.get("warehouse", "COMPUTE_WH"),
        database=merged.get("database", ""), schema=merged.get("schema", "PUBLIC"),
        role=merged.get("role", "ACCOUNTADMIN"))


def connect(creds: Credentials):
    if not _CONNECTOR:
        raise RuntimeError("snowflake-connector-python is not installed")
    conn = snowflake.connector.connect(
        account=creds.account, user=creds.user, password=creds.password,
        warehouse=creds.warehouse, database=creds.database or None,
        schema=creds.schema, role=creds.role)
    conn.autocommit(True)   # DDL must not sit in an open transaction
    return conn


class SnowflakeAdapter:
    """Wraps a real connection in the executor's two-method cursor protocol,
    mapping connector errors onto StatementError / TransportError."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        conn = self._conn

        class _Cursor:
            def __init__(self):
                self._cur = None

            def execute(_, sql: str) -> None:
                cur = conn.cursor()
                try:
                    cur.execute(sql)
                except ProgrammingError as exc:
                    raise StatementError(str(exc)) from exc
                except Exception as exc:
                    if _CONNECTOR and isinstance(
                            exc, snowflake.connector.errors.Error):
                        raise TransportError(str(exc)) from exc
                    raise
                _._cur = cur

            def fetchall(_):
                return _._cur.fetchall() if _._cur is not None else []

        return _Cursor()


def test_connection(creds: Credentials) -> dict:
    conn = connect(creds)
    try:
        cur = conn.cursor()
        cur.execute("SELECT CURRENT_ACCOUNT(), CURRENT_USER(), CURRENT_ROLE()")
        account, user, role = cur.fetchone()
        return {"ok": True, "account": account, "user": user, "role": role,
                "database": creds.database, "schema": creds.schema}
    finally:
        conn.close()


# ---------------------------------------------------------------------
# The scan layer
# ---------------------------------------------------------------------

@dataclass
class ScanResult:
    inventory: Inventory
    inspections: List[Inspection]
    findings: List[Finding]
    sampled: Dict[str, int]          # target -> rows actually sampled

    def summary(self) -> dict:
        return {
            "columns": len(self.inventory.columns),
            "sampled_columns": len(self.sampled),
            "findings": [f"{f.fqn}.{f.column} [{f.identifier_key}]" 
                         for f in self.findings],
            "coverage_note": ("denominator NOT asserted complete — "
                              "one schema is not an estate"),
        }


def _detect_in_values(values: Sequence[str]) -> Tuple[Optional[str], float, int]:
    """Return (identifier_key, confidence, hits) for the strongest entity
    across sampled values. Confidence is the measured hit fraction."""
    counts: Dict[str, int] = {}
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        for pat in GLOBAL_PATTERNS:
            if pat.regex.search(text):
                key = ENTITY_TO_KEY.get(pat.entity_type)
                if key:
                    counts[key] = counts.get(key, 0) + 1
                break
    if not counts:
        return None, 0.0, 0
    key = max(counts, key=counts.get)
    return key, min(0.99, counts[key] / max(1, len(values))), counts[key]


def scan_schema(creds: Credentials, sample_size: int = 500) -> ScanResult:
    """Crawl one schema's catalog, sample values, detect identifiers.
    Produces exactly the objects coverage.assess() and compile_plan() take."""
    conn = connect(creds)
    inspections: List[Inspection] = []
    findings: List[Finding] = []
    columns: List[Column] = []
    sampled: Dict[str, int] = {}
    db, sch = creds.database.upper(), creds.schema.upper()

    def q(sql: str) -> List[tuple]:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    try:
        catalog = q(
            f'SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE '
            f'FROM "{db}".INFORMATION_SCHEMA.COLUMNS '
            f"WHERE TABLE_SCHEMA = '{sch}' "
            f"ORDER BY TABLE_NAME, ORDINAL_POSITION")

        tables = sorted({r[0] for r in catalog})
        rowcounts = {}
        for t in tables:
            try:
                rowcounts[t] = int(q(f'SELECT COUNT(*) FROM "{db}"."{sch}"."{t}"')[0][0])
            except Exception:
                rowcounts[t] = 0

        for table, column, dtype in catalog:
            dt = (dtype or "").upper()
            col = Column(db, sch, table, column, dt, rowcounts.get(table, 0))
            columns.append(col)
            target = col.target
            if dt in TEXT_TYPES or dt in DATE_TYPES:
                expr = (f'TO_VARCHAR("{column}")' if dt in DATE_TYPES
                        else f'"{column}"')
                try:
                    rows = q(f'SELECT {expr} FROM "{db}"."{sch}"."{table}" '
                             f'LIMIT {sample_size}')
                except Exception as exc:
                    inspections.append(Inspection(
                        target, "content_sample", 0, "", 0.0, str(exc)))
                    continue
                values = [r[0] for r in rows if r and r[0] is not None]
                sampled[target] = len(values)
                key, conf, hits = _detect_in_values(values)
                if key and conf >= 0.3:
                    inspections.append(Inspection(
                        target, "content_sample", len(values), key, conf))
                    findings.append(Finding(db, sch, table, column, key,
                                            "regex", conf, col.row_estimate))
                    continue
                # content inconclusive: fall back to the column name as a hint
                hint = next((k for needle, k in NAME_HINTS
                             if needle in column.lower()), "")
                if hint:
                    inspections.append(Inspection(
                        target, "name_hint", len(values), hint, 0.50))
            # non-text types and unscanned columns simply have no Inspection:
            # absence of an inspection is NOT_SCANNED, never "clean"
    finally:
        conn.close()

    inventory = Inventory(
        tuple(columns),
        source=f"snowflake:{creds.account}/{db}/{sch}",
        complete=False)   # one schema is not an estate — say so
    return ScanResult(inventory, inspections, findings, sampled)
