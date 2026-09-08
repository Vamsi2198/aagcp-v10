"""Executors — the only part of AAGCP that touches a customer's engine.

The engine above (intent, policy, plan) is a pure library with no I/O.
This package is where that stops being true, which is exactly why it runs
inside the customer's boundary and reports metadata upward: statuses,
cause codes and digests, never rows.
"""
from .base import (  # noqa: F401
    EXECUTOR_CONTRACT_VERSION,
    BaseExecutor,
    CapabilityError,
    Connection,
    Cursor,
    ExecutionReceipt,
    ExecutionVerdict,
    Executor,
    ExecutorError,
    FailurePolicy,
    OperationRecord,
    OperationStatus,
    Preview,
    StagePolicy,
    StatementError,
    StatementRecord,
    StatementStatus,
    TransportError,
)
from .snowflake import SnowflakeExecutor  # noqa: F401
from .erase import (SnowflakeEraseExecutor,  # noqa: F401
                    PostgresEraseExecutor)
from .vector import (AnchorHandle, VectorEraseExecutor,  # noqa: F401
                     VectorReceipt, VectorStore)
from .postgres import PostgresExecutor  # noqa: F401

EXECUTORS = {
    "snowflake": SnowflakeExecutor,
    "postgres": PostgresExecutor,
}

__all__ = [
    "EXECUTOR_CONTRACT_VERSION", "EXECUTORS",
    "BaseExecutor", "SnowflakeExecutor", "PostgresExecutor",
    "SnowflakeEraseExecutor", "PostgresEraseExecutor",
    "VectorEraseExecutor", "VectorReceipt", "VectorStore",
    "AnchorHandle",
    "Executor", "Connection", "Cursor",
    "Preview", "StagePolicy", "FailurePolicy",
    "ExecutionReceipt", "ExecutionVerdict",
    "OperationRecord", "OperationStatus",
    "StatementRecord", "StatementStatus",
    "ExecutorError", "StatementError", "TransportError", "CapabilityError",
]
