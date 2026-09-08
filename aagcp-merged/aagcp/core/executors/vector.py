"""
aagcp/core/executors/vector.py — deletion from a vector store.

The gap this closes is embarrassing and worth stating plainly: until now
ErasureRequest verified a vector store that no code in this repository
ever deleted from. The attestation was real, the erasure was assumed.

THE ORDERING HOLE, CLOSED.
VectorTarget carried `anchor_registered: bool` — a claim the caller made
about itself. Everything downstream depended on it: the attestability
gate, the forecast, the decision to proceed. A boolean nobody checks is
not a precondition, it is a comment.

register() must run BEFORE the delete, because it captures where the
subject sat while the subject was still there. Afterwards the region is
unrecoverable and verify() has nothing to probe. So this executor demands
an AnchorHandle — an artifact that only exists if registration happened —
and refuses without one. It also records the handle's hash in the receipt,
so a later audit can tie the attestation to the registration that made it
possible rather than taking the sequence on trust.

WHAT THE POST-DELETE FETCH PROVES.
Very little, and it is included anyway. A fetch by id returning nothing
says the id is not addressable. It says nothing about the vector's
presence in an index segment, a replica, a snapshot, or a tombstone
awaiting compaction — which is precisely the list EngineType declares as
required_channels, and precisely why the statistical attestation exists.
So the fetch is recorded as a deterministic check with the same
three-valued honesty as everything else, and it never closes anything.
Only the attestation does.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from ..erasure import VectorTarget
from .base import (ExecutionVerdict, OperationStatus, StatementStatus,
                   CapabilityError, StatementError, TransportError)

CAUSE_NO_ANCHOR = "ANCHOR_NOT_REGISTERED_BEFORE_DELETE"
CAUSE_NO_IDS = "NO_RECORD_IDS_SUPPLIED_FOR_THE_SUBJECT"
CAUSE_DELETE_FAILED = "STORE_REJECTED_THE_DELETE"
CAUSE_DELETE_UNKNOWN = "DELETE_DISPATCHED_OUTCOME_UNOBSERVED"
CAUSE_STILL_ADDRESSABLE = "RECORD_STILL_FETCHABLE_BY_ID"
CAUSE_FETCH_UNAVAILABLE = "POST_DELETE_FETCH_COULD_NOT_RUN"
CAUSE_NOT_ADDRESSABLE = "RECORD_NOT_FETCHABLE_BY_ID"


class VectorStore(Protocol):
    """The two operations an erasure needs. Deliberately narrow — this is
    not a vector database abstraction, it is the part of one that an
    erasure touches.

    fetch() returns either a mapping of id to record, or a list of the
    records that were found. Both are common and _found_ids normalises
    them. The first live wiring of this port failed here, because the
    protocol assumed a mapping and the real connector returns a list of
    only the ids it has — which meant "nothing came back" was being read
    as "the fetch could not run".
    """
    def delete(self, ids: Sequence[str]) -> None: ...
    def fetch(self, ids: Sequence[str]): ...


def _found_ids(result, requested: Sequence[str]) -> Tuple[str, ...]:
    """Which of the requested ids the store still has."""
    if result is None:
        return ()
    if isinstance(result, dict):
        return tuple(sorted(k for k, v in result.items() if v is not None))
    found = []
    for rec in result:
        rid = getattr(rec, "id", None)
        if rid is None and isinstance(rec, str):
            rid = rec
        if rid in requested:
            found.append(rid)
    return tuple(sorted(found))


@dataclass(frozen=True)
class AnchorHandle:
    """Proof that register() ran, and when. Constructed from the verifier's
    SubjectAnchor by the adapter — the engine never sees the embedding."""
    token_hash: str
    store_name: str
    registered_at: str
    baseline_separation: Optional[float] = None
    record_ids: Tuple[str, ...] = ()

    def __post_init__(self):
        if not self.token_hash or not self.registered_at:
            raise CapabilityError(
                "an anchor handle without a token and a registration time "
                "is not evidence that registration happened")

    @property
    def handle_hash(self) -> str:
        return "A-" + hashlib.sha256(
            f"{self.token_hash}|{self.store_name}|{self.registered_at}"
            .encode()).hexdigest()[:12].upper()

    def to_dict(self):
        return {"token_hash": self.token_hash, "store_name": self.store_name,
                "registered_at": self.registered_at,
                "handle_hash": self.handle_hash,
                "record_ids": len(self.record_ids),
                "baseline_separation": self.baseline_separation}


@dataclass
class VectorReceipt:
    store_name: str
    engine: str
    verdict: ExecutionVerdict
    requested_ids: Tuple[str, ...]
    deleted_ids: Tuple[str, ...] = ()
    status: OperationStatus = OperationStatus.NOT_ATTEMPTED
    cause: str = ""
    detail: str = ""
    anchor: Optional[dict] = None
    still_addressable: Tuple[str, ...] = ()
    fetch_checked: Optional[bool] = None      # True/False/None as everywhere

    def to_dict(self):
        return {"store_name": self.store_name, "engine": self.engine,
                "verdict": self.verdict.value, "status": self.status.value,
                "requested": len(self.requested_ids),
                "deleted": len(self.deleted_ids),
                "still_addressable": list(self.still_addressable),
                "fetch_checked": self.fetch_checked,
                "cause": self.cause, "detail": self.detail,
                "anchor": self.anchor}

    @property
    def receipt_hash(self) -> str:
        import json
        return "RV-" + hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()[:12].upper()

    def explain(self) -> str:
        lines = [f"{self.verdict.value} — {self.store_name} [{self.engine}]: "
                 f"{len(self.deleted_ids)} of {len(self.requested_ids)} "
                 f"record(s) deleted"]
        if self.cause:
            lines.append(f"  {self.cause}: {self.detail}")
        if self.still_addressable:
            lines.append(f"  {CAUSE_STILL_ADDRESSABLE}: "
                         f"{', '.join(self.still_addressable)}")
        if self.fetch_checked is None:
            lines.append("  the post-delete fetch could not run")
        lines.append("  a successful delete is not an erasure; only the "
                     "attestation closes this")
        return "\n".join(lines)


class VectorEraseExecutor:
    """Deletes a subject's records from one store. Refuses without an
    anchor, because the anchor is the thing that makes the result
    verifiable and it cannot be obtained afterwards."""

    name = "vector-erase-executor"

    def __init__(self, store: VectorStore, target: VectorTarget):
        self.store = store
        self.target = target

    def preview(self, anchor: Optional[AnchorHandle],
                record_ids: Optional[Sequence[str]] = None) -> dict:
        # None means "not supplied, use the anchor's". An explicit empty
        # list means "delete nothing", which is an instruction and is
        # refused rather than quietly widened to the anchor's ids.
        ids = tuple(record_ids if record_ids is not None
                    else (anchor.record_ids if anchor else ()))
        problems = []
        if anchor is None:
            problems.append({
                "cause": CAUSE_NO_ANCHOR,
                "detail": "register() must run before the delete; afterwards "
                          "the subject's region cannot be located and no "
                          "attestation is reachable"})
        elif anchor.store_name != self.target.store_name:
            problems.append({
                "cause": CAUSE_NO_ANCHOR,
                "detail": f"the anchor is for {anchor.store_name}, not "
                          f"{self.target.store_name}"})
        if not ids:
            problems.append({"cause": CAUSE_NO_IDS,
                             "detail": "no record ids to delete; an erasure "
                                       "that targets nothing is not a no-op, "
                                       "it is a lookup that failed"})
        return {"store_name": self.target.store_name,
                "engine": self.target.engine, "record_ids": list(ids),
                "problems": problems, "executable": not problems,
                "anchor": anchor.to_dict() if anchor else None}

    def execute(self, anchor: Optional[AnchorHandle],
                record_ids: Optional[Sequence[str]] = None) -> VectorReceipt:
        pre = self.preview(anchor, record_ids)
        ids = tuple(pre["record_ids"])
        if not pre["executable"]:
            return VectorReceipt(
                self.target.store_name, self.target.engine,
                ExecutionVerdict.REFUSED, ids,
                cause=pre["problems"][0]["cause"],
                detail=pre["problems"][0]["detail"],
                anchor=pre["anchor"])

        try:
            self.store.delete(list(ids))
        except TransportError as exc:
            return VectorReceipt(
                self.target.store_name, self.target.engine,
                ExecutionVerdict.INCONCLUSIVE, ids,
                status=OperationStatus.UNKNOWN, cause=CAUSE_DELETE_UNKNOWN,
                detail=str(exc), anchor=pre["anchor"])
        except (StatementError, Exception) as exc:
            if isinstance(exc, TransportError):
                raise
            return VectorReceipt(
                self.target.store_name, self.target.engine,
                ExecutionVerdict.FAILED, ids,
                status=OperationStatus.FAILED, cause=CAUSE_DELETE_FAILED,
                detail=str(exc), anchor=pre["anchor"])

        # The weakest possible confirmation, recorded as such.
        still, checked = (), None
        try:
            found = self.store.fetch(list(ids))
            checked = True
            still = _found_ids(found, ids)
        except Exception:
            checked = None

        if still:
            return VectorReceipt(
                self.target.store_name, self.target.engine,
                ExecutionVerdict.PARTIAL, ids,
                deleted_ids=tuple(i for i in ids if i not in still),
                status=OperationStatus.PARTIALLY_APPLIED,
                cause=CAUSE_STILL_ADDRESSABLE,
                detail=f"{len(still)} record(s) remain fetchable by id",
                anchor=pre["anchor"], still_addressable=still,
                fetch_checked=checked)

        if checked is None:
            return VectorReceipt(
                self.target.store_name, self.target.engine,
                ExecutionVerdict.INCONCLUSIVE, ids, deleted_ids=ids,
                status=OperationStatus.APPLIED, cause=CAUSE_FETCH_UNAVAILABLE,
                detail="the delete was accepted and the post-delete fetch "
                       "could not run, so even addressability is unconfirmed",
                anchor=pre["anchor"], fetch_checked=None)

        return VectorReceipt(
            self.target.store_name, self.target.engine,
            ExecutionVerdict.COMPLETE, ids, deleted_ids=ids,
            status=OperationStatus.APPLIED, cause=CAUSE_NOT_ADDRESSABLE,
            detail="records are no longer fetchable by id; presence in "
                   "index segments, replicas and snapshots is a separate "
                   "question that only the attestation answers",
            anchor=pre["anchor"], fetch_checked=True)
