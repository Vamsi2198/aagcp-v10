"""
aagcp/core/journal.py — the substrate three separate gaps turned out to
share.

Surviving a process restart, producing an audit trail, and approving as a
named user look like three features. They are one: a durable, ordered,
append-only record of every phase transition, each carrying the hash of
what it is about and the principal who caused it. Without it, every
receipt in this codebase is a well-formed number floating free — the
forecast does not know which plan it authorised, the execution does not
know which forecast permitted it, and an AWAITING_VERIFICATION request
evaporates when the process dies, which makes "the request stays open" a
statement about a Python object rather than about the world.

WHAT THIS IS NOT. It is not an immutable audit trail and this file will
not call it one. A hash chain written and held by the operator is
tamper-EVIDENT against anyone who cannot rewrite the whole file, and
worth nothing against the operator, who can recompute every link. It
becomes evidence at the moment head() is witnessed somewhere the operator
does not control — a counterparty, a timestamping service, a regulator's
inbox. checkpoint() exists to be exported for exactly that, and
verify_chain() can only tell you the file is internally consistent with
itself. AAGCP_v3's AttestationLog says the same thing about itself in its
own docstring, and it is right to.

AttestationLog stays the log of record for attestations. A VERIFY entry
carries refs['attestation_log_index'] and refs['attestation_log_hash']
from AttestationLog.append(), so the journal points at the attestation
instead of duplicating its body into a second chain. verify_bindings()
checks the pointer is present whenever an attestation was involved.

TWO DIFFERENCES FROM AttestationLog:

  * Append-only on disk, not just in structure. AttestationLog rewrites
    the entire file on every append, so a crash mid-write can truncate
    the whole history. This writes one JSON object per line, flushes and
    fsyncs, so a crash costs at most a partial final line — which is
    detected and reported rather than silently dropped.
  * It binds phases to each other. A hash chain proves nobody edited the
    sequence. It says nothing about whether the execution at entry 40 was
    authorised by the forecast at entry 38, or whether that forecast was
    even for the same plan. verify_bindings() is the part that checks the
    story is coherent, and it is a different question from whether the
    file was edited.

SEPARATION OF DUTIES is enforced here rather than by convention: the
principal who submitted a change cannot approve it, and no principal can
approve above their own authority tier.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

JOURNAL_VERSION = "journal-1.0.0"
GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


class Phase(str, Enum):
    OBSERVE = "observe"
    ANALYZE = "analyze"
    RESOLVE = "resolve"
    PLAN = "plan"
    SIMULATE = "simulate"
    APPROVE = "approve"
    # Written BEFORE the executor runs. An attempt with no matching
    # execute entry is the crash window: something may have happened in the
    # warehouse and nothing recorded it.
    EXECUTE_ATTEMPT = "execute_attempt"
    EXECUTE = "execute"
    RECONCILE = "reconcile"
    VERIFY = "verify"
    CLOSE = "close"
    REFUSE = "refuse"


# ---- cause codes -----------------------------------------------------
CAUSE_CHAIN_BROKEN = "CHAIN_LINK_DOES_NOT_MATCH_PREDECESSOR"
CAUSE_ENTRY_ALTERED = "ENTRY_HASH_DOES_NOT_MATCH_ITS_BODY"
CAUSE_SEQ_GAP = "SEQUENCE_NUMBER_OUT_OF_ORDER"
CAUSE_TRUNCATED = "TRAILING_ENTRY_INCOMPLETE"
CAUSE_NO_PLAN = "FORECAST_REFERENCES_NO_RECORDED_PLAN"
CAUSE_PLAN_MISMATCH = "FORECAST_IS_FOR_A_DIFFERENT_PLAN"
CAUSE_NO_FORECAST = "EXECUTION_REFERENCES_NO_RECORDED_FORECAST"
CAUSE_UNAPPROVED = "EXECUTION_WITHOUT_AN_APPROVAL"
CAUSE_APPROVAL_STALE = "APPROVAL_IS_FOR_A_DIFFERENT_FORECAST"
CAUSE_SELF_APPROVAL = "REQUESTER_APPROVED_THEIR_OWN_CHANGE"
CAUSE_OVER_AUTHORITY = "PRINCIPAL_APPROVED_ABOVE_THEIR_TIER"
CAUSE_NO_RECEIPT = "VERIFICATION_REFERENCES_NO_RECORDED_EXECUTION"
CAUSE_CLOSE_UNVERIFIED = "CLOSED_WITHOUT_A_PASSING_VERIFICATION"
CAUSE_NO_ATTESTATION_REF = "VERIFICATION_CITES_NO_ATTESTATION_LOG_ENTRY"
CAUSE_NO_ATTEMPT = "EXECUTION_WITH_NO_PRECEDING_ATTEMPT"
CAUSE_DOUBLE_EXECUTION = "MORE_THAN_ONE_EXECUTION_FOR_ONE_ATTEMPT"
CAUSE_PRINCIPAL_MISSING = "ENTRY_REQUIRES_A_PRINCIPAL"


class JournalError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """Whoever caused an entry. `max_tier` is the highest RiskTier value
    this principal may approve — an integer rather than the enum so the
    journal does not import the forecast module and the two can version
    independently."""
    principal_id: str
    role: str = ""
    max_approval_tier: int = 0     # 0 = may not approve anything

    def __post_init__(self):
        if not self.principal_id:
            raise JournalError(CAUSE_PRINCIPAL_MISSING,
                               "a principal needs an id")

    def to_dict(self):
        return {"principal_id": self.principal_id, "role": self.role,
                "max_approval_tier": self.max_approval_tier}


# ---------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------

# Fields covered by the entry hash. Anything outside this set is not
# protected, so the set is explicit rather than "everything in the dict".
_HASHED = ("seq", "request_id", "phase", "subject_hash", "refs",
           "principal", "payload", "previous", "timestamp")


@dataclass
class Entry:
    seq: int
    request_id: str
    phase: Phase
    subject_hash: str                       # the hash this entry is ABOUT
    refs: Dict[str, str] = field(default_factory=dict)   # what it points back to
    principal: Optional[dict] = None
    payload: dict = field(default_factory=dict)
    previous: str = GENESIS
    timestamp: str = ""
    entry_hash: str = ""

    def body(self) -> dict:
        return {"seq": self.seq, "request_id": self.request_id,
                "phase": self.phase.value, "subject_hash": self.subject_hash,
                "refs": dict(sorted(self.refs.items())),
                "principal": self.principal, "payload": self.payload,
                "previous": self.previous, "timestamp": self.timestamp}

    def compute_hash(self) -> str:
        return hashlib.sha256(_canonical(self.body()).encode()).hexdigest()

    def to_line(self) -> str:
        d = self.body()
        d["entry_hash"] = self.entry_hash
        return _canonical(d)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(seq=d["seq"], request_id=d["request_id"],
                   phase=Phase(d["phase"]), subject_hash=d["subject_hash"],
                   refs=dict(d.get("refs") or {}),
                   principal=d.get("principal"),
                   payload=d.get("payload") or {},
                   previous=d["previous"], timestamp=d["timestamp"],
                   entry_hash=d.get("entry_hash", ""))


@dataclass(frozen=True)
class Checkpoint:
    """Export this. A chain the operator holds proves nothing about the
    operator; a head hash somebody else recorded at a known time does."""
    head: str
    entries: int
    at: str
    version: str = JOURNAL_VERSION

    def to_dict(self):
        return {"head": self.head, "entries": self.entries, "at": self.at,
                "version": self.version,
                "note": "tamper-evidence requires this value to be held by a "
                        "party other than the operator of the journal"}


# ---------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------

class Journal:
    """Append-only, one JSON object per line, fsynced.

    Reopening the same path rebuilds the full state — that is what makes a
    request survive a restart rather than a request object surviving a
    function call.
    """

    def __init__(self, path: Optional[str] = None,
                 clock=lambda: time.time()):
        self.path = Path(path) if path else None
        self._clock = clock
        self.entries: List[Entry] = []
        self.load_errors: List[dict] = []
        if self.path and self.path.exists():
            self._load()

    # ---- durability --------------------------------------------------
    def _load(self) -> None:
        raw = self.path.read_text().splitlines()
        for i, line in enumerate(raw):
            if not line.strip():
                continue
            try:
                self.entries.append(Entry.from_dict(json.loads(line)))
            except Exception as exc:
                # A crash between write and flush leaves a partial final
                # line. That is recoverable and must be reported, not
                # swallowed — a journal that silently drops its last entry
                # is worse than one that refuses to open.
                self.load_errors.append({
                    "cause": CAUSE_TRUNCATED, "line": i,
                    "detail": f"unparseable ({exc}); "
                              f"{'trailing' if i == len(raw) - 1 else 'mid-file'}"})

    def _persist(self, entry: Entry) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(entry.to_line() + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # ---- appending ---------------------------------------------------
    def append(self, request_id: str, phase: Phase, subject_hash: str,
               refs: Dict[str, str] = None, principal: Principal = None,
               payload: dict = None) -> Entry:
        if phase is Phase.APPROVE and principal is None:
            raise JournalError(CAUSE_PRINCIPAL_MISSING,
                               "an approval without a principal is not an "
                               "approval")
        e = Entry(seq=len(self.entries), request_id=request_id, phase=phase,
                  subject_hash=subject_hash, refs=dict(refs or {}),
                  principal=principal.to_dict() if principal else None,
                  payload=dict(payload or {}),
                  previous=self.head(), timestamp=f"{self._clock():.6f}")
        e.entry_hash = e.compute_hash()
        self.entries.append(e)
        self._persist(e)
        return e

    def head(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(head=self.head(), entries=len(self.entries),
                          at=f"{self._clock():.6f}")

    # ---- integrity ---------------------------------------------------
    def verify_chain(self) -> List[dict]:
        """Is the file internally consistent with itself. Returns the
        problems found; empty means consistent. It does NOT mean the
        history is true — see the module docstring."""
        problems: List[dict] = list(self.load_errors)
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.seq != i:
                problems.append({"cause": CAUSE_SEQ_GAP, "seq": e.seq,
                                 "detail": f"entry at position {i} claims "
                                           f"seq {e.seq}"})
            if e.previous != prev:
                problems.append({"cause": CAUSE_CHAIN_BROKEN, "seq": e.seq,
                                 "detail": "predecessor link does not match "
                                           "the entry before it"})
            if e.compute_hash() != e.entry_hash:
                problems.append({"cause": CAUSE_ENTRY_ALTERED, "seq": e.seq,
                                 "detail": "the body no longer hashes to the "
                                           "recorded entry hash"})
            prev = e.entry_hash
        return problems

    # ---- binding -----------------------------------------------------
    def verify_bindings(self, request_id: str = None) -> List[dict]:
        """A separate question from verify_chain: does the story hold up.

        An untampered chain can still record an execution authorised by a
        forecast for a different plan, or approved by the person who asked
        for it. Those are not edits, they are the sequence being wrong on
        purpose, and no amount of hashing detects them.
        """
        problems: List[dict] = []
        for rid, entries in sorted(self._by_request(request_id).items()):
            plans = {e.subject_hash for e in entries if e.phase is Phase.PLAN}
            forecasts = {e.subject_hash: e for e in entries
                         if e.phase is Phase.SIMULATE}
            approvals = [e for e in entries if e.phase is Phase.APPROVE]
            # A reconciled execution produces a receipt too. Collecting
            # only EXECUTE made every verification after a crash-window
            # recovery look like it cited nothing.
            receipts = {e.subject_hash for e in entries
                        if e.phase in (Phase.EXECUTE, Phase.RECONCILE)}
            requesters = {e.principal["principal_id"] for e in entries
                          if e.phase in (Phase.PLAN, Phase.OBSERVE)
                          and e.principal}

            for e in forecasts.values():
                ref = e.refs.get("plan_hash")
                if not ref:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_NO_PLAN,
                                     "detail": "forecast records no plan_hash"})
                elif ref not in plans:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_PLAN_MISMATCH,
                                     "detail": f"forecast cites plan {ref}, "
                                               f"which this request never "
                                               f"recorded"})

            for a in approvals:
                fref = a.refs.get("forecast_hash")
                if fref not in forecasts:
                    problems.append({"request_id": rid, "seq": a.seq,
                                     "cause": CAUSE_APPROVAL_STALE,
                                     "detail": f"approval cites forecast "
                                               f"{fref or 'none'}, not "
                                               f"recorded for this request"})
                    continue
                pid = (a.principal or {}).get("principal_id")
                if pid in requesters:
                    problems.append({"request_id": rid, "seq": a.seq,
                                     "cause": CAUSE_SELF_APPROVAL,
                                     "detail": f"{pid} submitted this change "
                                               f"and also approved it"})
                tier = int(forecasts[fref].payload.get("tier", 0))
                authority = int((a.principal or {}).get("max_approval_tier", 0))
                if tier > authority:
                    problems.append({"request_id": rid, "seq": a.seq,
                                     "cause": CAUSE_OVER_AUTHORITY,
                                     "detail": f"{pid} may approve to tier "
                                               f"{authority}; this forecast is "
                                               f"tier {tier}"})

            # Every execution must be preceded by an attempt carrying the
            # same idempotency key, and one attempt may produce exactly one
            # execution. Two executions against one attempt means the plan
            # was applied twice.
            attempts = [x for x in entries if x.phase is Phase.EXECUTE_ATTEMPT]
            attempt_keys = {x.refs.get("attempt_id") for x in attempts}
            seen_keys = {}
            for e in (x for x in entries if x.phase is Phase.EXECUTE):
                key = e.refs.get("attempt_id")
                if key not in attempt_keys:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_NO_ATTEMPT,
                                     "detail": "an execution was recorded "
                                               "with no preceding attempt"})
                elif key in seen_keys:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_DOUBLE_EXECUTION,
                                     "detail": f"attempt {key} already "
                                               f"produced an execution at "
                                               f"seq {seen_keys[key]}"})
                else:
                    seen_keys[key] = e.seq

            approved_forecasts = {a.refs.get("forecast_hash") for a in approvals}
            for e in (x for x in entries if x.phase is Phase.EXECUTE):
                fref = e.refs.get("forecast_hash")
                if fref not in forecasts:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_NO_FORECAST,
                                     "detail": "execution cites no recorded "
                                               "forecast"})
                    continue
                autonomous = (forecasts[fref].payload.get("decision")
                              == "AUTONOMOUS")
                if not autonomous and fref not in approved_forecasts:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_UNAPPROVED,
                                     "detail": "the forecast required approval "
                                               "and none was recorded for it"})

            for e in (x for x in entries if x.phase is Phase.VERIFY):
                if (e.payload.get("attested") is True
                        and not e.refs.get("attestation_log_hash")):
                    problems.append({
                        "request_id": rid, "seq": e.seq,
                        "cause": CAUSE_NO_ATTESTATION_REF,
                        "detail": "an attested verification must point at "
                                  "the AttestationLog entry that holds the "
                                  "attestation"})
                if e.refs.get("receipt_hash") not in receipts:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_NO_RECEIPT,
                                     "detail": "verification cites no recorded "
                                               "execution"})

            passing = {e.refs.get("receipt_hash") for e in entries
                       if e.phase is Phase.VERIFY
                       and e.payload.get("passed") is True}
            for e in (x for x in entries if x.phase is Phase.CLOSE):
                if e.refs.get("receipt_hash") not in passing:
                    problems.append({"request_id": rid, "seq": e.seq,
                                     "cause": CAUSE_CLOSE_UNVERIFIED,
                                     "detail": "closed against an execution "
                                               "with no passing verification"})
        return problems

    # ---- replay ------------------------------------------------------
    def _by_request(self, request_id: str = None) -> Dict[str, List[Entry]]:
        out: Dict[str, List[Entry]] = {}
        for e in self.entries:
            if request_id and e.request_id != request_id:
                continue
            out.setdefault(e.request_id, []).append(e)
        return out

    def replay(self, request_id: str) -> dict:
        """Rebuild a request's state from the record. This is what a
        process restart calls — the state was never in memory, it was
        always in the journal, and memory was a cache."""
        entries = self._by_request(request_id).get(request_id, [])
        if not entries:
            return {"request_id": request_id, "known": False}
        phases = [e.phase.value for e in entries]
        last = entries[-1]
        return {
            "request_id": request_id, "known": True,
            "entries": len(entries),
            "phases": phases,
            "current_phase": last.phase.value,
            "closed": last.phase in (Phase.CLOSE, Phase.REFUSE),
            "hashes": {e.phase.value: e.subject_hash for e in entries},
            "principals": sorted({e.principal["principal_id"]
                                  for e in entries if e.principal}),
            "approvals": [{"by": e.principal["principal_id"],
                           "forecast_hash": e.refs.get("forecast_hash"),
                           "at": e.timestamp}
                          for e in entries if e.phase is Phase.APPROVE],
            "last_seq": last.seq,
        }

    def open_requests(self) -> List[str]:
        return sorted(rid for rid in self._by_request()
                      if not self.replay(rid)["closed"])

    # ---- reporting ---------------------------------------------------
    def explain(self, request_id: str = None) -> str:
        chain = self.verify_chain()
        binds = self.verify_bindings(request_id)
        lines = [f"{len(self.entries)} entries, head {self.head()[:16]}…",
                 f"  chain: {'consistent' if not chain else str(len(chain)) + ' problem(s)'}",
                 f"  bindings: {'coherent' if not binds else str(len(binds)) + ' problem(s)'}"]
        for p in chain + binds:
            lines.append(f"    {p['cause']} — {p['detail']}")
        lines.append("  tamper-evidence holds only against parties who cannot "
                     "rewrite this file; export checkpoint() to a witness")
        return "\n".join(lines)
