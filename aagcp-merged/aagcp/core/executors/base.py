"""
aagcp/core/executors/base.py — the boundary where a plan stops being a
document and starts changing a warehouse.

Everything above this file is deterministic and reversible by virtue of
having done nothing. This is the first place where a failure leaves the
estate in a state nobody chose. So the whole design here is about naming
that state precisely rather than rounding it to success or failure.

Three principles, carried over from the erasure verifier:

  1. A statement that could not be confirmed is not a statement that
     succeeded. ChannelStatus.UNAVAILABLE has an exact analogue here:
     StatementStatus.UNKNOWN, for when the transport dropped and we
     genuinely do not know whether the DDL landed. It never rolls up
     into COMPLETE and never rolls up into FAILED.

  2. Rollback is not the safe default. Reverting a masking policy
     re-exposes data that was just ruled non-compliant. Leaving 388 of
     400 columns governed is the better failure than un-governing them
     to reach a tidy all-or-nothing. So the default on failure is HALT:
     keep what is applied, mark it PARTIAL, and make rollback an
     explicit second decision by a human.

  3. Reversibility is one fact, not two. Operation.reversible is set by
     the compiler from the treatment. The executor reads it and refuses;
     it does not carry its own opinion about what can be undone.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Protocol, Sequence, Tuple

from ..plan import Operation, Plan

EXECUTOR_CONTRACT_VERSION = "exec-1.0.0"


# ---------------------------------------------------------------------
# Failure modes. The distinction between these two exceptions is the
# single most important thing in this file: one of them means the
# statement definitely did not apply, the other means we do not know.
# ---------------------------------------------------------------------

class ExecutorError(Exception):
    """Base."""


class StatementError(ExecutorError):
    """The engine received the statement and rejected it. Definitively
    not applied. Safe to record as FAILED and to continue or halt."""


class TransportError(ExecutorError):
    """The connection dropped, timed out, or the driver lost the result.
    The statement may or may not have applied. This is the case that
    must never be collapsed into either bucket."""


class CapabilityError(ExecutorError):
    """The plan asks for something this executor cannot do. Raised during
    preflight, before anything is executed."""


# ---------------------------------------------------------------------
# Outcome vocabulary
# ---------------------------------------------------------------------

class StatementStatus(str, Enum):
    APPLIED = "applied"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"
    UNKNOWN = "unknown"            # dispatched, outcome unobserved


class OperationStatus(str, Enum):
    APPLIED = "applied"
    PARTIALLY_APPLIED = "partially_applied"   # some statements landed
    FAILED = "failed"                         # nothing landed
    NOT_ATTEMPTED = "not_attempted"
    UNKNOWN = "unknown"
    ROLLED_BACK = "rolled_back"


class ExecutionVerdict(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    HALTED_AT_CANARY = "HALTED_AT_CANARY"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFUSED = "REFUSED"
    ROLLED_BACK = "ROLLED_BACK"


class FailurePolicy(str, Enum):
    HALT = "halt"            # default: stop, keep what applied, no revert
    CONTINUE = "continue"    # attempt every remaining operation anyway
    ROLLBACK = "rollback"    # revert applied ops; refused for irreversible


# Cause codes. Every refusal and every non-clean statement carries one.
CAUSE_IRREVERSIBLE = "IRREVERSIBLE_OPERATION"
CAUSE_UNKNOWN_STATE = "UNKNOWN_STATE_NOT_ROLLBACK_SAFE"
CAUSE_PRESTATE_MISSING = "PRESTATE_NOT_CAPTURED"
CAUSE_UNSUPPORTED_OP = "OPERATION_NOT_SUPPORTED_BY_EXECUTOR"
CAUSE_DIALECT_MISMATCH = "PLAN_DIALECT_DOES_NOT_MATCH_EXECUTOR"
CAUSE_CANARY_FAILED = "CANARY_VERIFICATION_FAILED"
CAUSE_CANARY_UNVERIFIED = "CANARY_VERIFICATION_UNAVAILABLE"
CAUSE_TRANSPORT = "TRANSPORT_LOST_MID_STATEMENT"
CAUSE_ENGINE_REJECTED = "ENGINE_REJECTED_STATEMENT"
CAUSE_NOT_VERIFIED = "APPLIED_BUT_NOT_VERIFIED"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------

@dataclass
class StatementRecord:
    index: int
    sha8: str                       # binds the record to exact text in the Plan
    status: StatementStatus
    cause: str = ""
    detail: str = ""

    def to_dict(self):
        return {"index": self.index, "sha8": self.sha8,
                "status": self.status.value, "cause": self.cause,
                "detail": self.detail}


@dataclass
class OperationRecord:
    target: str
    op: str
    treatment: str
    citation: str
    reversible: bool
    stage: str                      # "canary" | "remainder"
    status: OperationStatus
    statements: List[StatementRecord] = field(default_factory=list)
    verified: Optional[bool] = None   # True / False / None = could not check
    verify_detail: str = ""
    residual_artifacts: List[str] = field(default_factory=list)

    @property
    def effective_ok(self) -> bool:
        """Applied AND confirmed. An unverified apply is not a success."""
        return self.status is OperationStatus.APPLIED and self.verified is True

    def to_dict(self):
        return {"target": self.target, "op": self.op,
                "treatment": self.treatment, "citation": self.citation,
                "reversible": self.reversible, "stage": self.stage,
                "status": self.status.value,
                "verified": self.verified, "verify_detail": self.verify_detail,
                "residual_artifacts": list(self.residual_artifacts),
                "statements": [s.to_dict() for s in self.statements]}


@dataclass
class StagePolicy:
    """How the canary is cut. Recorded in the receipt so the split is
    re-derivable — a receipt that cannot be reproduced is a story."""
    canary_fraction: float = 0.1
    canary_min: int = 1
    canary_max: int = 25
    on_failure: FailurePolicy = FailurePolicy.HALT
    selection_rule: str = "lowest-row-estimate-first/v1"

    def to_dict(self):
        return {"canary_fraction": self.canary_fraction,
                "canary_min": self.canary_min, "canary_max": self.canary_max,
                "on_failure": self.on_failure.value,
                "selection_rule": self.selection_rule}


@dataclass
class Preview:
    """Read-only. Issues no DDL. Captures whatever pre-state the executor
    will need in order to honestly reverse itself later."""
    plan_hash: str
    dialect: str
    operations: int
    statements: int
    canary_targets: List[str]
    irreversible_targets: List[str]
    capability_errors: List[dict] = field(default_factory=list)
    warnings: List[dict] = field(default_factory=list)
    prestate: Dict[str, dict] = field(default_factory=dict)
    stage_policy: dict = field(default_factory=dict)

    @property
    def executable(self) -> bool:
        return not self.capability_errors

    def to_dict(self):
        return {"plan_hash": self.plan_hash, "dialect": self.dialect,
                "operations": self.operations, "statements": self.statements,
                "canary_targets": list(self.canary_targets),
                "irreversible_targets": list(self.irreversible_targets),
                "capability_errors": list(self.capability_errors),
                "warnings": list(self.warnings),
                "prestate_captured": sorted(self.prestate.keys()),
                "stage_policy": self.stage_policy,
                "executable": self.executable}


@dataclass
class ExecutionReceipt:
    plan_hash: str
    dialect: str
    verdict: ExecutionVerdict
    operations: List[OperationRecord] = field(default_factory=list)
    stage_policy: dict = field(default_factory=dict)
    prestate: Dict[str, dict] = field(default_factory=dict)
    refusal: Optional[dict] = None
    started_at: float = 0.0
    finished_at: float = 0.0
    contract: str = EXECUTOR_CONTRACT_VERSION
    # True when this receipt was reconstructed by observing the engine
    # rather than by running the plan — see BaseExecutor.reconcile.
    reconciled: bool = False

    # ---- durability ----------------------------------------------
    def to_dict(self) -> dict:
        """A receipt that only exists as a Python object cannot survive the
        crash it is most needed after. This round-trips."""
        return {"plan_hash": self.plan_hash, "dialect": self.dialect,
                "verdict": self.verdict.value,
                "operations": [o.to_dict() for o in self.operations],
                "stage_policy": self.stage_policy,
                "prestate": self.prestate, "refusal": self.refusal,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "contract": self.contract, "reconciled": self.reconciled,
                "receipt_hash": self.receipt_hash}

    @classmethod
    def from_dict(cls, d: dict) -> "ExecutionReceipt":
        ops = []
        for o in d.get("operations", []):
            rec = OperationRecord(
                target=o["target"], op=o["op"], treatment=o["treatment"],
                citation=o["citation"], reversible=o["reversible"],
                stage=o["stage"], status=OperationStatus(o["status"]),
                verified=o.get("verified"),
                verify_detail=o.get("verify_detail", ""),
                residual_artifacts=list(o.get("residual_artifacts", [])))
            rec.statements = [
                StatementRecord(s["index"], s["sha8"],
                                StatementStatus(s["status"]),
                                s.get("cause", ""), s.get("detail", ""))
                for s in o.get("statements", [])]
            ops.append(rec)
        r = cls(plan_hash=d["plan_hash"], dialect=d["dialect"],
                verdict=ExecutionVerdict(d["verdict"]), operations=ops,
                stage_policy=d.get("stage_policy", {}),
                prestate=d.get("prestate", {}), refusal=d.get("refusal"),
                started_at=d.get("started_at", 0.0),
                finished_at=d.get("finished_at", 0.0),
                contract=d.get("contract", EXECUTOR_CONTRACT_VERSION),
                reconciled=d.get("reconciled", False))
        if d.get("receipt_hash") and r.receipt_hash != d["receipt_hash"]:
            raise ExecutorError(
                f"receipt does not rehydrate to its recorded hash: "
                f"{r.receipt_hash} != {d['receipt_hash']}")
        return r

    # ---- rollups -------------------------------------------------
    def by_status(self, status: OperationStatus) -> List[OperationRecord]:
        return [o for o in self.operations if o.status is status]

    def summary(self) -> dict:
        return {
            "receipt_hash": self.receipt_hash,
            "plan_hash": self.plan_hash,
            "verdict": self.verdict.value,
            "applied": len([o for o in self.operations if o.effective_ok]),
            "partially_applied": len(self.by_status(OperationStatus.PARTIALLY_APPLIED)),
            "failed": len(self.by_status(OperationStatus.FAILED)),
            "unknown": len(self.by_status(OperationStatus.UNKNOWN)),
            "not_attempted": len(self.by_status(OperationStatus.NOT_ATTEMPTED)),
            "applied_but_unverified": len(
                [o for o in self.operations
                 if o.status is OperationStatus.APPLIED and o.verified is not True]),
            "residual_artifacts": sum(len(o.residual_artifacts) for o in self.operations),
        }

    @property
    def receipt_hash(self) -> str:
        """Wall-clock time is deliberately outside the hash. Two runs of
        the same plan against the same engine state must produce the same
        receipt hash, or the hash is measuring the clock."""
        body = json.dumps({
            "plan": self.plan_hash, "dialect": self.dialect,
            "verdict": self.verdict.value, "contract": self.contract,
            "stage": self.stage_policy, "reconciled": self.reconciled,
            "ops": [o.to_dict() for o in self.operations],
            "refusal": self.refusal,
        }, sort_keys=True, separators=(",", ":"))
        return "R-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    def explain(self) -> str:
        s = self.summary()
        if self.verdict is ExecutionVerdict.REFUSED:
            return (f"REFUSED before execution. "
                    f"{self.refusal.get('cause') if self.refusal else ''}: "
                    f"{self.refusal.get('detail') if self.refusal else ''}")
        head = f"{self.verdict.value}. {s['applied']} of {len(self.operations)} operations applied and verified"
        tail = []
        if s["partially_applied"]:
            tail.append(f"{s['partially_applied']} left partially applied")
        if s["unknown"]:
            tail.append(f"{s['unknown']} in an unknown state — outcome unobserved, "
                        f"not safe to treat as either done or undone")
        if s["failed"]:
            tail.append(f"{s['failed']} failed outright")
        if s["not_attempted"]:
            tail.append(f"{s['not_attempted']} never attempted")
        if s["applied_but_unverified"]:
            tail.append(f"{s['applied_but_unverified']} applied without confirmation")
        if s["residual_artifacts"]:
            tail.append(f"{s['residual_artifacts']} residual object(s) to clean up")
        return head + ("; " + "; ".join(tail) if tail else ".")


# ---------------------------------------------------------------------
# The cursor contract. We do not import a driver; we describe the two
# methods we use, so a real connection and a mock are interchangeable.
# ---------------------------------------------------------------------

class Cursor(Protocol):
    def execute(self, sql: str) -> None: ...
    def fetchall(self) -> List[tuple]: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...


class Executor(Protocol):
    """The three-method contract. Nothing else is public."""
    name: str

    def preview(self, plan: Plan, stage: StagePolicy = ...) -> Preview: ...
    def execute_staged(self, plan: Plan, stage: StagePolicy = ...) -> ExecutionReceipt: ...
    def rollback(self, receipt: ExecutionReceipt, plan: Plan) -> ExecutionReceipt: ...


# ---------------------------------------------------------------------
# Base implementation. Dialect subclasses supply four hooks and nothing
# more: supported ops, pre-state capture, verification, undo statements.
# ---------------------------------------------------------------------

class BaseExecutor:
    name = "base"
    dialect = "base"
    supported_ops: Tuple[str, ...] = ()
    prestate_required = False   # True when rollback is a lie without it

    def __init__(self, connection, clock: Callable[[], float] = time.time):
        self.conn = connection
        self._clock = clock

    # ---- hooks ----------------------------------------------------
    def _capture_prestate(self, op: Operation) -> Optional[dict]:
        """Read-only. Anything needed to reverse this operation faithfully.
        None means nothing is needed."""
        return None

    def _verify_operation(self, op: Operation) -> Tuple[Optional[bool], str]:
        """(True | False | None, detail). None means the check itself could
        not run — never report that as clean."""
        return None, "no verification implemented for this executor"

    def _undo_statements(self, op: Operation, prestate: Optional[dict]) -> List[str]:
        raise NotImplementedError

    def _residual_artifacts(self, op: Operation, applied_upto: int) -> List[str]:
        return []

    # ---- plumbing -------------------------------------------------
    def _execute(self, sql: str) -> None:
        cur = self.conn.cursor()
        cur.execute(sql)

    def _query(self, sql: str) -> List[tuple]:
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    # ---- canary selection ----------------------------------------
    def select_canary(self, plan: Plan, stage: StagePolicy) -> List[str]:
        """Deterministic and blast-radius-aware: smallest tables first,
        ties broken by target name. Two runs of the same plan pick the
        same canary, which is what makes the receipt reproducible."""
        if stage.canary_fraction <= 0:
            return []
        ordered = sorted(plan.operations, key=lambda o: (o.row_estimate, o.target))
        n = max(stage.canary_min,
                int(len(ordered) * stage.canary_fraction + 0.999999))
        n = min(n, stage.canary_max, len(ordered))
        return [o.target for o in ordered[:n]]

    # ---- preflight ------------------------------------------------
    def _capability_errors(self, plan: Plan) -> List[dict]:
        errs = []
        if plan.dialect != self.dialect:
            errs.append({"cause": CAUSE_DIALECT_MISMATCH,
                         "detail": f"plan compiled for '{plan.dialect}', "
                                   f"executor speaks '{self.dialect}'"})
        for o in plan.operations:
            if o.op not in self.supported_ops:
                errs.append({"cause": CAUSE_UNSUPPORTED_OP, "target": o.target,
                             "detail": f"'{o.op}' is not implemented by {self.name}"})
        return errs

    # ---- preview --------------------------------------------------
    def preview(self, plan: Plan, stage: StagePolicy = None) -> Preview:
        stage = stage or StagePolicy()
        prestate, warnings = {}, []
        errors = self._capability_errors(plan)
        if not errors:
            for o in plan.operations:
                try:
                    ps = self._capture_prestate(o)
                except (StatementError, TransportError) as exc:
                    ps = None
                    # Blocking only where reversal depends on it. Postgres
                    # cannot honestly un-REVOKE without the grant snapshot;
                    # Snowflake only loses the ability to restore a policy
                    # it displaced, which is worth a warning, not a refusal.
                    entry = {"cause": CAUSE_PRESTATE_MISSING,
                             "target": o.target, "detail": str(exc)}
                    (errors if self.prestate_required else warnings).append(entry)
                if ps is not None:
                    prestate[o.target] = ps
        return Preview(
            plan_hash=plan.plan_hash, dialect=plan.dialect,
            operations=len(plan.operations),
            statements=sum(len(o.statements) for o in plan.operations),
            canary_targets=self.select_canary(plan, stage),
            irreversible_targets=[o.target for o in plan.irreversible_ops],
            capability_errors=errors, warnings=warnings, prestate=prestate,
            stage_policy=stage.to_dict(),
        )

    # ---- execution ------------------------------------------------
    def _apply_operation(self, op: Operation, stage_name: str) -> OperationRecord:
        rec = OperationRecord(
            target=op.target, op=op.op, treatment=op.treatment,
            citation=op.citation, reversible=op.reversible,
            stage=stage_name, status=OperationStatus.APPLIED)

        halted = False
        applied_upto = 0
        for i, sql in enumerate(op.statements):
            if halted:
                rec.statements.append(StatementRecord(i, _digest(sql),
                                                      StatementStatus.NOT_ATTEMPTED))
                continue
            try:
                self._execute(sql)
                rec.statements.append(StatementRecord(i, _digest(sql),
                                                      StatementStatus.APPLIED))
                applied_upto = i + 1
            except TransportError as exc:
                # We dispatched it and never learned the outcome. This is
                # the state that poisons every rollup above it.
                rec.statements.append(StatementRecord(
                    i, _digest(sql), StatementStatus.UNKNOWN,
                    CAUSE_TRANSPORT, str(exc)))
                rec.status = OperationStatus.UNKNOWN
                halted = True
            except StatementError as exc:
                rec.statements.append(StatementRecord(
                    i, _digest(sql), StatementStatus.FAILED,
                    CAUSE_ENGINE_REJECTED, str(exc)))
                rec.status = (OperationStatus.FAILED if applied_upto == 0
                              else OperationStatus.PARTIALLY_APPLIED)
                halted = True

        if rec.status in (OperationStatus.PARTIALLY_APPLIED, OperationStatus.UNKNOWN):
            rec.residual_artifacts = self._residual_artifacts(op, applied_upto)

        if rec.status is OperationStatus.APPLIED:
            try:
                ok, detail = self._verify_operation(op)
            except (StatementError, TransportError) as exc:
                ok, detail = None, f"verification call failed: {exc}"
            rec.verified, rec.verify_detail = ok, detail
        return rec

    def reconcile(self, plan: Plan) -> ExecutionReceipt:
        """What does the engine say happened, without running anything.

        This is the answer to a crash between the DDL landing and the
        journal write. The plan is not re-run; each operation is verified
        against the engine's own state and the receipt is rebuilt from
        what is observed. An operation whose verification cannot run is
        UNKNOWN, not NOT_ATTEMPTED — "I could not check" has never been
        allowed to mean "it did not happen" anywhere else in this codebase
        and it is not allowed to here, where the cost of being wrong is
        applying a change twice.

        Issues no DDL. There is a test asserting that.
        """
        started = self._clock()
        records: List[OperationRecord] = []
        for o in plan.operations:
            rec = OperationRecord(
                target=o.target, op=o.op, treatment=o.treatment,
                citation=o.citation, reversible=o.reversible,
                stage="reconcile", status=OperationStatus.NOT_ATTEMPTED)
            try:
                ok, detail = self._verify_operation(o)
            except (StatementError, TransportError) as exc:
                ok, detail = None, f"verification could not run: {exc}"
            rec.verified, rec.verify_detail = ok, detail
            if ok is True:
                rec.status = OperationStatus.APPLIED
            elif ok is None:
                rec.status = OperationStatus.UNKNOWN
            else:
                rec.status = OperationStatus.NOT_ATTEMPTED
            records.append(rec)

        applied = [r for r in records if r.status is OperationStatus.APPLIED]
        unknown = [r for r in records if r.status is OperationStatus.UNKNOWN]
        if unknown:
            verdict = ExecutionVerdict.INCONCLUSIVE
        elif len(applied) == len(records) and records:
            verdict = ExecutionVerdict.COMPLETE
        elif applied:
            verdict = ExecutionVerdict.PARTIAL
        else:
            verdict = ExecutionVerdict.FAILED
        return ExecutionReceipt(
            plan_hash=plan.plan_hash, dialect=plan.dialect, verdict=verdict,
            operations=records, stage_policy={"reconciled": True},
            started_at=started, finished_at=self._clock(), reconciled=True)

    def execute_staged(self, plan: Plan, stage: StagePolicy = None) -> ExecutionReceipt:
        stage = stage or StagePolicy()
        started = self._clock()
        pre = self.preview(plan, stage)

        if not pre.executable:
            return ExecutionReceipt(
                plan_hash=plan.plan_hash, dialect=plan.dialect,
                verdict=ExecutionVerdict.REFUSED,
                operations=[OperationRecord(
                    target=o.target, op=o.op, treatment=o.treatment,
                    citation=o.citation, reversible=o.reversible,
                    stage="none", status=OperationStatus.NOT_ATTEMPTED)
                    for o in plan.operations],
                stage_policy=stage.to_dict(),
                refusal={"cause": pre.capability_errors[0]["cause"],
                         "detail": pre.capability_errors[0]["detail"],
                         "all": pre.capability_errors},
                started_at=started, finished_at=self._clock())

        canary = set(pre.canary_targets)
        ops_by_target = {o.target: o for o in plan.operations}
        records: List[OperationRecord] = []

        # --- stage 1: canary ---------------------------------------
        for target in pre.canary_targets:
            records.append(self._apply_operation(ops_by_target[target], "canary"))

        canary_bad = [r for r in records if not r.effective_ok]
        halted_at_canary = bool(canary_bad)

        # --- stage 2: remainder ------------------------------------
        remainder = [o for o in plan.operations if o.target not in canary]
        if halted_at_canary:
            # The canary exists to stop exactly here. A canary that could
            # not be verified halts on the same footing as one that failed:
            # unmeasured is not clean.
            for o in remainder:
                records.append(OperationRecord(
                    target=o.target, op=o.op, treatment=o.treatment,
                    citation=o.citation, reversible=o.reversible,
                    stage="remainder", status=OperationStatus.NOT_ATTEMPTED,
                    verify_detail=(CAUSE_CANARY_FAILED
                                   if any(r.verified is False for r in canary_bad)
                                   else CAUSE_CANARY_UNVERIFIED)))
        else:
            stop = False
            for o in remainder:
                if stop:
                    records.append(OperationRecord(
                        target=o.target, op=o.op, treatment=o.treatment,
                        citation=o.citation, reversible=o.reversible,
                        stage="remainder", status=OperationStatus.NOT_ATTEMPTED))
                    continue
                r = self._apply_operation(o, "remainder")
                records.append(r)
                if not r.effective_ok and stage.on_failure is FailurePolicy.HALT:
                    stop = True

        receipt = ExecutionReceipt(
            plan_hash=plan.plan_hash, dialect=plan.dialect,
            verdict=self._verdict(records, halted_at_canary),
            operations=records, stage_policy=stage.to_dict(),
            prestate=pre.prestate, started_at=started, finished_at=self._clock())

        if (stage.on_failure is FailurePolicy.ROLLBACK
                and receipt.verdict not in (ExecutionVerdict.COMPLETE,)):
            return self.rollback(receipt, plan)
        return receipt

    # ---- verdict --------------------------------------------------
    @staticmethod
    def _verdict(records: Sequence[OperationRecord],
                 halted_at_canary: bool) -> ExecutionVerdict:
        """The floor over the parts, with UNKNOWN dominating. You cannot
        call a run complete or cleanly failed while any piece of it is
        unobserved."""
        if not records:
            return ExecutionVerdict.COMPLETE
        unknown = any(r.status is OperationStatus.UNKNOWN for r in records)
        unverified = any(r.status is OperationStatus.APPLIED and r.verified is None
                         for r in records)
        if unknown or unverified:
            return ExecutionVerdict.INCONCLUSIVE
        if all(r.effective_ok for r in records):
            return ExecutionVerdict.COMPLETE
        anything_landed = any(
            r.status in (OperationStatus.APPLIED, OperationStatus.PARTIALLY_APPLIED)
            for r in records)
        if halted_at_canary and not anything_landed:
            return ExecutionVerdict.HALTED_AT_CANARY
        if not anything_landed:
            return ExecutionVerdict.FAILED
        if halted_at_canary:
            return ExecutionVerdict.HALTED_AT_CANARY
        return ExecutionVerdict.PARTIAL

    # ---- reversibility, as the executor sees it -------------------
    def can_reverse(self, op: Operation) -> Tuple[Optional[bool], str]:
        """Asked by Phase 4, before anything runs. Pure — it builds undo
        statements and throws them away, no I/O.

        Three answers, because two would be a lie. Operation.reversible is
        the compiler's view, derived from the treatment alone. The executor
        may know better: a Postgres REVOKE is reversible in principle and
        not reversible in practice unless the grant snapshot was captured
        first. That case answers None, and None must never be spent as a
        yes.
        """
        if not op.reversible:
            return False, (f"treatment '{op.treatment}' is irreversible "
                           f"({op.citation})")
        try:
            stmts = self._undo_statements(op, None)
        except CapabilityError as exc:
            return None, f"conditional on pre-state: {exc}"
        except NotImplementedError:
            return None, f"{self.name} implements no undo for '{op.op}'"
        if not stmts:
            return None, "undo produced no statements"
        return True, f"reversible in {len(stmts)} statement(s)"

    # ---- rollback -------------------------------------------------
    def rollback(self, receipt: ExecutionReceipt, plan: Plan) -> ExecutionReceipt:
        """Explicit, never automatic on the HALT path. Refuses on anything
        it cannot honestly reverse: irreversible treatments, and operations
        whose state is unknown — undoing a statement that may never have
        applied is its own kind of damage."""
        ops_by_target = {o.target: o for o in plan.operations}
        out: List[OperationRecord] = []
        refusals: List[dict] = []

        for rec in receipt.operations:
            op = ops_by_target.get(rec.target)
            if rec.status in (OperationStatus.NOT_ATTEMPTED, OperationStatus.FAILED):
                out.append(rec)
                continue
            if not rec.reversible:
                refusals.append({"cause": CAUSE_IRREVERSIBLE, "target": rec.target,
                                 "detail": f"{rec.treatment} under {rec.citation} "
                                           f"cannot be reversed; the column is gone"})
                out.append(rec)
                continue
            if rec.status is OperationStatus.UNKNOWN:
                refusals.append({"cause": CAUSE_UNKNOWN_STATE, "target": rec.target,
                                 "detail": "outcome unobserved; reversing a "
                                           "statement that may not have applied "
                                           "needs a human"})
                out.append(rec)
                continue

            prestate = receipt.prestate.get(rec.target)
            try:
                stmts = self._undo_statements(op, prestate)
            except CapabilityError as exc:
                refusals.append({"cause": CAUSE_PRESTATE_MISSING,
                                 "target": rec.target, "detail": str(exc)})
                out.append(rec)
                continue

            undone = OperationRecord(
                target=rec.target, op=rec.op, treatment=rec.treatment,
                citation=rec.citation, reversible=rec.reversible,
                stage=rec.stage, status=OperationStatus.ROLLED_BACK,
                verified=None, verify_detail="reverted")
            for i, sql in enumerate(stmts):
                try:
                    self._execute(sql)
                    undone.statements.append(
                        StatementRecord(i, _digest(sql), StatementStatus.APPLIED))
                except TransportError as exc:
                    undone.statements.append(StatementRecord(
                        i, _digest(sql), StatementStatus.UNKNOWN,
                        CAUSE_TRANSPORT, str(exc)))
                    undone.status = OperationStatus.UNKNOWN
                except StatementError as exc:
                    undone.statements.append(StatementRecord(
                        i, _digest(sql), StatementStatus.FAILED,
                        CAUSE_ENGINE_REJECTED, str(exc)))
                    undone.status = OperationStatus.PARTIALLY_APPLIED
            out.append(undone)

        rolled = [r for r in out if r.status is OperationStatus.ROLLED_BACK]
        verdict = (ExecutionVerdict.ROLLED_BACK
                   if rolled and not any(r.status is OperationStatus.UNKNOWN for r in out)
                   else ExecutionVerdict.INCONCLUSIVE if any(
                       r.status is OperationStatus.UNKNOWN for r in out)
                   else receipt.verdict)

        return ExecutionReceipt(
            plan_hash=receipt.plan_hash, dialect=receipt.dialect,
            verdict=verdict, operations=out,
            stage_policy=receipt.stage_policy, prestate=receipt.prestate,
            refusal={"cause": "ROLLBACK_PARTIALLY_REFUSED",
                     "detail": f"{len(refusals)} operation(s) could not be reversed",
                     "all": refusals} if refusals else None,
            started_at=receipt.started_at, finished_at=self._clock())
