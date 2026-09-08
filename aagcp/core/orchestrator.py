"""
aagcp/core/orchestrator.py — the loop, driven from the journal.

Every module in core/ is a pure function over its inputs. This is the only
thing that calls them in order, and it holds no state of its own worth
speaking of: the phase a request is in, what it is allowed to do next, and
whether it was approved are all read back out of the journal. That is what
makes the loop resumable rather than merely restartable — a process that
dies between SIMULATE and EXECUTE comes back knowing it is waiting for an
approval, because the waiting was written down.

THE GATE IS ENFORCED HERE, NOT ONLY AUDITED.
journal.verify_bindings() catches an execution that had no approval after
the fact, which is the right tool for an auditor and the wrong one for a
control plane. execute() refuses at the point of action: it reads the
recorded forecast, and unless that forecast said AUTONOMOUS it looks for
an approval entry naming that exact forecast hash. An after-the-fact check
tells you the data is already gone.

ARTIFACTS DO NOT SURVIVE A RESTART, AND THAT IS DELIBERATE.
The journal records hashes, not Plans. After a restart you cannot ask the
orchestrator to execute request R and have it reconstruct the plan from
memory it does not have — you hand the Plan back, and it checks that the
plan_hash matches the one recorded. So the thing executed is provably the
thing that was simulated and approved, rather than a plan recompiled since
against findings that moved. A control plane that rebuilt the plan for you
would be the more convenient design and would quietly execute something
nobody approved.

LEARN DOES NOT TUNE ANYTHING.
Phase 6 compares what the forecast predicted against what the execution
and verification actually produced, and writes the difference down. It
does not adjust the rubric, the thresholds or the budget. A system that
retunes its own gates in response to its own outcomes will converge on
whatever makes its numbers look good, and the first thing to go is the
approval requirement. Calibration drift is a report for a human.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .coverage import CoverageReport, assess
from .erasure import ErasureRequest
from .journal import (Journal, JournalError, Phase, Principal,
                      CAUSE_OVER_AUTHORITY, CAUSE_SELF_APPROVAL)
from .plan import Finding, Plan, compile_plan
from .simulate import Decision, Forecast, RiskTier, simulate
from .subject_resolution import Resolution

ORCHESTRATOR_VERSION = "orchestrator-1.0.0"


# Legal predecessors. A phase may run when at least one of its
# prerequisites is already recorded for the request.
PREREQUISITES: Dict[Phase, Tuple[Phase, ...]] = {
    Phase.OBSERVE: (),
    Phase.ANALYZE: (Phase.OBSERVE,),
    Phase.RESOLVE: (),
    Phase.PLAN: (Phase.ANALYZE, Phase.RESOLVE),
    Phase.SIMULATE: (Phase.PLAN,),
    Phase.APPROVE: (Phase.SIMULATE,),
    Phase.EXECUTE_ATTEMPT: (Phase.SIMULATE,),
    Phase.EXECUTE: (Phase.EXECUTE_ATTEMPT,),
    Phase.RECONCILE: (Phase.EXECUTE_ATTEMPT,),
    # A reconciled execution is an execution for the purposes of what
    # may follow it. Leaving RECONCILE out meant a run recovered from
    # the crash window could never be verified or closed.
    Phase.VERIFY: (Phase.EXECUTE, Phase.RECONCILE),
    Phase.CLOSE: (Phase.VERIFY,),
    Phase.REFUSE: (),
    # LEARN is recorded as a CLOSE-phase payload rather than its own phase,
    # so the journal's binding rules stay a closed set.
}

CAUSE_OUT_OF_ORDER = "PHASE_PREREQUISITE_NOT_RECORDED"
CAUSE_ARTIFACT_MISMATCH = "ARTIFACT_DOES_NOT_MATCH_THE_RECORDED_HASH"
CAUSE_NOT_APPROVED = "NO_APPROVAL_RECORDED_FOR_THIS_FORECAST"
CAUSE_ALREADY_CLOSED = "REQUEST_IS_ALREADY_CLOSED"
CAUSE_UNRESOLVED = "SUBJECT_NOT_RESOLVED"
CAUSE_NO_FORECAST = "NO_FORECAST_RECORDED"
CAUSE_ALREADY_EXECUTED = "THIS_PLAN_HAS_ALREADY_BEEN_EXECUTED"
CAUSE_UNRECONCILED = "AN_EARLIER_ATTEMPT_WAS_NEVER_RESOLVED"
CAUSE_NOTHING_TO_RECONCILE = "NO_UNRESOLVED_ATTEMPT"


class OrchestratorError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _digest(obj) -> str:
    return "D-" + hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:12].upper()


@dataclass
class Lesson:
    """What the forecast said, against what happened. Written, not applied."""
    request_id: str
    predictions: List[dict] = field(default_factory=list)

    def add(self, name: str, predicted, observed, matched: Optional[bool],
            note: str = ""):
        self.predictions.append({"signal": name, "predicted": predicted,
                                 "observed": observed, "matched": matched,
                                 "note": note})

    @property
    def hits(self) -> int:
        return sum(1 for p in self.predictions if p["matched"] is True)

    @property
    def misses(self) -> List[dict]:
        return [p for p in self.predictions if p["matched"] is False]

    @property
    def unscored(self) -> List[dict]:
        return [p for p in self.predictions if p["matched"] is None]

    def to_dict(self):
        return {"request_id": self.request_id,
                "predictions": list(self.predictions),
                "hits": self.hits, "misses": len(self.misses),
                "unscored": len(self.unscored)}

    def explain(self) -> str:
        lines = [f"calibration: {self.hits} of "
                 f"{len(self.predictions) - len(self.unscored)} scored "
                 f"predictions held"]
        for m in self.misses:
            lines.append(f"  MISS {m['signal']}: predicted {m['predicted']}, "
                         f"observed {m['observed']}"
                         + (f" — {m['note']}" if m["note"] else ""))
        for u in self.unscored:
            lines.append(f"  unscored {u['signal']}: {u['note']}")
        if self.misses:
            lines.append("  the rubric is NOT adjusted from this; a system "
                         "that retunes its own gates on its own outcomes "
                         "converges on whatever flatters it")
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, journal: Journal):
        self.journal = journal

    # ---- journal reads ------------------------------------------------
    def _entries(self, request_id: str):
        return [e for e in self.journal.entries if e.request_id == request_id]

    def _last(self, request_id: str, phase: Phase):
        found = [e for e in self._entries(request_id) if e.phase is phase]
        return found[-1] if found else None

    def _phases(self, request_id: str) -> set:
        return {e.phase for e in self._entries(request_id)}

    def _require(self, request_id: str, phase: Phase) -> None:
        recorded = self._phases(request_id)
        if Phase.CLOSE in recorded or Phase.REFUSE in recorded:
            raise OrchestratorError(
                CAUSE_ALREADY_CLOSED,
                f"{request_id} is closed; a closed request does not reopen "
                f"by being asked to")
        need = PREREQUISITES[phase]
        if need and not (set(need) & recorded):
            raise OrchestratorError(
                CAUSE_OUT_OF_ORDER,
                f"{phase.value} needs one of "
                f"{[p.value for p in need]}; this request has "
                f"{sorted(p.value for p in recorded) or 'nothing'}")

    def resume(self, request_id: str) -> dict:
        """What a restarted process asks first. The next legal phases come
        from the record, not from anything held in memory."""
        state = self.journal.replay(request_id)
        if not state["known"]:
            return state
        recorded = self._phases(request_id)
        state["next_phases"] = sorted(
            p.value for p, need in PREREQUISITES.items()
            if p not in (Phase.OBSERVE, Phase.RESOLVE)
            and (not need or set(need) & recorded))
        state["artifacts_required"] = [
            e.phase.value for e in self._entries(request_id)
            if e.phase in (Phase.PLAN, Phase.SIMULATE)]
        unresolved, done = self._attempts(request_id)
        state["needs_reconciliation"] = unresolved is not None
        state["unresolved_attempt"] = (unresolved.refs.get("attempt_id")
                                       if unresolved else None)
        state["executed"] = bool(done)
        state["receipt_available"] = self.receipt_for(request_id) is not None
        if unresolved is not None:
            # The honest description of the crash window.
            state["next_phases"] = ["reconcile"]
            state["warning"] = (
                "an execution was attempted and never resolved; the engine "
                "may have been changed. reconcile() before anything else")
        return state

    # ---- phases -------------------------------------------------------
    def observe(self, request_id: str, inventory, inspections=(), exclusions=(),
                policy=None, findings=(), thresholds=None,
                principal: Principal = None) -> CoverageReport:
        self._require(request_id, Phase.OBSERVE)
        kw = {"thresholds": thresholds} if thresholds is not None else {}
        report = assess(inventory, inspections, exclusions, policy=policy,
                        findings=findings, **kw)
        self.journal.append(
            request_id, Phase.OBSERVE, report.report_hash, principal=principal,
            payload={"counts": report.counts,
                     "denominator_verified": report.denominator_verified,
                     "anomalies": len(report.anomalies)})
        return report

    def analyze(self, request_id: str, findings: Sequence[Finding],
                principal: Principal = None) -> str:
        """Findings are produced outside core/ — by Presidio, by column
        hints, by a customer's own detector. What is recorded is a digest
        of exactly which findings entered the plan, so a plan can never be
        re-attributed to a different scan afterwards."""
        self._require(request_id, Phase.ANALYZE)
        digest = _digest(sorted(
            [f"{f.fqn}.{f.column}|{f.identifier_key}|{f.detector}|"
             f"{f.confidence}|{f.row_estimate}" for f in findings]))
        self.journal.append(request_id, Phase.ANALYZE, digest,
                            principal=principal,
                            payload={"findings": len(findings)})
        return digest

    def resolve(self, request_id: str, resolution: Resolution,
                principal: Principal = None) -> Resolution:
        """Erase path only. A non-RESOLVED verdict is recorded and then
        refuses to advance — the refusal is part of the history, not a
        dropped call."""
        self._require(request_id, Phase.RESOLVE)
        self.journal.append(
            request_id, Phase.RESOLVE, resolution.resolution_hash,
            principal=principal,
            payload={"verdict": resolution.verdict.value,
                     "cause": resolution.cause,
                     "candidate_count": len(resolution.candidates)})
        if not resolution.verdict.resolved:
            self.refuse(request_id, resolution.cause,
                        f"resolution returned {resolution.verdict.value}",
                        principal=principal)
        return resolution

    def plan(self, request_id: str, intent, findings, dialect="snowflake",
             principal: Principal = None, plan: Plan = None) -> Plan:
        self._require(request_id, Phase.PLAN)
        p = plan if plan is not None else compile_plan(intent, list(findings),
                                                       dialect)
        self.journal.append(
            request_id, Phase.PLAN, p.plan_hash, principal=principal,
            refs={"intent_id": p.intent_id},
            payload={"operations": len(p.operations),
                     "irreversible": len(p.irreversible_ops),
                     "dialect": p.dialect})
        return p

    def simulate(self, request_id: str, plan: Plan, graph=None, executor=None,
                 coverage: CoverageReport = None,
                 budget: RiskTier = RiskTier.LOW, rubric=None,
                 principal: Principal = None) -> Forecast:
        self._require(request_id, Phase.SIMULATE)
        self._check_artifact(request_id, Phase.PLAN, plan.plan_hash, "plan")
        kw = {"rubric": rubric} if rubric is not None else {}
        f = simulate(plan, graph=graph, executor=executor, coverage=coverage,
                     budget=budget, **kw)
        self.journal.append(
            request_id, Phase.SIMULATE, f.forecast_hash, principal=principal,
            refs={"plan_hash": plan.plan_hash},
            payload={"tier": int(f.tier), "decision": f.decision.value,
                     "complete": f.complete,
                     "rows_estimate": f.rows_estimate,
                     "columns": f.columns_affected,
                     "downstream_consumers": f.total_consumers,
                     "irreversible": len(f.irreversible_targets),
                     "unmeasured": [s.name for s in f.unmeasured]})
        return f

    def approve(self, request_id: str, forecast: Forecast,
                principal: Principal) -> None:
        """Refused at the point of approval, not only in the audit. A
        principal below the tier, or the person who submitted the change,
        does not get an entry written and then flagged later."""
        self._require(request_id, Phase.APPROVE)
        self._check_artifact(request_id, Phase.SIMULATE,
                             forecast.forecast_hash, "forecast")
        # Separation of duties first. It is a structural bar that no amount
        # of authority cures, so checking the tier before it would report
        # the lesser problem to a senior person approving their own work.
        requesters = {e.principal["principal_id"] for e in self._entries(request_id)
                      if e.phase in (Phase.PLAN, Phase.OBSERVE, Phase.ANALYZE)
                      and e.principal}
        if principal.principal_id in requesters:
            raise OrchestratorError(
                CAUSE_SELF_APPROVAL,
                f"{principal.principal_id} submitted this change and cannot "
                f"also approve it, at any tier")
        if int(forecast.tier) > principal.max_approval_tier:
            raise OrchestratorError(
                CAUSE_OVER_AUTHORITY,
                f"{principal.principal_id} may approve to tier "
                f"{principal.max_approval_tier}; this forecast is tier "
                f"{int(forecast.tier)}")
        self.journal.append(
            request_id, Phase.APPROVE, forecast.forecast_hash,
            refs={"forecast_hash": forecast.forecast_hash},
            principal=principal,
            payload={"tier": int(forecast.tier),
                     "decision": forecast.decision.value})

    # ---- execution, in two records ------------------------------------
    def _attempts(self, request_id: str):
        """(unresolved attempt or None, completed attempt ids)."""
        done = {e.refs.get("attempt_id") for e in self._entries(request_id)
                if e.phase in (Phase.EXECUTE, Phase.RECONCILE)}
        unresolved = [e for e in self._entries(request_id)
                      if e.phase is Phase.EXECUTE_ATTEMPT
                      and e.refs.get("attempt_id") not in done]
        return (unresolved[-1] if unresolved else None), done

    def execute(self, request_id: str, plan: Plan, executor, stage=None,
                principal: Principal = None):
        """Two records, not one.

        The old shape wrote the journal entry AFTER the executor returned,
        which left a window: the DDL lands in the warehouse, the process
        dies, and the record says nothing happened. A restart would then
        execute the same plan again. So the attempt is written first, with
        an idempotency key, and the outcome second. An attempt with no
        outcome is not a failure and not a success — it is the one state
        that requires going and looking, which is what reconcile() does.
        """
        self._require(request_id, Phase.EXECUTE_ATTEMPT)
        self._check_artifact(request_id, Phase.PLAN, plan.plan_hash, "plan")

        unresolved, done = self._attempts(request_id)
        if unresolved is not None:
            raise OrchestratorError(
                CAUSE_UNRECONCILED,
                f"attempt {unresolved.refs.get('attempt_id')} was started and "
                f"never resolved. Something may have been applied. Call "
                f"reconcile() to find out before running anything again.")
        if done:
            raise OrchestratorError(
                CAUSE_ALREADY_EXECUTED,
                f"{request_id} already has a recorded execution; re-running "
                f"an approved plan is not idempotent and is not allowed by "
                f"replaying the call")

        sim = self._last(request_id, Phase.SIMULATE)
        if sim is None:
            raise OrchestratorError(CAUSE_NO_FORECAST,
                                    "nothing was simulated for this request")
        if sim.refs.get("plan_hash") != plan.plan_hash:
            raise OrchestratorError(
                CAUSE_ARTIFACT_MISMATCH,
                f"the recorded forecast is for plan "
                f"{sim.refs.get('plan_hash')}, not {plan.plan_hash}")

        if sim.payload.get("decision") != Decision.AUTONOMOUS.value:
            approved = any(
                e.refs.get("forecast_hash") == sim.subject_hash
                for e in self._entries(request_id) if e.phase is Phase.APPROVE)
            if not approved:
                raise OrchestratorError(
                    CAUSE_NOT_APPROVED,
                    f"forecast {sim.subject_hash} required approval and none "
                    f"is recorded; the gate is enforced here rather than "
                    f"noticed afterwards")

        attempt_id = _digest([request_id, plan.plan_hash, sim.subject_hash,
                              len(self._entries(request_id))])
        self.journal.append(
            request_id, Phase.EXECUTE_ATTEMPT, plan.plan_hash,
            principal=principal,
            refs={"attempt_id": attempt_id, "forecast_hash": sim.subject_hash,
                  "plan_hash": plan.plan_hash},
            payload={"operations": len(plan.operations),
                     "dialect": plan.dialect})

        kw = {"stage": stage} if stage is not None else {}
        receipt = executor.execute_staged(plan, **kw)

        self.journal.append(
            request_id, Phase.EXECUTE, receipt.receipt_hash,
            principal=principal,
            refs={"attempt_id": attempt_id,
                  "forecast_hash": sim.subject_hash,
                  "plan_hash": plan.plan_hash},
            payload={"verdict": receipt.verdict.value, **receipt.summary(),
                     "receipt": receipt.to_dict()})
        return receipt

    def reconcile(self, request_id: str, plan: Plan, executor,
                  principal: Principal = None):
        """Resolve an attempt that never produced an outcome.

        Asks the engine what is actually true and records that as the
        execution. It never re-runs the plan: an operation the engine says
        is already applied is applied, and one whose state cannot be read
        is UNKNOWN rather than assumed absent.
        """
        unresolved, _ = self._attempts(request_id)
        if unresolved is None:
            raise OrchestratorError(
                CAUSE_NOTHING_TO_RECONCILE,
                f"{request_id} has no attempt awaiting resolution")
        self._check_artifact(request_id, Phase.PLAN, plan.plan_hash, "plan")

        receipt = executor.reconcile(plan)
        self.journal.append(
            request_id, Phase.RECONCILE, receipt.receipt_hash,
            principal=principal,
            refs={"attempt_id": unresolved.refs.get("attempt_id"),
                  "plan_hash": plan.plan_hash},
            payload={"verdict": receipt.verdict.value, "reconciled": True,
                     **receipt.summary(), "receipt": receipt.to_dict()})
        return receipt

    def receipt_for(self, request_id: str):
        """Rehydrate the receipt from the journal. After a restart the
        caller has no receipt object, and verification cannot be made to
        wait on one that no longer exists."""
        from .executors.base import ExecutionReceipt
        for e in reversed(self._entries(request_id)):
            if e.phase in (Phase.EXECUTE, Phase.RECONCILE):
                body = e.payload.get("receipt")
                if body:
                    return ExecutionReceipt.from_dict(body)
        return None

    def verify(self, request_id: str, receipt=None, passed: bool = False,
               evidence: dict = None, principal: Principal = None) -> None:
        self._require(request_id, Phase.VERIFY)
        receipt = receipt if receipt is not None else self.receipt_for(request_id)
        if receipt is None:
            raise OrchestratorError(
                CAUSE_OUT_OF_ORDER,
                "no execution receipt is recorded for this request")
        evidence = dict(evidence or {})
        self.journal.append(
            request_id, Phase.VERIFY, _digest(evidence), principal=principal,
            refs={"receipt_hash": receipt.receipt_hash},
            payload={"passed": bool(passed), **evidence})

    def close(self, request_id: str, receipt=None,
              principal: Principal = None, lesson: Lesson = None) -> None:
        self._require(request_id, Phase.CLOSE)
        receipt = receipt if receipt is not None else self.receipt_for(request_id)
        if receipt is None:
            raise OrchestratorError(CAUSE_OUT_OF_ORDER,
                                    "nothing was executed for this request")
        passing = [e for e in self._entries(request_id)
                   if e.phase is Phase.VERIFY
                   and e.refs.get("receipt_hash") == receipt.receipt_hash
                   and e.payload.get("passed") is True]
        if not passing:
            raise OrchestratorError(
                "CLOSE_WITHOUT_PASSING_VERIFICATION",
                f"no passing verification is recorded for receipt "
                f"{receipt.receipt_hash}")
        self.journal.append(
            request_id, Phase.CLOSE, receipt.receipt_hash, principal=principal,
            refs={"receipt_hash": receipt.receipt_hash},
            payload={"lesson": lesson.to_dict()} if lesson else {})

    def refuse(self, request_id: str, cause: str, detail: str,
               principal: Principal = None) -> None:
        self.journal.append(request_id, Phase.REFUSE, _digest([cause, detail]),
                            principal=principal,
                            payload={"cause": cause, "detail": detail})

    # ---- helpers -------------------------------------------------------
    def _check_artifact(self, request_id: str, phase: Phase, h: str,
                        label: str) -> None:
        e = self._last(request_id, phase)
        if e is None:
            raise OrchestratorError(
                CAUSE_OUT_OF_ORDER, f"no {label} is recorded for {request_id}")
        if e.subject_hash != h:
            raise OrchestratorError(
                CAUSE_ARTIFACT_MISMATCH,
                f"the {label} handed in hashes to {h}; the record says "
                f"{e.subject_hash}. After a restart the artifact is supplied "
                f"by the caller and must be the one that was recorded, not "
                f"one recompiled since")

    # ---- Phase 6 -------------------------------------------------------
    def learn(self, request_id: str, forecast: Forecast, receipt,
              erasure: ErasureRequest = None) -> Lesson:
        """Did the forecast hold? Recorded, never applied."""
        lesson = Lesson(request_id)

        predicted_rev = set(forecast.irreversible_targets)
        actually_refused = {o.target for o in receipt.operations
                            if not o.reversible}
        lesson.add("reversibility", sorted(predicted_rev),
                   sorted(actually_refused),
                   predicted_rev == actually_refused)

        predicted_cols = forecast.columns_affected
        touched = len([o for o in receipt.operations
                       if o.status.value != "not_attempted"])
        lesson.add("columns_affected", predicted_cols, touched,
                   None if receipt.verdict.value in ("HALTED_AT_CANARY",
                                                     "REFUSED")
                   else predicted_cols == touched,
                   "" if receipt.verdict.value not in ("HALTED_AT_CANARY",
                                                       "REFUSED")
                   else "run stopped early by design; the forecast was not "
                        "given the chance to be wrong")

        clean_forecast = forecast.complete and not forecast.unmeasured
        clean_run = receipt.verdict.value == "COMPLETE"
        lesson.add("forecast_completeness", clean_forecast, clean_run,
                   None if not clean_forecast else clean_forecast == clean_run,
                   "" if clean_forecast else
                   "forecast was incomplete, so its silence about this "
                   "outcome predicted nothing")

        if erasure is not None:
            for a in erasure.attestability():
                view = erasure.attestations.get(a.store_name)
                observed = view.classification if view else None
                if a.attestable:
                    lesson.add(f"attestability[{a.store_name}]", "attestable",
                               observed,
                               None if observed is None else view.is_pass,
                               "" if observed else "never verified")
                else:
                    lesson.add(f"attestability[{a.store_name}]",
                               a.ceiling or "not attestable", observed,
                               None if observed is None
                               else observed == a.ceiling,
                               "predicted ceiling vs attested classification")
        return lesson
