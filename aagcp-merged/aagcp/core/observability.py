"""
aagcp/core/observability.py — spans and health, projected from the journal.

WHY A PROJECTION AND NOT AN EMITTER.
The tempting design is to sprinkle span calls through the orchestrator.
Do that and you have two records of what happened: the journal, and
whatever the tracing backend kept. They will disagree — a span dropped by
a sampler, a batch lost on shutdown, an exception between the journal
write and the emit — and the first time it matters you will be holding two
histories and no way to say which is the record. So nothing here emits
anything the journal does not already contain. A span is a rendering of an
entry. If it is not in the journal it did not happen, and if it is in the
journal it can be re-rendered at any time, including for a request that
finished before the tracing backend was installed.

WHY REDACTION IS CODE AND NOT A CONVENTION.
AAGCP_v3's aagcp/govern/telemetry.py documents its semantic convention as
including `aagcp.subject — subject identity (name/id) when applicable`.
That is a straight path from a governed estate into a third-party
observability backend that sits outside the customer boundary, and it
contradicts the same repository's ErasureVerifier.span_attrs(), which
says "token hash only, never a name" and means it. When a convention and
an implementation disagree, the convention is what a future contributor
reads. So the allowlist below is enforced: an attribute whose key is not
permitted is dropped and COUNTED, and a value that looks like a natural
identifier is refused outright rather than emitted. Silent dropping would
be its own failure — you would never learn the instrumentation was lying
about coverage.

WHAT IS ACTUALLY WORTH MEASURING.
Not latency. The governance-relevant numbers are the ones describing how
much this system knows and how much it is guessing:

  unmeasured_rate     how often forecasts ran on incomplete signals
  autonomy_rate       how often the gate let something through unattended.
                      At 100% the gate is decorative; at 0% nobody is using
                      the forecast and every change is a manual approval
  open_age            how long requests have been open, against a response
                      window the customer sets
  integrity           whether the chain and its bindings still hold

An erasure sitting open past a statutory response window is a compliance
failure that no amount of correct machinery fixes, and it is invisible
unless something counts it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .journal import Journal, Phase

OBSERVABILITY_VERSION = "observability-1.0.0"

# Attribute keys permitted on a span. Everything is a hash, a count, an
# enum or a boolean. There is no key here into which a name, an address or
# a column value could be written and still make sense.
EMITTABLE = frozenset({
    "aagcp.request_id", "aagcp.phase", "aagcp.seq", "aagcp.subject_hash",
    "aagcp.previous", "aagcp.entry_hash", "aagcp.principal_id",
    "aagcp.principal_role", "aagcp.plan_hash", "aagcp.forecast_hash",
    "aagcp.receipt_hash", "aagcp.intent_id",
    "aagcp.tier", "aagcp.decision", "aagcp.verdict", "aagcp.complete",
    "aagcp.passed", "aagcp.operations", "aagcp.columns", "aagcp.irreversible",
    "aagcp.rows_estimate", "aagcp.downstream_consumers", "aagcp.findings",
    "aagcp.unmeasured", "aagcp.candidate_count", "aagcp.cause",
    "aagcp.denominator_verified", "aagcp.anomalies", "aagcp.dialect",
    "aagcp.applied", "aagcp.failed", "aagcp.unknown", "aagcp.not_attempted",
    "aagcp.partially_applied", "aagcp.residual_artifacts",
    "aagcp.applied_but_unverified",
})

# A principal id is an email in most deployments, and it is the one
# identifier that legitimately belongs in a trace — an audit trail whose
# actors are anonymous is not an audit trail. Everything else that looks
# like a natural identifier is refused.
_IDENTIFIER_SHAPED = re.compile(
    r"[\w.+-]+@[\w-]+\.\w+"                 # email
    r"|\+?\d[\d \-()]{7,}"                  # phone
    r"|\b\d{4}[ -]?\d{4}[ -]?\d{4}\b")      # 12-digit id / card-like

# Hashes are hex and routinely contain long digit runs, which the phone
# pattern above matches. They are also the thing this module exists to
# emit, and a hex string cannot hide an email inside it, so they are
# exempted explicitly rather than by loosening the identifier pattern.
_HASH_SHAPED = re.compile(r"^(?:[0-9a-f]{16,}|[A-Z]-[0-9A-F]{6,}|0+)$")


def _is_hash(value: str) -> bool:
    return bool(_HASH_SHAPED.match(value))


CAUSE_KEY_NOT_PERMITTED = "ATTRIBUTE_KEY_NOT_ON_THE_ALLOWLIST"
CAUSE_VALUE_LOOKS_PERSONAL = "VALUE_MATCHES_A_NATURAL_IDENTIFIER"


class RedactionError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Span:
    name: str
    attributes: Dict[str, object] = field(default_factory=dict)
    dropped: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {"name": self.name, "attributes": dict(self.attributes),
                "dropped_attributes": list(self.dropped)}


_PAYLOAD_KEYS = {
    "tier": "aagcp.tier", "decision": "aagcp.decision",
    "verdict": "aagcp.verdict", "complete": "aagcp.complete",
    "passed": "aagcp.passed", "operations": "aagcp.operations",
    "columns": "aagcp.columns", "irreversible": "aagcp.irreversible",
    "rows_estimate": "aagcp.rows_estimate",
    "downstream_consumers": "aagcp.downstream_consumers",
    "findings": "aagcp.findings", "candidate_count": "aagcp.candidate_count",
    "cause": "aagcp.cause", "dialect": "aagcp.dialect",
    "denominator_verified": "aagcp.denominator_verified",
    "anomalies": "aagcp.anomalies", "applied": "aagcp.applied",
    "failed": "aagcp.failed", "unknown": "aagcp.unknown",
    "not_attempted": "aagcp.not_attempted",
    "partially_applied": "aagcp.partially_applied",
    "residual_artifacts": "aagcp.residual_artifacts",
    "applied_but_unverified": "aagcp.applied_but_unverified",
}


def _scalar(v):
    if isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)


def project(entry, strict: bool = True) -> Span:
    """One journal entry rendered as a span. Nothing is invented and
    nothing outside the allowlist survives.

    strict=True refuses an identifier-shaped value rather than emitting it.
    strict=False drops it and records the drop, which is what a running
    system wants: an instrumentation bug should not take down the loop, but
    it must not be silent either.
    """
    span = Span(name=f"aagcp.{entry.phase.value}")
    candidates: Dict[str, object] = {
        "aagcp.request_id": entry.request_id,
        "aagcp.phase": entry.phase.value,
        "aagcp.seq": entry.seq,
        "aagcp.subject_hash": entry.subject_hash,
        "aagcp.entry_hash": entry.entry_hash,
        "aagcp.previous": entry.previous,
    }
    if entry.principal:
        candidates["aagcp.principal_id"] = entry.principal["principal_id"]
        candidates["aagcp.principal_role"] = entry.principal.get("role", "")
    for k, v in (entry.refs or {}).items():
        candidates[f"aagcp.{k}"] = v
    for k, v in (entry.payload or {}).items():
        mapped = _PAYLOAD_KEYS.get(k)
        if mapped:
            candidates[mapped] = _scalar(v)
        elif k == "unmeasured":
            candidates["aagcp.unmeasured"] = _scalar(v)
        else:
            span.dropped.append({"key": k, "cause": CAUSE_KEY_NOT_PERMITTED})

    for key, value in candidates.items():
        if key not in EMITTABLE:
            span.dropped.append({"key": key, "cause": CAUSE_KEY_NOT_PERMITTED})
            continue
        # principal_id is the deliberate exception: an audit trail with
        # anonymous actors is not one.
        if (key != "aagcp.principal_id" and isinstance(value, str)
                and not _is_hash(value)
                and _IDENTIFIER_SHAPED.search(value)):
            if strict:
                raise RedactionError(
                    CAUSE_VALUE_LOOKS_PERSONAL,
                    f"{key} carries a value shaped like a natural identifier; "
                    f"refusing to emit it to a backend outside the boundary")
            span.dropped.append({"key": key,
                                 "cause": CAUSE_VALUE_LOOKS_PERSONAL})
            continue
        span.attributes[key] = value
    return span


def trace(journal: Journal, request_id: str, strict: bool = True) -> List[Span]:
    """One request, one trace, rendered from the record. Works for a
    request that closed before any tracing backend existed."""
    return [project(e, strict=strict) for e in journal.entries
            if e.request_id == request_id]


# ---------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------

@dataclass
class Health:
    requests: int
    open_requests: List[str]
    open_ages_seconds: Dict[str, float]
    overdue: List[dict]
    autonomy_rate: Optional[float]
    approval_rate: Optional[float]
    unmeasured_rate: Optional[float]
    incomplete_forecasts: int
    forecasts: int
    executions_by_verdict: Dict[str, int]
    chain_problems: List[dict]
    binding_problems: List[dict]
    response_window_days: float

    @property
    def integrity_ok(self) -> bool:
        return not self.chain_problems and not self.binding_problems

    def to_dict(self):
        return {"version": OBSERVABILITY_VERSION, "requests": self.requests,
                "open_requests": list(self.open_requests),
                "open_ages_seconds": dict(self.open_ages_seconds),
                "overdue": list(self.overdue),
                "autonomy_rate": self.autonomy_rate,
                "approval_rate": self.approval_rate,
                "unmeasured_rate": self.unmeasured_rate,
                "incomplete_forecasts": self.incomplete_forecasts,
                "forecasts": self.forecasts,
                "executions_by_verdict": dict(self.executions_by_verdict),
                "integrity_ok": self.integrity_ok,
                "chain_problems": list(self.chain_problems),
                "binding_problems": list(self.binding_problems),
                "response_window_days": self.response_window_days}

    def explain(self) -> str:
        lines = [f"{self.requests} request(s), {len(self.open_requests)} open"]
        if self.forecasts:
            lines.append(
                f"  autonomy {self.autonomy_rate:.0%} of {self.forecasts} "
                f"forecast(s); {self.incomplete_forecasts} ran on incomplete "
                f"signals ({self.unmeasured_rate:.0%})")
            if self.autonomy_rate == 1.0:
                lines.append("    every forecast was autonomous — the "
                             "approval gate is not doing anything")
            if self.autonomy_rate == 0.0:
                lines.append("    no forecast was autonomous — either the "
                             "budget is set below every real change, or the "
                             "forecast is not being used to decide anything")
        for o in self.overdue:
            lines.append(f"  OVERDUE {o['request_id']}: open "
                         f"{o['age_days']:.1f} days against a "
                         f"{self.response_window_days:g}-day window")
        for v, n in sorted(self.executions_by_verdict.items()):
            lines.append(f"  executions {v}: {n}")
        lines.append(f"  integrity: "
                     f"{'chain and bindings hold' if self.integrity_ok else 'PROBLEMS'}")
        for p in self.chain_problems + self.binding_problems:
            lines.append(f"    {p['cause']} — {p['detail']}")
        return "\n".join(lines)


def health(journal: Journal, now: float,
           response_window_days: float = 30.0) -> Health:
    """response_window_days is a legal input, not a fact this module knows.
    Statutory response windows differ by regime and by the kind of request,
    and I am not asserting a number for any of them here — the customer's
    counsel sets it and it is recorded in the output so a report says which
    window it was measured against."""
    by_request: Dict[str, list] = {}
    for e in journal.entries:
        by_request.setdefault(e.request_id, []).append(e)

    open_ids, ages, overdue = [], {}, []
    for rid, entries in sorted(by_request.items()):
        closed = any(e.phase in (Phase.CLOSE, Phase.REFUSE) for e in entries)
        if closed:
            continue
        open_ids.append(rid)
        started = float(entries[0].timestamp)
        age = max(now - started, 0.0)
        ages[rid] = age
        if age > response_window_days * 86400:
            overdue.append({"request_id": rid, "age_days": age / 86400,
                            "opened_at": entries[0].timestamp,
                            "current_phase": entries[-1].phase.value})

    forecasts = [e for e in journal.entries if e.phase is Phase.SIMULATE]
    autonomous = [e for e in forecasts
                  if e.payload.get("decision") == "AUTONOMOUS"]
    incomplete = [e for e in forecasts if e.payload.get("complete") is False]

    verdicts: Dict[str, int] = {}
    for e in journal.entries:
        if e.phase is Phase.EXECUTE:
            v = str(e.payload.get("verdict", "unknown"))
            verdicts[v] = verdicts.get(v, 0) + 1

    n = len(forecasts)
    return Health(
        requests=len(by_request), open_requests=open_ids,
        open_ages_seconds=ages, overdue=overdue,
        autonomy_rate=(len(autonomous) / n if n else None),
        approval_rate=((n - len(autonomous)) / n if n else None),
        unmeasured_rate=(len(incomplete) / n if n else None),
        incomplete_forecasts=len(incomplete), forecasts=n,
        executions_by_verdict=verdicts,
        chain_problems=journal.verify_chain(),
        binding_problems=journal.verify_bindings(),
        response_window_days=response_window_days)
