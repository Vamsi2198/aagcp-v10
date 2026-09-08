"""
aagcp/core/erasure.py — the erase action family.

Erasure is the only action in the loop that cannot be undone and cannot be
confirmed by looking at the thing you changed. A masking policy is either
attached or it is not; you query the catalog and you know. A subject is
either gone or recoverable through a retrieval path nobody thought to
check, and the difference is a statistical claim over an index that moved
while you were measuring it.

So this module does two things the other phases do not need to.

FIRST, IT ASKS WHETHER THE ERASURE CAN EVER BE CLOSED — BEFORE DELETING.
AAGCP_v3's verifier will refuse to attest under three conditions that are
all knowable in advance:

    n_control_anchors < 19        -> INCONCLUSIVE_CONTROLS
    |baseline_present - baseline_absent| < 0.01
                                  -> paired verdict 'uninformative'
                                  -> INCONCLUSIVE_INDISTINGUISHABLE
    any required channel unmeasurable
                                  -> INCONCLUSIVE_UNMEASURED

Those three constants are read out of erasure_verifier.py, not chosen
here — see the CONSTANTS block. The consequence is that a Pinecone-backed
subject, or a subject sitting on top of a near-duplicate, produces an
erasure that will be performed and can never be certified. Learning that
after the delete is the worst possible ordering: the data is gone, the
request stays open forever, and there is nothing left to re-measure.
So attestability is a Phase 4 gate, and by default an unattestable
erasure is refused rather than performed.

That default can be overridden, because it has to be. A statutory erasure
obligation does not pause because the verifier cannot reach a channel —
the fiduciary may be required to delete and unable to prove it. That is a
decision with legal consequences, so UnattestableAcceptance demands a
named authority, the same way an exclusion in Phase 0 does. An override
with nobody's name on it is not available.

SECOND, IT REFUSES TO CLOSE ON ANYTHING BUT A PASS. The request reaches
COMPLETE only when execution completed AND every target carries a passing
attestation. RESIDUE_DETECTED leaves it open. INCONCLUSIVE_UNMEASURED
leaves it open. A missing attestation leaves it open. There is no path
through this file where an erasure closes on the absence of evidence.

The verifier is reached through a Protocol, not an import. The engine
stays stdlib-only and the numpy/cryptography dependency lives in the
adapter, which is the same reason the control plane sees an
AttestationView — classification, counts, hashes — and never a vector.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from .intent import Action, Intent, IntentError, ScopeKind
from .plan import Operation, Plan, PostgresDialect, SnowflakeDialect
from .policy import Policy, Treatment

ERASURE_VERSION = "erasure-1.0.0"

# ---------------------------------------------------------------------
# CONSTANTS MIRRORED FROM THE VERIFIER
# Confidence: VERIFIED — read directly out of AAGCP_v3
# aagcp/verify/erasure_verifier.py. ErasureBound.classify() returns
# INCONCLUSIVE_CONTROLS below 19 control anchors; _probe_once() marks the
# paired verdict 'uninformative' when the two baselines sit closer than
# 0.01. They are restated here rather than imported because importing
# would drag numpy into the engine. Any change to those two numbers in
# the verifier must be reflected here, and the adapter asserts they still
# agree at runtime.
# ---------------------------------------------------------------------
MIN_CONTROL_ANCHORS = 19
MIN_BASELINE_SEPARATION = 0.01

PASSING_CLASSIFICATIONS = frozenset({
    "STRONG_EVIDENCE_ERASED", "MODERATE_EVIDENCE_ERASED",
})
KNOWN_CLASSIFICATIONS = PASSING_CLASSIFICATIONS | frozenset({
    "NOT_ERASED", "RESIDUE_DETECTED", "RESIDUE_SUSPECTED",
    "INCONCLUSIVE_INDISTINGUISHABLE", "INCONCLUSIVE_CONTROLS",
    "INCONCLUSIVE_UNMEASURED",
})

# Engines that expose no inspectable internal state. A retrieval probe can
# say the subject is not reachable; it cannot say the bytes are gone.
# Confidence: VERIFIED — EngineType.required_channels in the verifier
# declares these permanently UNAVAILABLE for Pinecone.
UNINSPECTABLE_ENGINES = frozenset({"pinecone"})


# ---- cause codes -----------------------------------------------------
CAUSE_ANCHOR_NOT_REGISTERED = "ANCHOR_NOT_REGISTERED_BEFORE_ERASURE"
CAUSE_ENGINE_UNINSPECTABLE = "ENGINE_EXPOSES_NO_INSPECTION_CHANNEL"
CAUSE_CONTROLS_INSUFFICIENT = "CONTROL_ANCHORS_BELOW_MINIMUM"
CAUSE_BASELINES_INSEPARABLE = "SUBJECT_NOT_SEPARABLE_FROM_NEIGHBOURS"
CAUSE_ATTESTABLE = "ATTESTABLE"
CAUSE_RESIDUE = "RESIDUE_DETECTED"
CAUSE_INCONCLUSIVE = "INCONCLUSIVE_UNMEASURED"
CAUSE_NOT_VERIFIED = "NOT_YET_VERIFIED"
CAUSE_EXECUTION_INCOMPLETE = "EXECUTION_DID_NOT_COMPLETE"
CAUSE_UNRECOGNISED = "UNRECOGNISED_CLASSIFICATION"
CAUSE_VERIFIER_DISAGREEMENT = "VERIFIER_PASS_FLAG_DISAGREES_WITH_CLASSIFICATION"
CAUSE_SUBJECT_UNSAFE = "SUBJECT_VALUE_NOT_SAFE_TO_EMBED"
CAUSE_STRUCTURED_RESIDUE = "SUBJECT_STILL_PRESENT_IN_STRUCTURED_STORE"
CAUSE_STRUCTURED_UNCHECKED = "STRUCTURED_STORE_NOT_RE_QUERIED"
CAUSE_VECTOR_NOT_DELETED = "NO_VECTOR_DELETION_RECORDED"
CAUSE_VECTOR_CONTRADICTS = "STORE_STILL_ADDRESSABLE_DESPITE_ATTESTATION"
CAUSE_TOKEN_MISMATCH = "ATTESTATION_IS_FOR_A_DIFFERENT_SUBJECT_TOKEN"
CAUSE_TOKEN_ABSENT = "ATTESTATION_CARRIES_NO_SUBJECT_TOKEN"
CAUSE_SUBJECT_UNRESOLVED = "SUBJECT_NOT_RESOLVED_TO_ONE_PERSON"
CAUSE_LINKED_NOT_COVERED = "LINKED_IDENTITY_KEY_NOT_COVERED_BY_ERASURE"


# ---------------------------------------------------------------------
# Subject
# ---------------------------------------------------------------------

# Deliberately conservative. A subject value is interpolated into DDL under
# push-down — there is no bind parameter on the far side of a generated
# statement — so anything that could terminate a literal or start a comment
# is refused rather than escaped cleverly.
#
# The apostrophe is the one exception, because O'Neill is a real person and
# refusing to erase them is not an option. Doubling it is safe here only
# because backslash is banned from the same set: with no backslash there is
# no escape mode in which '' means anything other than one literal quote.
# Semicolons, newlines and dashes stay out, so a comment or a second
# statement cannot be reached even before the doubling runs.
_SUBJECT_SAFE = re.compile(r"^[A-Za-z0-9@._+'\- :]{1,256}$")


class SubjectError(ValueError):
    def __init__(self, code: str, detail: str, candidates=()):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail
        self.candidates = list(candidates)


@dataclass(frozen=True)
class Subject:
    """One data subject. `key` is the value matched in structured stores;
    `token_hash` is the opaque handle the verifier knows them by.

    There is no name field and no resolution logic here yet — item 5 adds
    AMBIGUOUS_SUBJECT, and this type is the seam it plugs into.
    """
    key: str
    key_kind: str = "subject_id"       # subject_id | email | account | ...
    token_hash: str = ""

    def __post_init__(self):
        if not _SUBJECT_SAFE.match(self.key):
            raise SubjectError(
                CAUSE_SUBJECT_UNSAFE,
                f"subject key {self.key!r} contains characters that cannot be "
                f"safely embedded in generated DDL")

    @property
    def literal(self) -> str:
        return "'" + self.key.replace("'", "''") + "'"


# ---------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------

class EraseMode(str, Enum):
    DELETE_ROW = "delete_row"       # the record itself goes
    NULL_FIELDS = "null_fields"     # the record stays, the identifiers go


@dataclass(frozen=True)
class RowTarget:
    """A structured location holding the subject."""
    database: str
    schema: str
    table: str
    subject_column: str
    mode: EraseMode = EraseMode.DELETE_ROW
    fields: Tuple[str, ...] = ()     # required for NULL_FIELDS
    citation: str = ""
    row_estimate: int = 0

    @property
    def fqn(self) -> str:
        return f"{self.database}.{self.schema}.{self.table}"

    @property
    def target(self) -> str:
        return f"{self.fqn}.{self.subject_column}"

    def __post_init__(self):
        if self.mode is EraseMode.NULL_FIELDS and not self.fields:
            raise ValueError(f"{self.fqn}: NULL_FIELDS needs the fields to null")
        if not self.citation:
            raise ValueError(f"{self.fqn}: every erasure target needs the "
                             f"clause it answers to")


@dataclass(frozen=True)
class VectorTarget:
    """An index holding embeddings derived from the subject."""
    store_name: str
    engine: str                      # in_memory | pgvector_hnsw | pinecone | ...
    citation: str = ""
    n_control_anchors: int = 0       # how many the verifier will have
    anchor_registered: bool = False
    baseline_separation: Optional[float] = None   # None = never measured

    def __post_init__(self):
        if not self.citation:
            raise ValueError(f"{self.store_name}: every erasure target needs "
                             f"the clause it answers to")


# ---------------------------------------------------------------------
# Planning. Subclasses rather than edits: the erase statements are added
# by extending the compiler's dialects, so quoting and naming rules stay
# in one place instead of being reimplemented next to them.
# ---------------------------------------------------------------------

class SnowflakeEraseDialect(SnowflakeDialect):
    def erase_statements(self, t: RowTarget, subject: Subject) -> List[str]:
        tbl = ".".join(self.quote(p) for p in (t.database, t.schema, t.table))
        col = self.quote(t.subject_column)
        where = f"WHERE {col} = {subject.literal}"
        if t.mode is EraseMode.DELETE_ROW:
            return [f"DELETE FROM {tbl} {where};"]
        sets = ", ".join(f"{self.quote(f)} = NULL" for f in t.fields)
        return [f"UPDATE {tbl} SET {sets} {where};"]


class PostgresEraseDialect(PostgresDialect):
    def erase_statements(self, t: RowTarget, subject: Subject) -> List[str]:
        tbl = ".".join(self.quote(p) for p in (t.database, t.schema, t.table))
        col = self.quote(t.subject_column)
        where = f"WHERE {col} = {subject.literal}"
        if t.mode is EraseMode.DELETE_ROW:
            return [f"DELETE FROM {tbl} {where};"]
        sets = ", ".join(f"{self.quote(f)} = NULL" for f in t.fields)
        return [f"UPDATE {tbl} SET {sets} {where};"]


ERASE_DIALECTS = {"snowflake": SnowflakeEraseDialect(),
                  "postgres": PostgresEraseDialect()}


def compile_erasure_plan(intent: Intent, subject: Subject,
                         row_targets: Sequence[RowTarget],
                         dialect_name: str = "snowflake") -> Plan:
    """Deterministic, same as the masking compiler. Vector targets are not
    in the Plan: their deletion goes through the store's own client and
    their evidence comes from an attestation, so putting them in a list of
    SQL statements would misrepresent both."""
    if intent.action is not Action.ERASE:
        raise IntentError("NOT_AN_ERASE_INTENT",
                          f"compile_erasure_plan received '{intent.action.value}'")
    if intent.scope.kind is not ScopeKind.SUBJECT:
        raise IntentError("ERASE_SCOPE_MUST_BE_SUBJECT",
                          "erase applies to a data subject, not to objects")

    dialect = ERASE_DIALECTS[dialect_name]
    ops: List[Operation] = []
    for t in sorted(row_targets, key=lambda x: (x.fqn, x.subject_column)):
        ops.append(Operation(
            op=("erase_rows" if t.mode is EraseMode.DELETE_ROW
                else "erase_fields"),
            target=t.target,
            treatment="erase",
            identifier_key=t.subject_column,
            citation=t.citation,
            audience=(),
            statements=dialect.erase_statements(t, subject),
            reversible=False,      # there is no undo; the executor will refuse
            row_estimate=t.row_estimate,
        ))
    return Plan(intent_id=intent.intent_id, policy_id=intent.policy_id,
                operations=ops, unresolved=[], dialect=dialect.name)


# ---------------------------------------------------------------------
# Attestability — the Phase 4 pre-check
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Attestability:
    store_name: str
    engine: str
    attestable: bool
    cause: str
    detail: str
    ceiling: str = ""      # the best classification reachable, when capped

    def to_dict(self):
        return {"store_name": self.store_name, "engine": self.engine,
                "attestable": self.attestable, "cause": self.cause,
                "detail": self.detail, "ceiling": self.ceiling}


def attestability(target: VectorTarget) -> Attestability:
    """Would the verifier be able to reach a pass on this store, for this
    subject, if the erasure were performed right now?

    Checked in the same order the verifier classifies, so the answer here
    and the classification later cannot drift apart.
    """
    if not target.anchor_registered:
        # verify() raises outright without a registered anchor: you cannot
        # probe a region you never located.
        return Attestability(
            target.store_name, target.engine, False, CAUSE_ANCHOR_NOT_REGISTERED,
            "no anchor was registered before erasure; the subject's region "
            "was never located and cannot be probed afterwards",
            ceiling="none — verify() raises")

    if target.engine.lower() in UNINSPECTABLE_ENGINES:
        return Attestability(
            target.store_name, target.engine, False, CAUSE_ENGINE_UNINSPECTABLE,
            f"{target.engine} exposes no tombstone, compaction or replication "
            f"channel, so every required channel stays UNAVAILABLE",
            ceiling="INCONCLUSIVE_UNMEASURED")

    if (target.baseline_separation is not None
            and target.baseline_separation < MIN_BASELINE_SEPARATION):
        return Attestability(
            target.store_name, target.engine, False, CAUSE_BASELINES_INSEPARABLE,
            f"baselines differ by {target.baseline_separation:.4f}, below "
            f"{MIN_BASELINE_SEPARATION}; a near-duplicate occupies the region "
            f"and no retrieval probe can separate present from erased",
            ceiling="INCONCLUSIVE_INDISTINGUISHABLE")

    if target.n_control_anchors < MIN_CONTROL_ANCHORS:
        return Attestability(
            target.store_name, target.engine, False, CAUSE_CONTROLS_INSUFFICIENT,
            f"{target.n_control_anchors} control anchors available, "
            f"{MIN_CONTROL_ANCHORS} required; confidence comes from controls, "
            f"not from probe count",
            ceiling="INCONCLUSIVE_CONTROLS")

    return Attestability(target.store_name, target.engine, True,
                         CAUSE_ATTESTABLE,
                         f"{target.n_control_anchors} control anchors, anchor "
                         f"registered, channels inspectable")


@dataclass(frozen=True)
class UnattestableAcceptance:
    """Proceeding with an erasure that can never be certified. Requires a
    name, because it is a decision somebody has to own — the same standard
    an exclusion in Phase 0 is held to."""
    authority: str
    detail: str
    stores: Tuple[str, ...] = ()

    def __post_init__(self):
        if not self.authority:
            raise ValueError(
                "accepting an unattestable erasure requires a named "
                "authority; the data goes and the proof never arrives, and "
                "somebody has to own that")
        if not self.detail:
            raise ValueError("an acceptance must state its reasoning")

    def covers(self, store_name: str) -> bool:
        return not self.stores or store_name in self.stores


# ---------------------------------------------------------------------
# Verification intake
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class AttestationView:
    """A stdlib projection of ErasureAttestation. The control plane sees
    this; it never sees a vector, an embedding or an anchor."""
    store_name: str
    classification: str
    is_pass: bool
    p_value: float = 1.0
    n_control_anchors: int = 0
    unmeasured_channels: Tuple[str, ...] = ()
    merkle_root: str = ""
    signature: str = ""
    scope: str = ""
    subject_token_hash: str = ""
    # Where this attestation sits in aagcp.verify.AttestationLog, which
    # remains the log of record for attestations. The journal references
    # these rather than copying the attestation body.
    log_index: Optional[int] = None
    log_entry_hash: str = ""

    def to_dict(self):
        return {"store_name": self.store_name,
                "classification": self.classification, "is_pass": self.is_pass,
                "p_value": self.p_value,
                "n_control_anchors": self.n_control_anchors,
                "unmeasured_channels": list(self.unmeasured_channels),
                "merkle_root": self.merkle_root,
                "signature_present": bool(self.signature),
                "scope": self.scope,
                "subject_token_hash": self.subject_token_hash,
                "log_index": self.log_index,
                "log_entry_hash": self.log_entry_hash}


class ErasureVerifierPort(Protocol):
    def attest(self, subject: Subject, store_name: str) -> AttestationView: ...


@dataclass(frozen=True)
class StructuredCheck:
    """Re-query evidence from a structured store. Three-valued, for the same
    reason every other measurement in this codebase is."""
    target: str
    subject_present: Optional[bool]    # True | False | None = could not check
    detail: str = ""

    def to_dict(self):
        return {"target": self.target, "subject_present": self.subject_present,
                "detail": self.detail}


def adjudicate(view: AttestationView) -> Tuple[bool, str, str]:
    """(closes, cause, detail) for one attestation.

    Two independent readings of the same attestation, deliberately. The
    verifier's own is_pass flag is checked against a local allowlist of
    classifications, and a disagreement between them is resolved as
    inconclusive rather than as whichever answer is more convenient. That
    guard exists so a future loosening of is_pass() upstream cannot quietly
    start closing requests here.
    """
    if view.classification not in KNOWN_CLASSIFICATIONS:
        return (False, CAUSE_UNRECOGNISED,
                f"'{view.classification}' is not a classification this "
                f"version recognises; treated as no evidence")

    local = view.classification in PASSING_CLASSIFICATIONS
    if local != view.is_pass:
        return (False, CAUSE_VERIFIER_DISAGREEMENT,
                f"attestation reports is_pass={view.is_pass} for "
                f"'{view.classification}'; the two do not agree")

    if not local:
        cause = (CAUSE_RESIDUE
                 if view.classification in ("NOT_ERASED", "RESIDUE_DETECTED",
                                            "RESIDUE_SUSPECTED")
                 else CAUSE_INCONCLUSIVE)
        return (False, cause, f"attested {view.classification}")

    if not view.signature:
        return (False, CAUSE_INCONCLUSIVE,
                "a passing classification arrived unsigned; an unsigned "
                "attestation is not an attestation")
    return (True, CAUSE_ATTESTABLE, f"attested {view.classification}")


# ---------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------

class RequestState(str, Enum):
    OPEN = "OPEN"                        # nothing executed yet
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    COMPLETE = "COMPLETE"
    REFUSED = "REFUSED"                  # never executed; unattestable


@dataclass
class ErasureRequest:
    subject: Subject
    row_targets: Tuple[RowTarget, ...] = ()
    vector_targets: Tuple[VectorTarget, ...] = ()
    acceptance: Optional[UnattestableAcceptance] = None
    # Set when the subject came through core.subject_resolution. Carries the
    # linked key set, which is what makes fragmentation detectable.
    resolution: Optional[object] = None
    additional_subjects: Tuple[Subject, ...] = ()
    state: RequestState = RequestState.OPEN
    execution_verdict: str = ""
    attestations: Dict[str, AttestationView] = field(default_factory=dict)
    structured_checks: Dict[str, StructuredCheck] = field(default_factory=dict)
    vector_receipts: Dict[str, dict] = field(default_factory=dict)
    refusal: Optional[dict] = None

    # ---- construction from a resolution -------------------------------
    @classmethod
    def from_resolution(cls, resolution, row_targets=(), vector_targets=(),
                        subjects: Sequence[Subject] = (), **kw
                        ) -> "ErasureRequest":
        """The only constructor that enforces identity. An unresolved
        subject cannot become an erasure request — AMBIGUOUS_SUBJECT is a
        refusal, not a warning to be carried forward and ignored."""
        if not getattr(resolution.verdict, "resolved", False):
            raise SubjectError(
                CAUSE_SUBJECT_UNRESOLVED,
                f"resolution returned {resolution.verdict.value} "
                f"({resolution.cause}); an irreversible act needs one person")
        if not subjects:
            raise SubjectError(CAUSE_SUBJECT_UNRESOLVED,
                               "no subject keys supplied for the erasure")
        return cls(subject=subjects[0], row_targets=tuple(row_targets),
                   vector_targets=tuple(vector_targets),
                   resolution=resolution,
                   additional_subjects=tuple(subjects[1:]), **kw)

    def covered_keys(self) -> set:
        return {s.key.strip().casefold()
                for s in (self.subject,) + tuple(self.additional_subjects)}

    def uncovered_linked_keys(self) -> List[dict]:
        """The silent failure: the person holds three account ids and the
        erasure touched one. Nothing about the execution or the attestation
        would notice, because both are correct about what they were asked
        to do."""
        if self.resolution is None:
            return []
        out = []
        covered = self.covered_keys()
        for kind, value in getattr(self.resolution, "linked_keys", ()):
            if value.strip().casefold() not in covered:
                out.append({"key_kind": kind, "cause": CAUSE_LINKED_NOT_COVERED,
                            "detail": f"the subject is also known by a "
                                      f"{kind} that no erase operation "
                                      f"targets"})
        return out

    # ---- Phase 4 -----------------------------------------------------
    def attestability(self) -> List[Attestability]:
        return [attestability(t) for t in
                sorted(self.vector_targets, key=lambda x: x.store_name)]

    def blockers(self) -> List[dict]:
        """Stores that cannot be certified and are not covered by a named
        acceptance."""
        out = []
        for a in self.attestability():
            if a.attestable:
                continue
            if self.acceptance and self.acceptance.covers(a.store_name):
                continue
            out.append(a.to_dict())
        return out

    def accepted_unattestable(self) -> List[dict]:
        if not self.acceptance:
            return []
        return [{**a.to_dict(), "accepted_by": self.acceptance.authority,
                 "acceptance_detail": self.acceptance.detail}
                for a in self.attestability()
                if not a.attestable and self.acceptance.covers(a.store_name)]

    def authorise(self) -> "ErasureRequest":
        """Gate before execution. An erasure that cannot be certified is
        refused unless somebody named has accepted that."""
        blockers = self.blockers()
        if blockers:
            self.state = RequestState.REFUSED
            self.refusal = {
                "cause": blockers[0]["cause"],
                "detail": f"{len(blockers)} store(s) cannot produce a passing "
                          f"attestation; erasing them would delete the data "
                          f"and leave the request permanently open",
                "all": blockers}
        return self

    # ---- Phase 5 -----------------------------------------------------
    def record_execution(self, verdict: str) -> "ErasureRequest":
        self.execution_verdict = verdict
        if self.state is not RequestState.REFUSED:
            self.state = RequestState.AWAITING_VERIFICATION
        return self

    def record_attestation(self, view: AttestationView) -> "ErasureRequest":
        self.attestations[view.store_name] = view
        return self

    def record_vector_execution(self, receipt) -> "ErasureRequest":
        """The deletion half of the vector story. An attestation is a
        statistical claim about retrievability; the receipt is a
        deterministic fact about whether anything was deleted at all. A
        request that has one and not the other is missing a half."""
        self.vector_receipts[receipt.store_name] = receipt.to_dict()
        return self

    def record_structured_check(self, check: StructuredCheck) -> "ErasureRequest":
        self.structured_checks[check.target] = check
        return self

    def verify_all(self, port: ErasureVerifierPort) -> "ErasureRequest":
        for t in sorted(self.vector_targets, key=lambda x: x.store_name):
            self.record_attestation(port.attest(self.subject, t.store_name))
        return self

    # ---- settlement --------------------------------------------------
    def open_causes(self) -> List[dict]:
        """Everything standing between this request and COMPLETE. Empty is
        the only thing that closes it."""
        causes: List[dict] = []

        if self.state is RequestState.REFUSED:
            causes.append({"cause": self.refusal["cause"],
                           "detail": self.refusal["detail"], "scope": "request"})
            return causes

        if self.execution_verdict != "COMPLETE":
            causes.append({
                "cause": CAUSE_EXECUTION_INCOMPLETE, "scope": "execution",
                "detail": f"execution verdict is "
                          f"'{self.execution_verdict or 'none'}', not COMPLETE"})

        for gap in self.uncovered_linked_keys():
            causes.append({"cause": gap["cause"], "scope": gap["key_kind"],
                           "detail": gap["detail"]})

        for t in sorted(self.row_targets, key=lambda x: x.target):
            chk = self.structured_checks.get(t.target)
            if chk is None:
                causes.append({"cause": CAUSE_STRUCTURED_UNCHECKED,
                               "scope": t.target,
                               "detail": "the store was never re-queried for "
                                         "the subject after the delete"})
            elif chk.subject_present is None:
                causes.append({"cause": CAUSE_STRUCTURED_UNCHECKED,
                               "scope": t.target,
                               "detail": chk.detail or "re-query could not run"})
            elif chk.subject_present:
                causes.append({"cause": CAUSE_STRUCTURED_RESIDUE,
                               "scope": t.target,
                               "detail": chk.detail or "subject still returns rows"})

        for t in sorted(self.vector_targets, key=lambda x: x.store_name):
            view = self.attestations.get(t.store_name)
            if view is None:
                causes.append({"cause": CAUSE_NOT_VERIFIED,
                               "scope": t.store_name,
                               "detail": "no attestation has been recorded"})
                continue
            # The attestation must be about THIS subject. Two token
            # schemes existed before the merge and lined up only by hand;
            # a mismatch here means the verifier attested a token no
            # erasure ever used, which reads as success and is not one.
            if self.subject.token_hash:
                if not view.subject_token_hash:
                    causes.append({
                        "cause": CAUSE_TOKEN_ABSENT, "scope": t.store_name,
                        "detail": "the attestation names no subject token, so "
                                  "it cannot be tied to this request"})
                elif view.subject_token_hash != self.subject.token_hash:
                    causes.append({
                        "cause": CAUSE_TOKEN_MISMATCH, "scope": t.store_name,
                        "detail": f"attested token "
                                  f"{view.subject_token_hash[:16]}… is not "
                                  f"this subject's "
                                  f"{self.subject.token_hash[:16]}…"})

            closes, cause, detail = adjudicate(view)
            if not closes:
                causes.append({"cause": cause, "scope": t.store_name,
                               "detail": detail})

            rec = self.vector_receipts.get(t.store_name)
            if rec is None:
                causes.append({
                    "cause": CAUSE_VECTOR_NOT_DELETED, "scope": t.store_name,
                    "detail": "no deletion receipt; an attestation without a "
                              "recorded delete verifies a store nothing "
                              "touched"})
            elif rec.get("still_addressable"):
                # The two kinds of evidence disagree. A passing attestation
                # says the subject is not retrievable; a fetch by id says
                # the records are still there. Whichever is right, closing
                # on the more flattering one is not available.
                causes.append({
                    "cause": CAUSE_VECTOR_CONTRADICTS, "scope": t.store_name,
                    "detail": f"{len(rec['still_addressable'])} record(s) "
                              f"remain fetchable by id while the attestation "
                              f"reads {view.classification}; the two "
                              f"disagree"})
            elif rec.get("verdict") not in ("COMPLETE",):
                causes.append({
                    "cause": CAUSE_VECTOR_NOT_DELETED, "scope": t.store_name,
                    "detail": f"deletion verdict is {rec.get('verdict')}"})
        return causes

    def settle(self) -> RequestState:
        """The hard rule, in one place. COMPLETE requires a clean execution,
        a clean re-query of every structured target, and a passing signed
        attestation for every vector target. Anything else stays open."""
        if self.state is RequestState.REFUSED:
            return self.state
        self.state = (RequestState.COMPLETE if not self.open_causes()
                      else RequestState.AWAITING_VERIFICATION)
        return self.state

    @property
    def closed(self) -> bool:
        return self.state in (RequestState.COMPLETE, RequestState.REFUSED)

    # ---- reporting ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "version": ERASURE_VERSION,
            "subject_key_kind": self.subject.key_kind,
            "subject_token_hash": self.subject.token_hash,
            "state": self.state.value,
            "closed": self.closed,
            "execution_verdict": self.execution_verdict,
            "row_targets": [t.target for t in self.row_targets],
            "vector_targets": [t.store_name for t in self.vector_targets],
            "attestability": [a.to_dict() for a in self.attestability()],
            "accepted_unattestable": self.accepted_unattestable(),
            "attestations": [v.to_dict() for _, v in
                             sorted(self.attestations.items())],
            "structured_checks": [c.to_dict() for _, c in
                                  sorted(self.structured_checks.items())],
            "vector_receipts": [r for _, r in
                                sorted(self.vector_receipts.items())],
            "resolution": (self.resolution.to_dict()
                           if self.resolution is not None else None),
            "additional_subject_tokens": [s.token_hash
                                          for s in self.additional_subjects],
            "uncovered_linked_keys": self.uncovered_linked_keys(),
            "open_causes": self.open_causes(),
            "refusal": self.refusal,
        }

    @property
    def request_hash(self) -> str:
        # The subject key itself never enters the hash — only its token.
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "E-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    def explain(self) -> str:
        lines = [f"{self.state.value} — {len(self.row_targets)} structured "
                 f"target(s), {len(self.vector_targets)} vector store(s)"]
        for a in self.attestability():
            mark = "attestable" if a.attestable else f"NOT attestable ({a.cause})"
            lines.append(f"  {a.store_name} [{a.engine}]: {mark}")
            if not a.attestable:
                lines.append(f"      ceiling: {a.ceiling or 'none'} — {a.detail}")
        for acc in self.accepted_unattestable():
            lines.append(f"  accepted unattestable: {acc['store_name']} "
                         f"by {acc['accepted_by']} — {acc['acceptance_detail']}")
        for c in self.open_causes():
            lines.append(f"  open: {c['cause']} [{c['scope']}] — {c['detail']}")
        if self.state is RequestState.COMPLETE:
            lines.append("  every target carries a passing signed attestation")
        return "\n".join(lines)
