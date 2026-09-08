"""
aagcp/core/subject_resolution.py — who, exactly.

Dinesh measured a 600-record corpus and found 154 names shared by two or
more distinct people, covering 61% of records. Confidence: STATED — that
is his measurement of his corpus, not a constant, and collision_profile()
below exists so a customer computes their own rather than inheriting his.
The shape of the finding is what matters: on real data, a name is not an
identifier, and an erasure keyed on one is a coin toss with somebody
else's record.

THREE THINGS THIS MODULE DOES THAT THE SPEC DID NOT ASK FOR, each because
the version without it would look correct and fail quietly.

1. DISCLOSURE CONTROL ON THE REFUSAL ITSELF.
   "Refuses and names the candidates" is a data breach if the names go to
   the requester. A subject asking to be erased who receives "we found
   three people matching that name, here are their emails" has just been
   handed two other people's personal data by the privacy system. So a
   Resolution has two serialisations that cannot be confused: to_dict()
   is control-plane safe and carries opaque candidate tokens plus the
   NAMES OF the fields that differ, never their values; resolver_view()
   carries masked values, requires a named authority, and is deliberately
   excluded from to_dict() so it cannot reach an audit record by
   accident. There is a test asserting no candidate value appears
   anywhere in the serialised refusal.

2. UNIQUENESS IN A SAMPLE IS NOT UNIQUENESS.
   A name that matches exactly one record in an index nobody asserted was
   complete is not resolved — it is unresolved with a flattering number
   attached. That is Phase 0's denominator problem wearing a different
   hat, and it gets the same treatment: an index whose completeness is
   unasserted can produce AMBIGUOUS_UNVERIFIED but never RESOLVED.

3. THE SYMMETRIC ERROR.
   Collision is one person's request hitting another person's record.
   Fragmentation is one person holding three account ids and the erasure
   touching one of them. The first is a wrongful deletion and it is loud.
   The second closes COMPLETE while the subject is still fully present
   under a key nobody looked up, and it is silent — which makes it the
   more dangerous of the two for a system whose whole claim is that
   nothing disappears without evidence. So resolution returns the linked
   key set, and the erasure request stays open until every linked key is
   covered.

A NAME NEVER RESOLVES ON ITS OWN. Not when it matches once, not when the
index is complete, not when the confidence is high. It resolves when a
corroborating key agrees with it, or when a human with a name attached
picks a candidate. That is the direct reading of "erasing by name is
unsafe" and it is enforced in one place, in _verdict_for.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

RESOLUTION_VERSION = "resolution-1.0.0"


class KeyKind(str, Enum):
    """How much weight a key can carry on its own."""
    SUBJECT_ID = "subject_id"       # unique by construction in the estate
    ACCOUNT = "account"             # unique by construction
    EMAIL = "email"                 # near-unique; shared mailboxes exist
    PHONE = "phone"                 # near-unique; reassigned, shared
    NAME = "name"                   # not an identifier
    DOB = "dob"                     # corroborating only
    POSTCODE = "postcode"           # corroborating only

    @property
    def unique_by_construction(self) -> bool:
        return self in (KeyKind.SUBJECT_ID, KeyKind.ACCOUNT)

    @property
    def can_stand_alone(self) -> bool:
        # EMAIL and PHONE are near-unique, and near-unique is enough to
        # single out a candidate for confirmation but not to authorise an
        # irreversible act on its own — a reassigned number belongs to
        # somebody new.
        return self.unique_by_construction


class ResolutionVerdict(str, Enum):
    RESOLVED = "RESOLVED"
    AMBIGUOUS_SUBJECT = "AMBIGUOUS_SUBJECT"
    AMBIGUOUS_UNVERIFIED = "AMBIGUOUS_UNVERIFIED"
    NOT_FOUND = "NOT_FOUND"
    INDEX_UNAVAILABLE = "INDEX_UNAVAILABLE"

    @property
    def resolved(self) -> bool:
        return self is ResolutionVerdict.RESOLVED


# ---- cause codes -----------------------------------------------------
CAUSE_MULTIPLE_CANDIDATES = "MULTIPLE_DISTINCT_SUBJECTS_MATCH"
CAUSE_NAME_ONLY = "NAME_ALONE_CANNOT_IDENTIFY_A_SUBJECT"
CAUSE_WEAK_KEY_ALONE = "KEY_IS_NOT_UNIQUE_BY_CONSTRUCTION"
CAUSE_INDEX_INCOMPLETE = "IDENTITY_INDEX_COMPLETENESS_NOT_ASSERTED"
CAUSE_INDEX_UNAVAILABLE = "IDENTITY_INDEX_COULD_NOT_ANSWER"
CAUSE_NO_MATCH = "NO_SUBJECT_MATCHED"
CAUSE_CORROBORATED = "CORROBORATED_BY_SECOND_KEY"
CAUSE_UNIQUE_STRONG_KEY = "MATCHED_ON_KEY_UNIQUE_BY_CONSTRUCTION"
CAUSE_HUMAN_SELECTED = "SELECTED_BY_NAMED_RESOLVER"
CAUSE_LINKED_NOT_COVERED = "LINKED_IDENTITY_KEY_NOT_COVERED_BY_ERASURE"
CAUSE_DISCLOSURE_REFUSED = "CANDIDATE_DISCLOSURE_REQUIRES_AUTHORITY"


class ResolutionError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------
# Identity records
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class IdentityRecord:
    """One distinct person as the identity index knows them.

    `keys` maps a KeyKind to the value held for this person. The record
    token is derived from the subject id, so two lookups for the same
    person produce the same opaque handle without the id travelling.
    """
    subject_id: str
    keys: Tuple[Tuple[KeyKind, str], ...]
    source_objects: Tuple[str, ...] = ()

    @property
    def token(self) -> str:
        return "S-" + hashlib.sha256(
            self.subject_id.encode()).hexdigest()[:12].upper()

    def key_map(self) -> Dict[KeyKind, str]:
        return {k: v for k, v in self.keys}

    def get(self, kind: KeyKind) -> Optional[str]:
        return self.key_map().get(kind)


class IdentityIndex(Protocol):
    def lookup(self, kind: KeyKind, value: str) -> Optional[List[IdentityRecord]]:
        """Records matching one key. None — not [] — when the index cannot
        answer. Absence of an answer is not absence of a person."""
        ...

    @property
    def complete(self) -> Optional[bool]:
        """True only when the index asserts it enumerates every subject in
        scope. None means nobody said, which counts as not asserted."""
        ...


class StaticIdentityIndex:
    def __init__(self, records: Sequence[IdentityRecord],
                 complete: Optional[bool] = None,
                 unavailable_kinds: Sequence[KeyKind] = ()):
        self.records = list(records)
        self._complete = complete
        self.unavailable = set(unavailable_kinds)

    @property
    def complete(self) -> Optional[bool]:
        return self._complete

    def lookup(self, kind: KeyKind, value: str) -> Optional[List[IdentityRecord]]:
        if kind in self.unavailable:
            return None
        v = value.strip().casefold()
        return [r for r in self.records
                if (r.get(kind) or "").strip().casefold() == v]


# ---------------------------------------------------------------------
# Candidates and disclosure
# ---------------------------------------------------------------------

def _mask(value: str) -> str:
    """A presentation-layer mask for a resolver's screen. Not a governance
    treatment — the Treatment enum in policy.py compiles to warehouse SQL
    and has nothing to do with rendering a string in a review queue."""
    if "@" in value:
        local, _, domain = value.partition("@")
        dom, _, tld = domain.rpartition(".")
        return f"{local[:1]}{'*' * max(len(local) - 1, 1)}@{dom[:1]}" \
               f"{'*' * max(len(dom) - 1, 1)}.{tld}"
    if len(value) <= 4:
        return "*" * len(value)
    return value[:1] + "*" * (len(value) - 3) + value[-2:]


@dataclass(frozen=True)
class Candidate:
    """What the control plane is allowed to know about one of the people a
    request might be about: an opaque token, and which fields separate
    them from the others. Never a value."""
    token: str
    discriminator_fields: Tuple[str, ...]
    source_objects: Tuple[str, ...] = ()

    def to_dict(self):
        return {"token": self.token,
                "discriminator_fields": list(self.discriminator_fields),
                "source_objects": list(self.source_objects)}


@dataclass(frozen=True)
class ResolverAuthority:
    """Whoever is about to look at other people's data in order to break a
    tie. Named, like every other override in this codebase."""
    authority: str
    reason: str

    def __post_init__(self):
        if not self.authority:
            raise ResolutionError(
                CAUSE_DISCLOSURE_REFUSED,
                "viewing candidate discriminators requires a named "
                "authority; the tie-break exposes other subjects' data")
        if not self.reason:
            raise ResolutionError(CAUSE_DISCLOSURE_REFUSED,
                                  "a disclosure must state its reason")


# ---------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------

@dataclass
class Resolution:
    verdict: ResolutionVerdict
    cause: str
    detail: str
    query: Tuple[Tuple[str, str], ...]       # (kind, MASKED value) — never raw
    candidates: Tuple[Candidate, ...] = ()
    resolved_token: str = ""
    linked_keys: Tuple[Tuple[str, str], ...] = ()   # (kind, value) for the person
    index_complete: Optional[bool] = None
    provenance: Optional[dict] = None
    # Raw records are held for resolver_view() only and never serialised.
    _records: Tuple[IdentityRecord, ...] = field(default=(), repr=False)

    # ---- control-plane serialisation --------------------------------
    def to_dict(self) -> dict:
        """Safe to log, hash, and ship to the control plane. Carries no
        candidate value, and no raw query value."""
        return {
            "version": RESOLUTION_VERSION,
            "verdict": self.verdict.value,
            "cause": self.cause,
            "detail": self.detail,
            "query": [list(q) for q in self.query],
            "candidate_count": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates],
            "resolved_token": self.resolved_token,
            "linked_key_kinds": sorted({k for k, _ in self.linked_keys}),
            "index_complete": self.index_complete,
            "provenance": self.provenance,
        }

    @property
    def resolution_hash(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "R-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    # ---- in-boundary disclosure -------------------------------------
    def resolver_view(self, authority: ResolverAuthority) -> dict:
        """Masked discriminators for a human breaking the tie. Runs inside
        the customer boundary, is not part of to_dict(), and is not
        reachable without an authority object that refuses to construct
        anonymously."""
        if not isinstance(authority, ResolverAuthority):
            raise ResolutionError(CAUSE_DISCLOSURE_REFUSED,
                                  "candidate discriminators require a "
                                  "ResolverAuthority")
        fields = {f for c in self.candidates for f in c.discriminator_fields}
        return {
            "disclosed_to": authority.authority,
            "reason": authority.reason,
            "verdict": self.verdict.value,
            "candidates": [
                {"token": r.token,
                 "discriminators": {k.value: _mask(v) for k, v in r.keys
                                    if k.value in fields},
                 "source_objects": list(r.source_objects)}
                for r in sorted(self._records, key=lambda x: x.token)],
        }

    def select(self, token: str, authority: ResolverAuthority) -> "Resolution":
        """A named human picks one candidate. Produces a RESOLVED result
        carrying who chose and why — the decision does not become anonymous
        by being correct."""
        rec = next((r for r in self._records if r.token == token), None)
        if rec is None:
            raise ResolutionError("UNKNOWN_CANDIDATE",
                                  f"{token} is not among the candidates")
        return Resolution(
            verdict=ResolutionVerdict.RESOLVED, cause=CAUSE_HUMAN_SELECTED,
            detail=f"tie broken by {authority.authority}",
            query=self.query, candidates=(), resolved_token=rec.token,
            linked_keys=tuple(sorted((k.value, v) for k, v in rec.keys)),
            index_complete=self.index_complete,
            provenance={"selected_by": authority.authority,
                        "reason": authority.reason,
                        "from_candidates": [c.token for c in self.candidates],
                        "prior_verdict": self.verdict.value},
            _records=(rec,))

    def explain(self) -> str:
        lines = [f"{self.verdict.value} — {self.cause}", f"  {self.detail}"]
        if self.candidates:
            lines.append(f"  {len(self.candidates)} distinct subject(s) match; "
                         f"they differ on: "
                         f"{', '.join(sorted({f for c in self.candidates for f in c.discriminator_fields}))}")
            for c in self.candidates:
                lines.append(f"    {c.token} seen in "
                             f"{', '.join(c.source_objects) or 'unknown objects'}")
            lines.append("  candidate values are not shown here and are not "
                         "in the audit record; use resolver_view() with a "
                         "named authority inside the boundary")
        if self.linked_keys:
            lines.append(f"  linked keys for this subject: "
                         f"{', '.join(k for k, _ in self.linked_keys)}")
        if self.provenance:
            lines.append(f"  provenance: {self.provenance}")
        return "\n".join(lines)


def _discriminators(records: Sequence[IdentityRecord]) -> Tuple[str, ...]:
    """Which key kinds actually separate these people. A field every
    candidate shares is not a discriminator and naming it would leak
    without helping."""
    kinds = {k for r in records for k, _ in r.keys}
    out = []
    for kind in sorted(kinds, key=lambda k: k.value):
        values = {(r.get(kind) or "").casefold() for r in records}
        values.discard("")
        if len(values) > 1:
            out.append(kind.value)
    return tuple(out)


def resolve(index: IdentityIndex,
            keys: Sequence[Tuple[KeyKind, str]]) -> Resolution:
    """Match a subject from one or more supplied keys.

    Candidates are the INTERSECTION across supplied keys: a second key
    corroborates, it does not widen. Everything after that is about what
    the result is allowed to claim.
    """
    if not keys:
        raise ResolutionError("NO_KEYS", "resolution needs at least one key")

    masked_query = tuple((k.value, _mask(v)) for k, v in keys)
    sets: List[List[IdentityRecord]] = []
    for kind, value in keys:
        hits = index.lookup(kind, value)
        if hits is None:
            return Resolution(
                verdict=ResolutionVerdict.INDEX_UNAVAILABLE,
                cause=CAUSE_INDEX_UNAVAILABLE,
                detail=f"the identity index cannot answer for {kind.value}; "
                       f"an unanswered lookup is not an empty result",
                query=masked_query, index_complete=index.complete)
        sets.append(hits)

    by_token: Dict[str, IdentityRecord] = {}
    common: Optional[set] = None
    for hits in sets:
        tokens = set()
        for r in hits:
            by_token[r.token] = r
            tokens.add(r.token)
        common = tokens if common is None else (common & tokens)
    records = [by_token[t] for t in sorted(common or set())]

    return _verdict_for(records, keys, masked_query, index.complete)


def _verdict_for(records, keys, masked_query,
                 index_complete: Optional[bool]) -> Resolution:
    kinds = [k for k, _ in keys]

    if not records:
        return Resolution(
            verdict=ResolutionVerdict.NOT_FOUND, cause=CAUSE_NO_MATCH,
            detail="no subject matched; this is not the same as a subject "
                   "who has already been erased, and it does not close "
                   "anything",
            query=masked_query, index_complete=index_complete)

    if len(records) > 1:
        disc = _discriminators(records)
        return Resolution(
            verdict=ResolutionVerdict.AMBIGUOUS_SUBJECT,
            cause=CAUSE_MULTIPLE_CANDIDATES,
            detail=f"{len(records)} distinct subjects match these keys; "
                   f"erasing on this input would act on the wrong person",
            query=masked_query,
            candidates=tuple(Candidate(r.token, disc, r.source_objects)
                             for r in records),
            index_complete=index_complete,
            _records=tuple(records))

    rec = records[0]
    linked = tuple(sorted((k.value, v) for k, v in rec.keys))

    # One candidate. Now: is one candidate enough to authorise an
    # irreversible act on this input?
    strong = [k for k in kinds if k.can_stand_alone]
    name_involved = KeyKind.NAME in kinds
    corroborated = len(kinds) > 1

    if name_involved and not strong and not corroborated:
        return Resolution(
            verdict=ResolutionVerdict.AMBIGUOUS_UNVERIFIED,
            cause=CAUSE_NAME_ONLY,
            detail="a name matched exactly one record, which is a property "
                   "of this index rather than of the world; a name never "
                   "resolves a subject on its own",
            query=masked_query,
            candidates=(Candidate(rec.token, _discriminators(records),
                                  rec.source_objects),),
            index_complete=index_complete, _records=(rec,))

    if not strong and not corroborated:
        return Resolution(
            verdict=ResolutionVerdict.AMBIGUOUS_UNVERIFIED,
            cause=CAUSE_WEAK_KEY_ALONE,
            detail=f"{kinds[0].value} is near-unique, not unique by "
                   f"construction; a reassigned number or a shared mailbox "
                   f"belongs to somebody else now",
            query=masked_query,
            candidates=(Candidate(rec.token, _discriminators(records),
                                  rec.source_objects),),
            index_complete=index_complete, _records=(rec,))

    if index_complete is not True:
        # Uniqueness inside a sample is not uniqueness. Same rule Phase 0
        # applies to a coverage denominator.
        return Resolution(
            verdict=ResolutionVerdict.AMBIGUOUS_UNVERIFIED,
            cause=CAUSE_INDEX_INCOMPLETE,
            detail="exactly one match, in an index that does not assert it "
                   "enumerates every subject; a second person carrying the "
                   "same key would be invisible here",
            query=masked_query,
            candidates=(Candidate(rec.token, _discriminators(records),
                                  rec.source_objects),),
            index_complete=index_complete, _records=(rec,))

    return Resolution(
        verdict=ResolutionVerdict.RESOLVED,
        cause=(CAUSE_UNIQUE_STRONG_KEY if strong else CAUSE_CORROBORATED),
        detail=(f"matched on {strong[0].value}, unique by construction"
                if strong else
                f"matched on {len(kinds)} agreeing keys: "
                f"{', '.join(k.value for k in kinds)}"),
        query=masked_query, resolved_token=rec.token, linked_keys=linked,
        index_complete=index_complete, _records=(rec,))


# ---------------------------------------------------------------------
# Collision profiling — measure your own corpus, do not inherit a number
# ---------------------------------------------------------------------

def collision_profile(records: Sequence[IdentityRecord],
                      kind: KeyKind = KeyKind.NAME) -> dict:
    """How unsafe is this key, on this corpus?

    Returns the two numbers that matter: how many values are shared by two
    or more distinct subjects, and what share of subjects sit on a shared
    value. The second is the one that decides whether keying on this field
    is a rare problem or the normal case.
    """
    values = defaultdict(set)
    for r in records:
        v = (r.get(kind) or "").strip().casefold()
        if v:
            values[v].add(r.subject_id)

    shared = {v: ids for v, ids in values.items() if len(ids) > 1}
    subjects_on_shared = {i for ids in shared.values() for i in ids}
    total_subjects = len({r.subject_id for r in records
                          if (r.get(kind) or "").strip()})

    return {
        "key_kind": kind.value,
        "distinct_values": len(values),
        "values_shared_by_multiple_subjects": len(shared),
        "subjects_total": total_subjects,
        "subjects_on_a_shared_value": len(subjects_on_shared),
        "share_of_subjects_on_a_shared_value": (
            len(subjects_on_shared) / total_subjects if total_subjects else None),
        "max_subjects_on_one_value": max((len(i) for i in values.values()),
                                         default=0),
        "safe_to_key_on": len(shared) == 0 and kind.unique_by_construction,
    }
