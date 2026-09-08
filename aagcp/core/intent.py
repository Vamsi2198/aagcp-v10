"""
aagcp/core/intent.py — the layer that keeps the model away from DDL.

A governance instruction has four slots and no more:

    scope     which objects        schema / table / tag / estate
    policy    which rule set       hipaa_safe_harbor / dpdp / pci_dss / gdpr
    action    what to do           mask / tokenize / erase / report
    audience  who keeps access     role names

The language model fills the slots. It never writes SQL, never names a
column, never decides a treatment. Everything after this file is
deterministic, which is what makes a receipt reproducible: the same
Intent always compiles to the same plan and the same statements.

That constraint is the point. If the model generated DDL directly you
could not re-derive an attestation a year later, you could not test the
compiler without a model, and every new warehouse would be another round
of prompt engineering instead of a template file.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Action(str, Enum):
    MASK = "mask"            # reversible for privileged roles
    TOKENIZE = "tokenize"    # deterministic surrogate, joins survive
    ERASE = "erase"          # irreversible; always goes through the verifier
    REPORT = "report"        # read-only; never mutates


class ScopeKind(str, Enum):
    ESTATE = "estate"        # everything reachable
    DATABASE = "database"
    SCHEMA = "schema"
    TABLE = "table"
    TAG = "tag"              # objects carrying a catalog tag
    SUBJECT = "subject"      # one data subject, for DSR work


# Actions that can never be applied without an approval, whatever the
# forecast says. G2: a clean simulation lowers the tier, it does not
# authorise. Erasure is irreversible by definition.
ALWAYS_REQUIRES_APPROVAL = {Action.ERASE}

# Actions the executor is forbidden to run in one transaction across the
# whole estate. Bulk is only safe behind a canary.
REQUIRES_STAGED_EXECUTION = {Action.MASK, Action.TOKENIZE, Action.ERASE}


@dataclass(frozen=True)
class Scope:
    kind: ScopeKind
    value: str = ""                      # "SALES.PUBLIC", "orders", "pii", subject id
    exclude: tuple = ()                  # object names explicitly out of scope

    def describe(self) -> str:
        if self.kind is ScopeKind.ESTATE:
            base = "the whole estate"
        else:
            base = f"{self.kind.value} {self.value}"
        return base + (f" excluding {', '.join(self.exclude)}" if self.exclude else "")


@dataclass(frozen=True)
class Intent:
    action: Action
    scope: Scope
    policy_id: str                       # resolved against the policy registry
    audience: tuple = ()                 # roles retaining cleartext access
    requested_by: str = "unknown"
    utterance: str = ""                  # original text, for the audit record only
    confidence: float = 1.0              # slot-filling confidence, 0..1

    # ---- identity -------------------------------------------------
    @property
    def intent_id(self) -> str:
        body = json.dumps({
            "a": self.action.value,
            "s": [self.scope.kind.value, self.scope.value, sorted(self.scope.exclude)],
            "p": self.policy_id,
            "au": sorted(self.audience),
        }, sort_keys=True, separators=(",", ":"))
        return "I-" + hashlib.sha256(body.encode()).hexdigest()[:12].upper()

    @property
    def requires_approval(self) -> bool:
        return self.action in ALWAYS_REQUIRES_APPROVAL

    @property
    def requires_staging(self) -> bool:
        return self.action in REQUIRES_STAGED_EXECUTION

    def describe(self) -> str:
        aud = f", cleartext retained for {', '.join(self.audience)}" if self.audience else ""
        return f"{self.action.value} {self.policy_id} across {self.scope.describe()}{aud}"

    def to_dict(self):
        d = asdict(self)
        d["action"] = self.action.value
        d["scope"]["kind"] = self.scope.kind.value
        d["intent_id"] = self.intent_id
        d["describes"] = self.describe()
        return d


class IntentError(ValueError):
    """Raised when slots cannot be filled unambiguously. Never guessed past."""

    def __init__(self, code: str, detail: str, candidates=()):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.candidates = list(candidates)


# ---------------------------------------------------------------------
# Slot validation. Runs on whatever produced the slots — model, form, or
# API call — so a malformed Intent can never reach the planner.
# ---------------------------------------------------------------------

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)*$")


def validate(intent: Intent, policy_registry, min_confidence: float = 0.75) -> Intent:
    if intent.policy_id not in policy_registry:
        raise IntentError(
            "UNKNOWN_POLICY",
            f"'{intent.policy_id}' is not a registered policy",
            candidates=sorted(policy_registry.keys()))

    if intent.scope.kind is not ScopeKind.ESTATE and not intent.scope.value:
        raise IntentError("SCOPE_INCOMPLETE",
                          f"scope kind '{intent.scope.kind.value}' needs a value")

    if intent.scope.kind in (ScopeKind.DATABASE, ScopeKind.SCHEMA, ScopeKind.TABLE):
        if not IDENT.match(intent.scope.value):
            raise IntentError("SCOPE_NOT_AN_IDENTIFIER",
                              f"'{intent.scope.value}' is not a valid object name")

    if intent.action is Action.ERASE and intent.scope.kind is not ScopeKind.SUBJECT:
        # Erasure is a data-subject right. Erasing a table is a different
        # operation with a different legal basis and a different approval.
        raise IntentError("ERASE_SCOPE_MUST_BE_SUBJECT",
                          "erase applies to a data subject, not to objects")

    if intent.confidence < min_confidence:
        raise IntentError(
            "LOW_CONFIDENCE",
            f"slot confidence {intent.confidence:.2f} below {min_confidence:.2f}; "
            f"confirm the intent rather than acting on it")

    return intent


# ---------------------------------------------------------------------
# The model-facing contract. The provider returns JSON for these slots
# and nothing else — no SQL, no column names, no treatments.
# ---------------------------------------------------------------------

SLOT_SCHEMA = {
    "action": [a.value for a in Action],
    "scope_kind": [s.value for s in ScopeKind],
    "scope_value": "string, empty when scope_kind is 'estate'",
    "scope_exclude": "array of object names, may be empty",
    "policy_id": "one of the registered policy ids, supplied in the prompt",
    "audience": "array of role names that keep cleartext access, may be empty",
    "confidence": "number 0..1, your confidence that these slots match the request",
}

SYSTEM_PROMPT = """You extract governance slots. You never write SQL, never
name columns, and never choose how data is treated — the policy registry
decides that.

Return ONLY a JSON object with these keys: action, scope_kind, scope_value,
scope_exclude, policy_id, audience, confidence.

If the request is ambiguous — you cannot tell which policy applies, or which
objects are meant — return your best slots with a confidence below 0.75. Do
not guess a policy. An ambiguous request is confirmed with a human, not
resolved by you.
"""


def from_slots(slots: dict, policy_registry, utterance: str = "",
               requested_by: str = "unknown", min_confidence: float = 0.75) -> Intent:
    """Turn a provider's JSON into a validated Intent, or raise."""
    try:
        action = Action(slots["action"])
        kind = ScopeKind(slots["scope_kind"])
    except (KeyError, ValueError) as exc:
        raise IntentError("SLOTS_MALFORMED", str(exc)) from exc

    intent = Intent(
        action=action,
        scope=Scope(kind=kind,
                    value=(slots.get("scope_value") or "").strip(),
                    exclude=tuple(slots.get("scope_exclude") or ())),
        policy_id=(slots.get("policy_id") or "").strip(),
        audience=tuple(slots.get("audience") or ()),
        requested_by=requested_by,
        utterance=utterance,
        confidence=float(slots.get("confidence", 1.0)),
    )
    return validate(intent, policy_registry, min_confidence)
