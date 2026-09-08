"""
aagcp/govern/prompt_guard.py

Prompt-injection governance — as a GOVERNANCE EVENT, not just detection.

The nuance that makes this defensible: everyone claims "we detect prompt
injection." The differentiator here is that injection risk is wired into the
SAME authorization decision as PII reveal — so a suspicious query provably has
its data reveal downgraded or blocked, and that decision is traced. Injection
detection that isn't tied to an enforcement outcome is theatre; this ties it.

This is a heuristic layer (pattern + intent signals). It is honest about being
that: real ML classification is a clean drop-in behind `scan()`. What matters
architecturally is the decision-and-trace wiring, which is model-agnostic.

Signals:
  - instruction override ("ignore previous", "disregard rules", "you are now")
  - exfiltration intent ("list all", "dump", "show every", "reveal all PII")
  - role/privilege escalation ("as admin", "act as compliance officer")
  - encoded payloads (base64-ish blobs, unusual escaping)
  - system-prompt probing ("what are your instructions", "repeat the prompt")

Decision:
  risk < 0.34  -> allow
  0.34–0.66    -> downgrade  (force lowest-privilege reveal regardless of role)
  risk >= 0.67 -> block      (refuse retrieval)
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List

_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|instruction|rule|system|policy|guardrail)s?\b", re.I)
_YOU_ARE_NOW = re.compile(r"\b(you\s+are\s+now|from\s+now\s+on|pretend\s+to\s+be|act\s+as)\b", re.I)
_EXFIL = re.compile(r"\b(list|dump|show|reveal|export|give\s+me|print)\b.{0,20}\b(all|every|entire|full|complete)\b.{0,20}\b(pii|ssn|aadhaar|record|data|customer|patient|user|secret|password|token)s?\b", re.I)
_ESCALATE = re.compile(r"\b(as|become|switch\s+to|elevate\s+to)\b.{0,15}\b(admin|administrator|compliance|root|superuser|officer)\b", re.I)
_PROBE = re.compile(r"\b(what\s+(are|is)\s+your\s+(system\s+)?(instruction|prompt|rule)s?|repeat\s+the\s+(system\s+)?prompt|reveal\s+your\s+(prompt|instruction)|show\s+your\s+(rules|prompt|instructions))\b", re.I)
_ENCODED = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})|(?:\\x[0-9a-f]{2}){4,}", re.I)


@dataclass
class InjectionVerdict:
    risk: float
    decision: str            # allow | downgrade | block
    signals: List[str] = field(default_factory=list)

    def to_attrs(self) -> dict:
        return {"op": "injection_scan", "injection_risk": round(self.risk, 3),
                "decision": self.decision, "signals": self.signals}


def scan(query: str) -> InjectionVerdict:
    q = query or ""
    signals, score = [], 0.0
    checks = [
        (_OVERRIDE, "instruction_override", 0.45),
        (_YOU_ARE_NOW, "persona_switch", 0.30),
        (_EXFIL, "exfiltration_intent", 0.45),
        (_ESCALATE, "privilege_escalation", 0.40),
        (_PROBE, "system_prompt_probe", 0.35),
        (_ENCODED, "encoded_payload", 0.25),
    ]
    for rx, label, weight in checks:
        if rx.search(q):
            signals.append(label)
            score += weight
    score = min(1.0, score)
    decision = "allow" if score < 0.34 else ("downgrade" if score < 0.67 else "block")
    return InjectionVerdict(score, decision, signals)
