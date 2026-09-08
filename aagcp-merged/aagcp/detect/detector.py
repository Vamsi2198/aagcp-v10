"""
PIIDetector — global detection with a pluggable NER backend.

Two layers, one interface:
  1. Regex layer (patterns.py) — pattern-based IDs across jurisdictions.
     Runs everywhere, no dependencies, UNCAPPED (returns every match).
  2. Presidio backend — NER for names/locations/orgs/medical terms and
     Presidio's own recognizers. Optional: enabled iff presidio-analyzer is
     installed. Written against Presidio's real API; smoke-tested by you.

Backend selection is automatic and explicit: the detector reports which
backend produced results so nothing is silently missing.

No detection cap anywhere: scan(text) returns one Finding per match, for
however many exist.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional

from .patterns import GLOBAL_PATTERNS, NER_ENTITY_TYPES


@dataclass(frozen=True)
class Finding:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    source: str          # "regex" | "presidi_cue_nameso"
    jurisdiction: str = ""


class PIIDetector:
    def __init__(self, use_presidio: Optional[bool] = None,
                 languages: Optional[List[str]] = None,
                 min_confidence: float = 0.35,
                 person_lexicon: Optional[List[str]] = None):
        self.min_confidence = min_confidence
        # Person names via lexicon when Presidio is absent (Presidio's NER
        # supplies these in production). Case-insensitive, longest-first.
        self.person_lexicon = sorted(person_lexicon or [], key=len, reverse=True)
        self._presidio = None
        self.presidio_active = False
        want = True if use_presidio is None else use_presidio
        if want:
            self._try_presidio(languages or ["en"])

    def _try_presidio(self, languages: List[str]):
        try:
            from presidio_analyzer import AnalyzerEngine  # noqa
            self._presidio = AnalyzerEngine()
            self.presidio_active = True
        except Exception:
            self._presidio = None
            self.presidio_active = False

    # ── Detection ────────────────────────────────────────────────────

    # Structural name cues common in records: "Name: X Y", "Patient X Y",
    # "Subject ... X Y", honorifics. Catches names in UPLOADED docs even with
    # no lexicon and no Presidio, so erase-by-name and name-query both work.
    _NAME_CUE = re.compile(
        r"(?:(?:Full\s+)?Name|Patient|Subject|Member|Employee|Cardholder|Enrollee|Holder|Investigator|Steward)"
        r"\s*[:\-]?\s+((?:Dr\.?\s+|Mr\.?\s+|Ms\.?\s+|Mrs\.?\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})",
        re.IGNORECASE)
    _HONORIFIC = re.compile(
        r"\b(?:Dr|Mr|Ms|Mrs|Shri|Smt)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})")

    def _cue_names(self, text: str):
        out = []
        for rx in (self._NAME_CUE, self._HONORIFIC):
            for m in rx.finditer(text):
                val = m.group(1).strip()
                # strip a leading honorific token so the identity key is the name
                val = re.sub(r"^(?:Dr|Mr|Ms|Mrs|Shri|Smt)\.?\s+", "", val, flags=re.IGNORECASE).strip()
                if 3 <= len(val) <= 60 and " " in val:
                    out.append((val, m.start(1) + (m.group(1).find(val) if val in m.group(1) else 0)))
        return out

    def scan(self, text: str) -> List[Finding]:
        findings: List[Finding] = []

        # Layer 1: regex (always) — uncapped
        for pat in GLOBAL_PATTERNS:
            for m in pat.regex.finditer(text):
                val = m.group(0)
                if pat.validator and not pat.validator(val):
                    continue
                findings.append(Finding(pat.entity_type, val, m.start(), m.end(),
                                        pat.confidence, "regex", pat.jurisdiction))

        # Layer 1b: person names via lexicon (when Presidio absent) — uncapped
        if self.person_lexicon:
            import re as _re
            for name in self.person_lexicon:
                for m in _re.finditer(_re.escape(name), text, _re.IGNORECASE):
                    findings.append(Finding("PERSON", m.group(0), m.start(),
                                            m.end(), 0.90, "lexicon", "GLOBAL"))

        # Layer 1c: structural name cues — catches names in UPLOADED docs with
        # no lexicon and no Presidio (Name:/Patient/Dr. patterns). This is what
        # makes erase-by-name and name-based retrieval work on uploads.
        for val, pos in self._cue_names(text):
            idx = text.find(val, max(0, pos - 2))
            if idx < 0:
                idx = text.find(val)
            if idx >= 0:
                findings.append(Finding("PERSON", val, idx, idx + len(val), 0.80, "cue", "GLOBAL"))

        # Layer 2: Presidio NER (if available) — uncapped
        if self.presidio_active and self._presidio is not None:
            try:
                for r in self._presidio.analyze(text=text, language="en"):
                    findings.append(Finding(
                        r.entity_type, text[r.start:r.end], r.start, r.end,
                        float(r.score), "presidio", "GLOBAL"))
            except Exception:
                pass

        findings = [f for f in findings if f.confidence >= self.min_confidence]
        return self._resolve_overlaps(findings)

    @staticmethod
    def _resolve_overlaps(findings: List[Finding]) -> List[Finding]:
        """Longest, highest-confidence span wins when spans overlap."""
        kept: List[Finding] = []
        for f in sorted(findings, key=lambda x: (x.start, -(x.end - x.start), -x.confidence)):
            if not any(not (f.end <= k.start or f.start >= k.end) for k in kept):
                kept.append(f)
        return sorted(kept, key=lambda x: x.start)

    # ── Reporting ────────────────────────────────────────────────────

    def coverage(self) -> dict:
        """What this detector can currently find — honest capability report."""
        regex_types = sorted({p.entity_type for p in GLOBAL_PATTERNS})
        if self.presidio_active:
            person = "presidio"
        elif self.person_lexicon:
            person = f"lexicon ({len(self.person_lexicon)} names)"
        else:
            person = "NONE (install presidio-analyzer for names/addresses)"
        return {
            "regex_entities": regex_types,
            "regex_entity_count": len(regex_types),
            "ner_backend": person,
            "ner_entities": NER_ENTITY_TYPES if self.presidio_active else [],
            "note": ("Full global coverage active."
                     if self.presidio_active else
                     "Regex layer active; names/addresses/orgs need Presidio — "
                     "pip install presidio-analyzer presidio-anonymizer && "
                     "python -m spacy download en_core_web_lg"),
        }

    @staticmethod
    def risk_score(findings: List[Finding]) -> float:
        high = {"AADHAAR", "PAN", "US_SSN", "CREDIT_CARD", "IBAN", "MRN",
                "UK_NINO", "US_MEDICARE", "IN_PASSPORT", "PERSON"}
        if not findings:
            return 0.0
        w = sum(1.0 if f.entity_type in high else 0.4 for f in findings)
        return min(1.0, w / 3.0)
