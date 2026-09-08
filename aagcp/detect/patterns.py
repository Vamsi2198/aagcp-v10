"""
Global PII pattern library.

Pattern-based identifiers across GDPR (EU), DPDP (India), HIPAA/US, UK, and
common financial standards. These are the entities that HAVE a regex shape.
Entities that do NOT (person names, addresses, organizations, medical
conditions) require NER — handled by the Presidio backend in detector.py.

Every pattern carries a base confidence and, where applicable, a validator
(e.g. Luhn for cards, Verhoeff for Aadhaar) so precision stays high without
capping recall. Nothing here limits how many matches are returned.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Callable, Optional


def _luhn_ok(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if len(digits) < 12:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _verhoeff_ok(num: str) -> bool:
    """Aadhaar checksum (Verhoeff). Reduces false positives on 12-digit runs."""
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
         [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
         [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
         [9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
         [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
         [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    digits = [int(x) for x in re.sub(r"\D", "", num)]
    if len(digits) != 12:
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = d[c][p[i % 8][item]]
    return c == 0


@dataclass(frozen=True)
class Pattern:
    entity_type: str
    jurisdiction: str          # EU | IN | US | UK | GLOBAL | FIN
    regex: re.Pattern
    confidence: float
    validator: Optional[Callable[[str], bool]] = None


# Order matters: stricter/longer identifiers first so a 12-digit Aadhaar is
# not partially consumed as a shorter account number.
GLOBAL_PATTERNS: list[Pattern] = [
    # ── India (DPDP) ────────────────────────────────────────────────
    Pattern("AADHAAR", "IN", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), 0.85, _verhoeff_ok),
    Pattern("PAN", "IN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), 0.95),
    Pattern("IN_VOTER_ID", "IN", re.compile(r"\b[A-Z]{3}\d{7}\b"), 0.75),
    Pattern("IN_PASSPORT", "IN", re.compile(r"\b[A-PR-WY][1-9]\d{6}\b"), 0.70),
    Pattern("IN_DRIVING_LICENCE", "IN", re.compile(r"\b[A-Z]{2}\d{2}\s?\d{11}\b"), 0.75),
    Pattern("IN_PHONE", "IN", re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b"), 0.75),
    Pattern("IN_GSTIN", "IN", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b"), 0.90),

    # ── US (HIPAA / financial) ──────────────────────────────────────
    Pattern("US_SSN", "US", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.90),
    Pattern("US_NPI", "US", re.compile(r"\b\d{10}\b"), 0.55, _luhn_ok),          # provider ID (Luhn w/ prefix)
    Pattern("US_MEDICARE", "US", re.compile(r"\b\d[A-Z]\d{2}-?[A-Z]\d{2}-?[A-Z]{2}\d{2}\b"), 0.80),
    Pattern("US_EIN", "US", re.compile(r"\b\d{2}-\d{7}\b"), 0.70),
    Pattern("US_PHONE", "US", re.compile(r"\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b"), 0.65),

    # ── UK / EU ─────────────────────────────────────────────────────
    Pattern("UK_NHS", "UK", re.compile(r"\b\d{3}\s?\d{3}\s?\d{4}\b"), 0.70),
    Pattern("UK_NINO", "UK", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b"), 0.85),
    Pattern("EU_VAT", "EU", re.compile(r"\b[A-Z]{2}[A-Z0-9]{8,12}\b"), 0.55),
    Pattern("IBAN", "FIN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), 0.85),
    Pattern("SWIFT_BIC", "FIN", re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"), 0.55),

    # ── Financial (global) ──────────────────────────────────────────
    Pattern("CREDIT_CARD", "FIN", re.compile(r"\b(?:\d[ -]?){13,16}\d\b"), 0.75, _luhn_ok),

    # ── Healthcare / pharma (global) ────────────────────────────────
    Pattern("MRN", "GLOBAL", re.compile(r"\bMRN[-:\s]?\d{5,10}\b", re.I), 0.90),
    Pattern("ICD10", "GLOBAL", re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"), 0.45),
    Pattern("NCT_TRIAL", "GLOBAL", re.compile(r"\bNCT\d{8}\b"), 0.90),

    # ── Contact / network (global) ──────────────────────────────────
    Pattern("EMAIL", "GLOBAL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.95),
    Pattern("INTL_PHONE", "GLOBAL", re.compile(r"\+\d{1,3}[\s-]?\d{6,14}\b"), 0.60),
    Pattern("IPV4", "GLOBAL", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 0.60),
    Pattern("IPV6", "GLOBAL", re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I), 0.70),
    Pattern("DOB", "GLOBAL", re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"), 0.55),
]


# Names/locations/orgs/medical-conditions have NO regex shape.
# The Presidio backend (detector.py) supplies these via NER:
NER_ENTITY_TYPES = [
    "PERSON", "LOCATION", "ADDRESS", "ORGANIZATION",
    "NRP",                      # nationality / religion / political
    "MEDICAL_CONDITION", "DATE_TIME", "AGE",
]
