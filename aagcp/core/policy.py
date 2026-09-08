"""
aagcp/core/policy.py — regimes, not categories.

The instinct to "add more PII categories" is the wrong unit. A category
without a treatment tells you nothing: a date of birth is a HIPAA Safe
Harbor identifier that must be generalised to a year, a DPDP personal
data element that may be masked, and under PCI not in scope at all. Same
column, three different correct answers.

So the unit is a regime: a named set of identifiers, each with a stated
treatment and a citation. Adding an Indian voter-ID recognizer is then an
hour inside an existing frame, rather than one more ambiguous entry in a
list of two hundred.

CITATIONS ARE PART OF THE DATA. When an auditor asks why a column was
generalised rather than masked, the answer is a clause reference, not an
engineering preference. Confidence: the identifier lists below follow the
published texts, but a customer's counsel decides scope — treat these as
defaults to be reviewed, not legal advice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Treatment(str, Enum):
    REDACT = "redact"                # replace with a constant
    MASK_PARTIAL = "mask_partial"    # keep a suffix, e.g. last four
    TOKENIZE = "tokenize"            # deterministic surrogate; joins survive
    GENERALIZE = "generalize"        # reduce precision: date -> year, zip -> 3 digits
    HASH = "hash"                    # one-way, keyed
    DROP = "drop"                    # remove the column entirely
    RETAIN = "retain"                # explicitly in scope and deliberately kept


@dataclass(frozen=True)
class Identifier:
    key: str                         # stable id, used in plans and receipts
    label: str
    treatment: Treatment
    citation: str                    # the clause this treatment answers to
    detectors: tuple = ()            # Presidio entity names / recognizer keys
    column_hints: tuple = ()         # lowercase substrings for column matching
    note: str = ""


@dataclass(frozen=True)
class Policy:
    policy_id: str
    name: str
    authority: str
    identifiers: tuple
    default_treatment: Treatment = Treatment.REDACT
    closed_list: bool = False        # True when the regime enumerates exhaustively
    note: str = ""

    def by_key(self) -> Dict[str, Identifier]:
        return {i.key: i for i in self.identifiers}

    def match_column(self, column_name: str) -> Optional[Identifier]:
        """Hint-based match. Never authoritative on its own — the detector
        result from ANALYZE decides; this only proposes."""
        c = column_name.lower()
        best = None
        for ident in self.identifiers:
            for hint in ident.column_hints:
                if hint in c and (best is None or len(hint) > best[0]):
                    best = (len(hint), ident)
        return best[1] if best else None


# ---------------------------------------------------------------------
# HIPAA — 45 CFR 164.514(b)(2), the Safe Harbor method. Eighteen
# identifiers, exhaustively enumerated. This is the only regime here
# whose list is closed, which is why it is the easiest to defend.
# ---------------------------------------------------------------------

HIPAA_SAFE_HARBOR = Policy(
    policy_id="hipaa_safe_harbor",
    name="HIPAA Safe Harbor de-identification",
    authority="45 CFR 164.514(b)(2)",
    closed_list=True,
    note="All eighteen identifiers must be removed or generalised for the "
         "result to be de-identified. Partial application does not qualify.",
    identifiers=(
        Identifier("name", "Names", Treatment.TOKENIZE, "164.514(b)(2)(i)(A)",
                   ("PERSON",), ("name", "fname", "lname", "surname")),
        Identifier("geo", "Geographic subdivisions smaller than a state",
                   Treatment.GENERALIZE, "164.514(b)(2)(i)(B)",
                   ("LOCATION",), ("addr", "address", "city", "zip", "postal"),
                   note="ZIP generalised to the first three digits, and to 000 "
                        "where that unit has 20,000 or fewer people."),
        Identifier("dates", "All elements of dates except year",
                   Treatment.GENERALIZE, "164.514(b)(2)(i)(C)",
                   ("DATE_TIME",), ("dob", "birth", "admit", "discharge", "death"),
                   note="Ages over 89 aggregate into a single 90+ category."),
        Identifier("phone", "Telephone numbers", Treatment.MASK_PARTIAL,
                   "164.514(b)(2)(i)(D)", ("PHONE_NUMBER",), ("phone", "mobile", "tel")),
        Identifier("fax", "Fax numbers", Treatment.REDACT,
                   "164.514(b)(2)(i)(E)", (), ("fax",)),
        Identifier("email", "Email addresses", Treatment.TOKENIZE,
                   "164.514(b)(2)(i)(F)", ("EMAIL_ADDRESS",), ("email", "mail")),
        Identifier("ssn", "Social security numbers", Treatment.REDACT,
                   "164.514(b)(2)(i)(G)", ("US_SSN",), ("ssn", "social")),
        Identifier("mrn", "Medical record numbers", Treatment.TOKENIZE,
                   "164.514(b)(2)(i)(H)", (), ("mrn", "medical_record", "chart")),
        Identifier("beneficiary", "Health plan beneficiary numbers",
                   Treatment.TOKENIZE, "164.514(b)(2)(i)(I)", (), ("beneficiary", "member_id")),
        Identifier("account", "Account numbers", Treatment.TOKENIZE,
                   "164.514(b)(2)(i)(J)", (), ("account", "acct")),
        Identifier("license", "Certificate and licence numbers",
                   Treatment.REDACT, "164.514(b)(2)(i)(K)", (), ("license", "licence")),
        Identifier("vehicle", "Vehicle identifiers and serial numbers",
                   Treatment.REDACT, "164.514(b)(2)(i)(L)", (), ("vin", "plate")),
        Identifier("device", "Device identifiers and serial numbers",
                   Treatment.REDACT, "164.514(b)(2)(i)(M)", (), ("device_id", "serial")),
        Identifier("url", "Web URLs", Treatment.REDACT,
                   "164.514(b)(2)(i)(N)", ("URL",), ("url", "website")),
        Identifier("ip", "IP addresses", Treatment.GENERALIZE,
                   "164.514(b)(2)(i)(O)", ("IP_ADDRESS",), ("ip", "ip_addr")),
        Identifier("biometric", "Biometric identifiers",
                   Treatment.DROP, "164.514(b)(2)(i)(P)", (), ("fingerprint", "biometric")),
        Identifier("photo", "Full-face photographs and comparable images",
                   Treatment.DROP, "164.514(b)(2)(i)(Q)", (), ("photo", "image")),
        Identifier("other_unique", "Any other unique identifying number or code",
                   Treatment.TOKENIZE, "164.514(b)(2)(i)(R)", (), (),
                   note="The catch-all. Anything singling out an individual "
                        "falls here, which is why this policy can never be "
                        "fully automated without review."),
    ),
)

# ---------------------------------------------------------------------
# DPDP — India. The Act defines personal data by relation to an
# identifiable individual and does NOT enumerate. So this list is a
# working default for the Indian identifier space, not a legal closed set.
# ---------------------------------------------------------------------

DPDP = Policy(
    policy_id="dpdp",
    name="DPDP Act personal data",
    authority="Digital Personal Data Protection Act 2023, s.2(t)",
    closed_list=False,
    note="DPDP defines personal data by relation to an identifiable "
         "individual rather than by enumeration. This list is a working "
         "default and must be reviewed against the fiduciary's own mapping.",
    identifiers=(
        Identifier("aadhaar", "Aadhaar number", Treatment.TOKENIZE,
                   "DPDP s.2(t); Aadhaar Act s.29",
                   ("IN_AADHAAR",), ("aadhaar", "aadhar", "uid"),
                   note="Aadhaar carries its own statutory restrictions "
                        "beyond DPDP; storage of the raw number is "
                        "separately constrained."),
        Identifier("pan", "Permanent Account Number", Treatment.TOKENIZE,
                   "DPDP s.2(t)", ("IN_PAN",), ("pan",)),
        Identifier("voter_id", "Voter ID / EPIC", Treatment.TOKENIZE,
                   "DPDP s.2(t)", ("IN_VOTER",), ("voter", "epic")),
        Identifier("passport", "Passport number", Treatment.TOKENIZE,
                   "DPDP s.2(t)", ("IN_PASSPORT",), ("passport",)),
        Identifier("name", "Name", Treatment.TOKENIZE, "DPDP s.2(t)",
                   ("PERSON",), ("name",)),
        Identifier("phone", "Mobile number", Treatment.MASK_PARTIAL,
                   "DPDP s.2(t)", ("PHONE_NUMBER",), ("phone", "mobile")),
        Identifier("email", "Email address", Treatment.TOKENIZE,
                   "DPDP s.2(t)", ("EMAIL_ADDRESS",), ("email",)),
        Identifier("bank", "Bank account / IBAN", Treatment.TOKENIZE,
                   "DPDP s.2(t)", ("IBAN_CODE",), ("iban", "account")),
        Identifier("address", "Postal address", Treatment.GENERALIZE,
                   "DPDP s.2(t)", ("LOCATION",), ("addr", "address")),
        Identifier("dob", "Date of birth", Treatment.GENERALIZE,
                   "DPDP s.2(t)", ("DATE_TIME",), ("dob", "birth")),
    ),
)

# ---------------------------------------------------------------------
# PCI DSS — narrow on purpose. The PAN is the account data; the sensitive
# authentication data must not be stored after authorisation at all,
# which is why it is DROP rather than a masking treatment.
# ---------------------------------------------------------------------

PCI_DSS = Policy(
    policy_id="pci_dss",
    name="PCI DSS cardholder data",
    authority="PCI DSS v4.0, Requirement 3",
    closed_list=True,
    note="Requirement 3.3 forbids storing sensitive authentication data "
         "after authorisation. That is a deletion obligation, not a "
         "masking one, so those identifiers are DROP.",
    identifiers=(
        Identifier("pan", "Primary account number", Treatment.MASK_PARTIAL,
                   "PCI DSS 3.4", ("CREDIT_CARD",), ("card", "pan", "cc_num"),
                   note="At most the first six and last four digits may be "
                        "displayed."),
        Identifier("cardholder_name", "Cardholder name", Treatment.TOKENIZE,
                   "PCI DSS 3.3", ("PERSON",), ("cardholder", "name")),
        Identifier("expiry", "Expiration date", Treatment.RETAIN,
                   "PCI DSS 3.3", (), ("expiry", "exp_date")),
        Identifier("cav2", "Card verification value", Treatment.DROP,
                   "PCI DSS 3.3.1", (), ("cvv", "cvc", "cav2", "cid")),
        Identifier("pin", "PIN / PIN block", Treatment.DROP,
                   "PCI DSS 3.3.1", (), ("pin",)),
        Identifier("track", "Full track data", Treatment.DROP,
                   "PCI DSS 3.3.1", (), ("track", "magstripe")),
    ),
)

# ---------------------------------------------------------------------
# GDPR — like DPDP, defines by relation rather than enumeration. Article 9
# special categories get the stricter default.
# ---------------------------------------------------------------------

GDPR = Policy(
    policy_id="gdpr",
    name="GDPR personal data",
    authority="Regulation (EU) 2016/679, Art. 4(1) and Art. 9",
    closed_list=False,
    note="Art. 9 special-category data (health, biometric, racial or ethnic "
         "origin, political opinion, religion, union membership, sex life or "
         "orientation) carries a stricter basis and defaults to DROP here.",
    identifiers=(
        Identifier("name", "Name", Treatment.TOKENIZE, "Art. 4(1)",
                   ("PERSON",), ("name",)),
        Identifier("email", "Email address", Treatment.TOKENIZE, "Art. 4(1)",
                   ("EMAIL_ADDRESS",), ("email",)),
        Identifier("national_id", "National identification number",
                   Treatment.TOKENIZE, "Art. 87", (), ("national_id", "nin", "nino")),
        Identifier("location", "Location data", Treatment.GENERALIZE,
                   "Art. 4(1)", ("LOCATION",), ("addr", "address", "geo", "lat", "lon")),
        Identifier("online_id", "Online identifiers", Treatment.HASH,
                   "Art. 4(1), Recital 30", ("IP_ADDRESS",), ("ip", "cookie", "device_id")),
        Identifier("special_category", "Art. 9 special categories",
                   Treatment.DROP, "Art. 9(1)", (),
                   ("health", "diagnosis", "religion", "ethnicity", "union",
                    "biometric", "orientation")),
    ),
)


REGISTRY: Dict[str, Policy] = {
    p.policy_id: p for p in (HIPAA_SAFE_HARBOR, DPDP, PCI_DSS, GDPR)
}


def register(policy: Policy) -> None:
    """Customer-specific regimes. Same shape, same citations required."""
    if not policy.identifiers:
        raise ValueError("a policy with no identifiers governs nothing")
    for i in policy.identifiers:
        if not i.citation:
            raise ValueError(f"identifier '{i.key}' has no citation; "
                             "every treatment must answer to a clause")
    REGISTRY[policy.policy_id] = policy


def describe_registry() -> str:
    lines = []
    for p in REGISTRY.values():
        kind = "closed list" if p.closed_list else "open definition"
        lines.append(f"{p.policy_id:20s} {p.name} — {p.authority} "
                     f"({len(p.identifiers)} identifiers, {kind})")
    return "\n".join(lines)
