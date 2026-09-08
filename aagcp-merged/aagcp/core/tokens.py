"""
aagcp/core/tokens.py — one authority for what a subject is called.

Before the merge there were two schemes for the same thing.
core.subject_resolution minted `S-20E1A527CCCB` from a SHA of the subject
id; aagcp.vault.PseudonymVault minted `<PERSON_c9a744da9f63cff2>` from a
keyed HMAC. Both were "the subject's token". `Subject.token_hash` is what
ties an attestation to a person, and in the live test the two lined up
only because I passed the vault's value by hand. Hand it the resolution
token instead and the attestation silently belongs to nobody — the
verifier would happily attest a token that no erasure ever used.

That is the merge failure this file exists to remove. There is now one
authority, and one cross-check.

WHY THE VAULT WINS. Its token is keyed, so it cannot be reversed by
guessing subject ids from a dictionary — a SHA of "subj-0001" is
recoverable by anyone who can enumerate the id space, which for a
sequential customer id is everyone. The resolution token was never
intended as a pseudonym and became one by being in the right field.

THE CROSS-CHECK IS THE PART THAT MATTERS. An authority nobody verifies
against is a convention. ErasureRequest now refuses to close when an
attestation's subject_token_hash does not match the subject it was
supposed to be about, so a mismatch is loud rather than silent.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional, Protocol

TOKEN_VERSION = "token-1.0.0"

CAUSE_NO_AUTHORITY = "SUBJECT_TOKEN_HAS_NO_AUTHORITY"
CAUSE_TOKEN_MISMATCH = "ATTESTATION_IS_FOR_A_DIFFERENT_SUBJECT_TOKEN"


class TokenAuthority(Protocol):
    """Mints the one handle a subject is known by across every plane."""
    name: str

    def token_for(self, subject_key: str, key_kind: str = "") -> str: ...


@dataclass
class KeyedTokenAuthority:
    """Stdlib HMAC-SHA256, for deployments not running the vault. The
    secret is the whole security property: with it the mapping is
    reversible by brute force over the id space, without it nothing is.
    """
    secret: bytes
    name: str = "keyed-hmac"

    def __post_init__(self):
        if not self.secret or len(self.secret) < 32:
            raise ValueError(
                "a subject-token secret shorter than 32 bytes is not a "
                "secret; an unkeyed digest of a sequential customer id is "
                "reversible by anyone who can count")

    def token_for(self, subject_key: str, key_kind: str = "") -> str:
        return hmac.new(self.secret,
                        f"{key_kind}|{subject_key}".encode(),
                        hashlib.sha256).hexdigest()


class VaultTokenAuthority:
    """Delegates to aagcp.vault.PseudonymVault so the token in a Subject is
    the same token the verifier anchored. Imported lazily: aagcp.core is
    stdlib-only and the vault is not."""

    name = "pseudonym-vault"

    def __init__(self, vault, entity_type: str = "PERSON"):
        self.vault = vault
        self.entity_type = entity_type

    def token_for(self, subject_key: str, key_kind: str = "") -> str:
        from ..detect.detector import Finding as SpanFinding
        finding = SpanFinding(self.entity_type, subject_key, 0,
                              len(subject_key), 1.0, "aagcp.core", "")
        return str(self.vault.token_for(finding, subject_key, subject_key))


def bind(subject_key: str, authority: Optional[TokenAuthority],
         key_kind: str = "") -> str:
    if authority is None:
        raise ValueError(
            f"{CAUSE_NO_AUTHORITY}: minting a subject token without a named "
            f"authority is how two schemes for the same subject appear")
    return authority.token_for(subject_key, key_kind)
