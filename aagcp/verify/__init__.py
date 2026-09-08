"""Erasure verification — additive module. Nothing else in AAGCP is modified."""
from .erasure_verifier import (  # noqa: F401
    VERSION,
    EngineType,
    ChannelStatus,
    ChannelResult,
    ErasureVerifier,
    SubjectAnchor,
    ErasureBound,
    ErasureAttestation,
    IndexCommitment,
    DeterministicFinding,
    PgVectorInspector,
    AttestationLog,
    clopper_pearson_upper,
    verify_attestation,
    canonical,
    SCOPE_TEXT,
)

from .adapters import PineconeProbeAdapter, MockPineconeIndex  # noqa: F401

__all__ = [
    "PineconeProbeAdapter", "MockPineconeIndex",
    "VERSION", "EngineType", "ChannelStatus", "ChannelResult",
    "ErasureVerifier", "SubjectAnchor", "ErasureBound", "ErasureAttestation",
    "IndexCommitment", "DeterministicFinding", "PgVectorInspector",
    "AttestationLog", "clopper_pearson_upper", "verify_attestation",
    "canonical", "SCOPE_TEXT",
]
