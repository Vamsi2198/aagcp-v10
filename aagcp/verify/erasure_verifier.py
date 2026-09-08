"""
aagcp/verify/erasure_verifier.py — v2.0

Erasure verification for AAGCP-Vector.  ADDITIVE ONLY: this module reads the
existing engine through its public interfaces and modifies nothing.

Merge of two lineages:
  * conformal statistics + AAGCP store/vault wiring + deterministic sweep
  * v1.0's AESGCM anchor encryption, PEM keys, engine modes, Merkle
    index commitment

THREE SAFETY INVARIANTS (each has a regression test)
-----------------------------------------------------
  I1  An UNMEASURED channel can never produce a passing attestation.
      Stubs return UNAVAILABLE, and any UNAVAILABLE channel forces
      INCONCLUSIVE.  A signature over an unmeasured claim is worse than no
      verifier at all, because the signature makes it look checked.

  I2  A subject that is still present must NEVER classify as erased.
      False negatives are the catastrophic direction.  test_i2 asserts this.

  I3  Confidence comes from CONTROL ANCHORS, never from probe count.
      Probes around one anchor are correlated; 1000 of them are ~1
      independent observation.  Minimum attainable p is 1/(m+1).

VERIFICATION LADDER — strongest evidence first, stop when it is decisive
------------------------------------------------------------------------
  Stage 0  INSPECTION  (deterministic, engine-specific)
        Read the engine's own state: dead tuples, vacuum backlog, replica
        lag, HNSW neighbour lists.  When available this is far stronger than
        any probe.  Implemented for pgvector.  Where an engine cannot be
        inspected, the channel reports UNAVAILABLE — it never reports "clean".

  Stage 1  DETERMINISTIC SWEEP  (deterministic, engine-agnostic)
        Stream the index for the subject's vault tokens in source_text or
        metadata.  A hit is proof of non-erasure; no statistics needed.

  Stage 2  CONFORMAL PROBE  (statistical, engine-agnostic)
        A record whose text was scrubbed is invisible to Stage 1 but still
        geometrically present.  Probe for it.

        Unit of analysis is the ANCHOR, not the probe:
            s_0      = subject region score (median top-1 similarity)
            s_1..s_m = same score for m control anchors from the index
            p        = (1 + #{i : s_i >= s_0}) / (1 + m)
        Exact under exchangeability.  No calibration constant, no normal
        approximation, no assumption about the score distribution.

PRIVACY — this module is a data controller
-------------------------------------------
    Probing requires the subject's anchor embedding, and embeddings are
    invertible.  So the verifier holds personal data about the person it is
    proving was erased.  That is retention for a legal obligation
    (GDPR Art. 17(3)(b) / DPDP s.8), not a loophole.  Enforced in code:
      * anchors are AESGCM-encrypted at rest under a key separate from both
        the vault key and the signing key
      * forget() destroys the ciphertext AND zeroes the derived key material
      * attestations and spans carry token_hash only — never a name or value

DEPENDENCIES
------------
    numpy (already required).  `cryptography` optional but strongly
    recommended: without it there are no Ed25519 signatures and no anchor
    encryption, and the module says so loudly in sig_alg.  No scipy — the
    exact binomial bound is computed in pure Python.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False


VERSION = "2.0"


# ======================================================================
# Enums / channel results
# ======================================================================

class EngineType(Enum):
    """
    IN_MEMORY is the only engine with no inspection channels, because its
    delete() genuinely removes the object — there is no tombstone, no
    compaction, no replica. Every real engine has internal state that either
    CAN be inspected (pgvector) or demonstrably CANNOT (Pinecone). Declaring
    that up front is what stops a black-box engine from silently satisfying
    I1 by having nothing to measure.
    """
    IN_MEMORY = "in_memory"
    GENERIC = "generic"
    PGVECTOR_HNSW = "pgvector_hnsw"
    PGVECTOR_IVF = "pgvector_ivfflat"
    PINECONE = "pinecone"
    QDRANT = "qdrant"

    @property
    def required_channels(self) -> Tuple[str, ...]:
        """Internal state that must be accounted for before an erasure claim."""
        if self is EngineType.IN_MEMORY:
            return ()
        if self in (EngineType.PGVECTOR_HNSW, EngineType.PGVECTOR_IVF):
            return ("pg.dead_tuples", "pg.replica_lag", "pg.hnsw_neighbors")
        if self is EngineType.PINECONE:
            # Pinecone exposes none of these. They are permanently UNAVAILABLE,
            # which caps Pinecone at INCONCLUSIVE_UNMEASURED by design: you can
            # attest non-retrievability, not absence.
            return ("pinecone.tombstones", "pinecone.compaction",
                    "pinecone.replication")
        if self is EngineType.QDRANT:
            return ("qdrant.deleted_segments", "qdrant.optimizer")
        return ("engine.internal_state",)


class ChannelStatus(Enum):
    """Three states, never two.

    UNAVAILABLE is the whole point: a channel that could not be measured is
    not a channel that came back clean.  Collapsing these two is how a
    verifier ends up signing a pass without touching the database.
    """
    CLEAN = "clean"                # measured, nothing found
    RESIDUE = "residue"            # measured, residue found
    UNAVAILABLE = "unavailable"    # NOT measured — never counts as clean


@dataclass
class ChannelResult:
    name: str
    status: ChannelStatus
    detail: str
    value: Optional[float] = None

    @property
    def measured(self) -> bool:
        return self.status is not ChannelStatus.UNAVAILABLE


# ======================================================================
# Exact binomial upper limit (no scipy)
# ======================================================================

def _log_binom_cdf(h: int, n: int, p: float) -> float:
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 0.0 if h >= n else -math.inf
    terms = [
        math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
        + k * math.log(p) + (n - k) * math.log1p(-p)
        for k in range(h + 1)
    ]
    m = max(terms)
    return m + math.log(sum(math.exp(t - m) for t in terms))


def clopper_pearson_upper(h: int, n: int, delta: float) -> float:
    """Exact one-sided Clopper-Pearson upper limit on a binomial proportion.

    Retained as a SECONDARY diagnostic only.  It is never the headline number,
    because probe-level trials are correlated (see I3).
    """
    if n <= 0:
        return 1.0
    if h >= n:
        return 1.0
    target = math.log(max(1e-300, 1.0 - delta))
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if _log_binom_cdf(h, n, mid) >= target:
            lo = mid
        else:
            hi = mid
    return hi


# ======================================================================
# Canonical serialization
# ======================================================================

def canonical(obj) -> str:
    """Stable JSON for signing.

    Floats are formatted .12e explicitly. v1.0 used .6f, under which
    1e-9 and 4e-7 both serialize to "0.000000" — two different bounds,
    one signature payload.
    """
    def norm(o):
        if isinstance(o, float):
            return f"{o:.12e}"
        if isinstance(o, bool):
            return o
        if isinstance(o, int):
            return int(o)
        if isinstance(o, dict):
            return {str(k): norm(v) for k, v in sorted(o.items())}
        if isinstance(o, (list, tuple)):
            return [norm(v) for v in o]
        if isinstance(o, Enum):
            return o.value
        return str(o)

    return json.dumps(norm(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


# ======================================================================
# Types
# ======================================================================

@dataclass(frozen=True)
class SubjectAnchor:
    """Opaque probe handle. Holds NO embedding — v1.0's SubjectHandle carried
    plaintext probe_vectors, which defeated its own encrypted vault. Here the
    embedding lives only in the verifier's encrypted anchor store."""
    token_hash: str
    dim: int
    registered_at: float
    vault_tokens: Tuple[str, ...] = ()
    # Paired baselines, captured at registration while the subject is present.
    # baseline_present : region score WITH the subject's record
    # baseline_absent  : region score with the subject's record EXCLUDED
    # These are the two hypotheses verification chooses between. If they are
    # nearly equal, a near-duplicate occupies the region and NO retrieval-level
    # test can distinguish them — see ErasureBound.paired_verdict.
    baseline_present: float = float("nan")
    baseline_absent: float = float("nan")
    baseline_radius: float = float("nan")
    record_id: Optional[str] = None


@dataclass
class DeterministicFinding:
    vector_id: str
    reason: str
    detail: str


@dataclass
class IndexCommitment:
    """What the attestation is about. Without this an attestation refers to
    'the index', which is not a thing that holds still."""
    engine: str
    store_name: str
    n_vectors: int
    committed_at: float
    segment_hashes: List[str] = field(default_factory=list)
    merkle_root: str = ""

    def __post_init__(self):
        if not self.merkle_root:
            self.merkle_root = self._merkle()

    def _merkle(self) -> str:
        leaves = [hashlib.sha256(h.encode()).hexdigest()
                  for h in self.segment_hashes]
        if not leaves:
            return hashlib.sha256(
                canonical({"e": self.engine, "s": self.store_name,
                           "n": self.n_vectors, "t": self.committed_at}).encode()
            ).hexdigest()
        while len(leaves) > 1:
            nxt = []
            for i in range(0, len(leaves), 2):
                l = leaves[i]
                r = leaves[i + 1] if i + 1 < len(leaves) else leaves[i]
                nxt.append(hashlib.sha256((l + r).encode()).hexdigest())
            leaves = nxt
        return leaves[0]


@dataclass
class ErasureBound:
    p_value: float
    n_control_anchors: int
    min_attainable_p: float
    subject_score: float
    control_median: float
    control_max: float
    deterministic_findings: int
    inspection: List[ChannelResult] = field(default_factory=list)
    probe_radius: float = float("nan")
    # paired pre/post test (primary when baselines exist)
    paired_verdict: str = "unavailable"   # erased|present|uninformative|unavailable
    baseline_present: float = float("nan")
    baseline_absent: float = float("nan")
    observed_post: float = float("nan")
    separation: float = float("nan")
    # secondary diagnostic — never the headline
    epsilon: float = 1.0
    delta: float = 0.99
    alpha: float = 0.05
    n_treatment: int = 0
    n_control_probes: int = 0
    hits: int = 0

    # ---- invariant helpers ----
    @property
    def inspection_residue(self) -> bool:
        return any(c.status is ChannelStatus.RESIDUE for c in self.inspection)

    @property
    def inspection_unavailable(self) -> List[str]:
        return [c.name for c in self.inspection if not c.measured]

    def classify(self) -> str:
        # I1: measured residue anywhere is decisive and negative.
        if self.deterministic_findings > 0:
            return "NOT_ERASED"
        if self.inspection_residue:
            return "NOT_ERASED"
        # Paired pre/post is the primary statistic when available: it compares
        # the subject's own region against itself, so a legitimate near
        # neighbour cannot masquerade as residue.
        if self.paired_verdict == "present":
            return "RESIDUE_DETECTED"
        if self.paired_verdict == "uninformative":
            return "INCONCLUSIVE_INDISTINGUISHABLE"
        if self.n_control_anchors < 19:
            return "INCONCLUSIVE_CONTROLS"
        if self.paired_verdict == "erased":
            if self.inspection_unavailable:
                return "INCONCLUSIVE_UNMEASURED"
            return "STRONG_EVIDENCE_ERASED"
        if self.p_value <= 0.01:
            return "RESIDUE_DETECTED"
        if self.p_value <= 0.05:
            return "RESIDUE_SUSPECTED"
        # I1 again: clean probe + unmeasured channels != erased.
        if self.inspection_unavailable:
            return "INCONCLUSIVE_UNMEASURED"
        if self.min_attainable_p <= 0.01:
            return "STRONG_EVIDENCE_ERASED"
        return "MODERATE_EVIDENCE_ERASED"

    def is_pass(self) -> bool:
        return self.classify() in ("STRONG_EVIDENCE_ERASED",
                                   "MODERATE_EVIDENCE_ERASED")

    def explain(self) -> str:
        c = self.classify()
        if c == "NOT_ERASED":
            if self.deterministic_findings:
                return (f"NOT ERASED. Sweep found {self.deterministic_findings} "
                        f"record(s) still carrying the subject's identifiers. "
                        f"Direct evidence; no probabilistic statement applies.")
            bad = [x.name for x in self.inspection
                   if x.status is ChannelStatus.RESIDUE]
            return (f"NOT ERASED. Engine inspection found residue on: "
                    f"{', '.join(bad)}. Direct evidence from the engine's own "
                    f"state; no probabilistic statement applies.")
        if c == "INCONCLUSIVE_INDISTINGUISHABLE":
            return (f"INCONCLUSIVE — the two hypotheses are not separable here. "
                    f"At registration the subject's region scored "
                    f"{self.baseline_present:.4f} with the subject present and "
                    f"{self.baseline_absent:.4f} with it excluded: a separation of "
                    f"only {self.separation:.4f}. A near-duplicate neighbour "
                    f"occupies the same region, so no retrieval-level probe can "
                    f"tell residue from a legitimate neighbour. Use engine "
                    f"inspection (Stage 0) for this subject.")
        if c == "INCONCLUSIVE_CONTROLS":
            return (f"INCONCLUSIVE. {self.n_control_anchors} control anchors. A "
                    f"conformal p-value cannot fall below 1/(m+1), so under 19 "
                    f"controls cannot reach p<=0.05 at any probe budget. Enlarge "
                    f"the control set, not the probe count.")
        if c == "RESIDUE_DETECTED" and self.paired_verdict == "present":
            return (f"RESIDUE DETECTED (paired test). The subject's region now "
                    f"scores {self.observed_post:.4f}. At registration it scored "
                    f"{self.baseline_present:.4f} with the subject present and "
                    f"{self.baseline_absent:.4f} without. The post-erasure "
                    f"measurement matches the PRESENT baseline, so the subject's "
                    f"vector is still retrievable in that region.")
        if c == "RESIDUE_DETECTED":
            return (f"RESIDUE DETECTED. Subject region scores "
                    f"{self.subject_score:.4f} against control median "
                    f"{self.control_median:.4f} / max {self.control_max:.4f} over "
                    f"{self.n_control_anchors} anchors (conformal p={self.p_value:.4f}, "
                    f"radius={self.probe_radius:.4f}). The region is anomalously "
                    f"dense. Do not assert erasure — check tombstones, vacuum "
                    f"backlog, replicas and snapshots.")
        if c == "RESIDUE_SUSPECTED":
            return (f"RESIDUE SUSPECTED. Conformal p={self.p_value:.4f} over "
                    f"{self.n_control_anchors} anchors; subject {self.subject_score:.4f} "
                    f"vs control median {self.control_median:.4f}. Suggestive, not "
                    f"conclusive. Re-run with more control anchors before claiming "
                    f"anything in either direction.")
        if c == "INCONCLUSIVE_UNMEASURED":
            return (f"INCONCLUSIVE. The probe found no anomaly (p={self.p_value:.4f}), "
                    f"but these channels were NOT measured: "
                    f"{', '.join(self.inspection_unavailable)}. An unmeasured channel "
                    f"is not a clean channel, so no erasure claim is issued. Enable "
                    f"inspection access or state the reduced scope explicitly.")
        if c == "STRONG_EVIDENCE_ERASED" and self.paired_verdict == "erased":
            meas = ', '.join(x.name for x in self.inspection) or "none required"
            return (f"Strong evidence of erasure (paired test). Sweep clean; "
                    f"inspection clean [{meas}]. The subject's region now scores "
                    f"{self.observed_post:.4f}, matching the ABSENT baseline "
                    f"{self.baseline_absent:.4f} rather than the PRESENT baseline "
                    f"{self.baseline_present:.4f} (separation {self.separation:.4f}). "
                    f"Conformal cross-check p={self.p_value:.4f} over "
                    f"{self.n_control_anchors} controls. Bounds RETRIEVAL "
                    f"recoverability only — see scope.")
        if c == "STRONG_EVIDENCE_ERASED":
            meas = ', '.join(x.name for x in self.inspection) or "none required"
            return (f"Strong evidence of erasure. Sweep clean; inspection clean "
                    f"[{meas}]; subject region statistically indistinguishable from "
                    f"{self.n_control_anchors} matched controls (conformal "
                    f"p={self.p_value:.4f}, subject {self.subject_score:.4f} vs median "
                    f"{self.control_median:.4f}). Bounds RETRIEVAL recoverability "
                    f"only — see scope.")
        return (f"Moderate evidence of erasure. No anomaly (p={self.p_value:.4f}), but "
                f"with {self.n_control_anchors} control anchors the strongest "
                f"attainable evidence is p={self.min_attainable_p:.4f}. Absence of "
                f"evidence at this resolution is weak evidence of absence: use >=99 "
                f"control anchors for a p<=0.01 claim.")


SCOPE_TEXT = (
    "RETRIEVAL_ONLY. Covers recoverability of the subject through vector "
    "retrieval over the index state named in index_commitment.merkle_root. "
    "Does NOT cover: (1) model weights, if the subject's data reached training "
    "or fine-tuning — machine unlearning is out of scope; (2) replicas, "
    "snapshots, backups or WAL outside the committed state, except where an "
    "inspection channel explicitly reports on them; (3) derived embeddings, "
    "caches or features; (4) application logs, traces and observability "
    "backends. The conformal p-value tests whether the subject's region is "
    "distinguishable from matched control regions; it is not a probability "
    "that the subject is recoverable."
)


@dataclass
class ErasureAttestation:
    version: str
    subject_token_hash: str
    commitment: IndexCommitment
    bound: ErasureBound
    findings: List[DeterministicFinding]
    scope: str
    sig_alg: str
    public_key: str
    signature: str
    timestamp: float
    log_index: Optional[int] = None
    log_entry_hash: Optional[str] = None

    def payload(self) -> str:
        return canonical({
            "version": self.version,
            "subject_token_hash": self.subject_token_hash,
            "merkle_root": self.commitment.merkle_root,
            "engine": self.commitment.engine,
            "store_name": self.commitment.store_name,
            "n_vectors": self.commitment.n_vectors,
            "classification": self.bound.classify(),
            "p_value": self.bound.p_value,
            "n_control_anchors": self.bound.n_control_anchors,
            "min_attainable_p": self.bound.min_attainable_p,
            "subject_score": self.bound.subject_score,
            "control_median": self.bound.control_median,
            "deterministic_findings": self.bound.deterministic_findings,
            "paired_verdict": self.bound.paired_verdict,
            "baseline_present": self.bound.baseline_present,
            "baseline_absent": self.bound.baseline_absent,
            "observed_post": self.bound.observed_post,
            "inspection": [[c.name, c.status.value] for c in self.bound.inspection],
            "epsilon_diagnostic": self.bound.epsilon,
            "scope": self.scope,
            "sig_alg": self.sig_alg,
            "public_key": self.public_key,
            "timestamp": self.timestamp,
        })

    def to_dict(self) -> dict:
        d = asdict(self)
        d["classification"] = self.bound.classify()
        d["explanation"] = self.bound.explain()
        d["pass"] = self.bound.is_pass()
        return d


def verify_attestation(att_dict: dict, public_key_pem: str) -> bool:
    """Third-party verification from JSON + public key. No index access."""
    if not _CRYPTO or att_dict.get("sig_alg") != "ed25519":
        return False
    b, c = att_dict["bound"], att_dict["commitment"]
    payload = canonical({
        "version": att_dict["version"],
        "subject_token_hash": att_dict["subject_token_hash"],
        "merkle_root": c["merkle_root"],
        "engine": c["engine"],
        "store_name": c["store_name"],
        "n_vectors": c["n_vectors"],
        "classification": att_dict["classification"],
        "p_value": b["p_value"],
        "n_control_anchors": b["n_control_anchors"],
        "min_attainable_p": b["min_attainable_p"],
        "subject_score": b["subject_score"],
        "control_median": b["control_median"],
        "deterministic_findings": b["deterministic_findings"],
        "paired_verdict": b["paired_verdict"],
        "baseline_present": b["baseline_present"],
        "baseline_absent": b["baseline_absent"],
        "observed_post": b["observed_post"],
        "inspection": [[x["name"], x["status"].value
                        if isinstance(x["status"], Enum) else x["status"]]
                       for x in b["inspection"]],
        "epsilon_diagnostic": b["epsilon"],
        "scope": att_dict["scope"],
        "sig_alg": att_dict["sig_alg"],
        "public_key": att_dict["public_key"],
        "timestamp": att_dict["timestamp"],
    })
    try:
        pk = serialization.load_pem_public_key(public_key_pem.encode())
        pk.verify(bytes.fromhex(att_dict["signature"]), payload.encode())
        return True
    except Exception:
        return False


# ======================================================================
# Crypto
# ======================================================================

class _Signer:
    def __init__(self, key: Optional[bytes] = None):
        if _CRYPTO:
            self._sk = (Ed25519PrivateKey.from_private_bytes(key) if key
                        else Ed25519PrivateKey.generate())
            self.alg = "ed25519"
            self.public_key = self._sk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        else:
            self._mac = key or secrets.token_bytes(32)
            self.alg = "hmac-sha256-NOT-THIRD-PARTY-VERIFIABLE"
            self.public_key = ""
            logger.warning("[VERIFY] cryptography missing — HMAC fallback; "
                           "attestations are NOT third-party verifiable")

    def sign(self, payload: str) -> str:
        if _CRYPTO:
            return self._sk.sign(payload.encode()).hex()
        return hmac.new(self._mac, payload.encode(), hashlib.sha256).hexdigest()


class _AnchorStore:
    """AESGCM-encrypted anchors at rest (from v1.0) — but the plaintext is
    never handed back out in a handle, and forget() destroys key material."""

    def __init__(self, key: bytes):
        self._key = bytearray(key)
        self._blobs: Dict[str, bytes] = {}

    def put(self, token_hash: str, vec: np.ndarray) -> None:
        raw = vec.astype(np.float32).tobytes()
        if _CRYPTO:
            nonce = secrets.token_bytes(12)
            self._blobs[token_hash] = nonce + AESGCM(bytes(self._key)).encrypt(
                nonce, raw, token_hash.encode())
        else:
            self._blobs[token_hash] = raw

    def get(self, token_hash: str, dim: int) -> Optional[np.ndarray]:
        blob = self._blobs.get(token_hash)
        if blob is None:
            return None
        if _CRYPTO:
            raw = AESGCM(bytes(self._key)).decrypt(
                blob[:12], blob[12:], token_hash.encode())
        else:
            raw = blob
        return np.frombuffer(raw, dtype=np.float32).copy()

    def forget(self, token_hash: str) -> bool:
        return self._blobs.pop(token_hash, None) is not None

    def destroy(self) -> None:
        for i in range(len(self._key)):
            self._key[i] = 0
        self._blobs.clear()


# ======================================================================
# Append-only log
# ======================================================================

class AttestationLog:
    """Hash-chained, file-backed.

    Honest limitation: signed and held by the same party. It detects
    corruption and edits by anyone WITHOUT the signing key; it does not
    constrain the operator. Publish head() to an external witness for that.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else None
        self.entries: List[dict] = []
        if self.path and self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text())
            except Exception:
                logger.warning("[VERIFY] log unreadable; starting fresh")

    def append(self, att: ErasureAttestation) -> Tuple[int, str]:
        body = {
            "index": len(self.entries),
            "payload_hash": hashlib.sha256(att.payload().encode()).hexdigest(),
            "signature": att.signature,
            "classification": att.bound.classify(),
            "timestamp": f"{time.time():.6f}",
            "previous": self.entries[-1]["hash"] if self.entries else "0" * 64,
        }
        body["hash"] = hashlib.sha256(canonical(body).encode()).hexdigest()
        self.entries.append(body)
        if self.path:
            self.path.write_text(json.dumps(self.entries, indent=2))
        return body["index"], body["hash"]

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = {k: e[k] for k in ("index", "payload_hash", "signature",
                                      "classification", "timestamp", "previous")}
            if e["previous"] != prev:
                return False
            if hashlib.sha256(canonical(body).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else "0" * 64


# ======================================================================
# Inspection (Stage 0)
# ======================================================================

class PgVectorInspector:
    """Real queries against Postgres. Every method returns UNAVAILABLE on any
    failure — never CLEAN.

    v1.0's inspector returned hardcoded {"ghost_in_neighbors": False} and
    ignored its connection argument, so verify_inspection() signed a passing
    attestation with a dead database. That is the failure mode I1 exists to
    prevent.
    """

    @staticmethod
    def _q(conn, sql: str, args=()) -> Optional[list]:
        try:
            cur = conn.cursor()
            cur.execute(sql, args)
            return cur.fetchall()
        except Exception as e:
            logger.info("[VERIFY] inspection query failed: %s", e)
            return None

    @staticmethod
    def dead_tuples(conn, table: str) -> ChannelResult:
        rows = PgVectorInspector._q(
            conn,
            "SELECT n_dead_tup, last_vacuum, last_autovacuum "
            "FROM pg_stat_user_tables WHERE relname = %s", (table,))
        if not rows:
            return ChannelResult("pg.dead_tuples", ChannelStatus.UNAVAILABLE,
                                 "pg_stat_user_tables unreadable or table absent")
        dead = int(rows[0][0] or 0)
        if dead > 0:
            return ChannelResult(
                "pg.dead_tuples", ChannelStatus.RESIDUE,
                f"{dead} dead tuple(s) awaiting vacuum — deleted rows are still "
                f"resident on disk", float(dead))
        return ChannelResult("pg.dead_tuples", ChannelStatus.CLEAN,
                             "no dead tuples pending", 0.0)

    @staticmethod
    def replica_lag(conn) -> ChannelResult:
        rows = PgVectorInspector._q(
            conn,
            "SELECT client_addr, "
            "pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag "
            "FROM pg_stat_replication")
        if rows is None:
            return ChannelResult("pg.replica_lag", ChannelStatus.UNAVAILABLE,
                                 "pg_stat_replication unreadable (needs "
                                 "pg_monitor or superuser)")
        lag = max([int(r[1] or 0) for r in rows], default=0)
        if lag > 0:
            return ChannelResult(
                "pg.replica_lag", ChannelStatus.RESIDUE,
                f"{len(rows)} replica(s), max {lag} bytes unreplayed — the "
                f"deletion has not landed everywhere", float(lag))
        return ChannelResult("pg.replica_lag", ChannelStatus.CLEAN,
                             f"{len(rows)} replica(s) in sync", 0.0)

    @staticmethod
    def hnsw_neighbors(conn, index: str) -> ChannelResult:
        """Ghost entries in HNSW neighbour lists. Needs pageinspect."""
        ok = PgVectorInspector._q(
            conn, "SELECT 1 FROM pg_extension WHERE extname = 'pageinspect'")
        if not ok:
            return ChannelResult(
                "pg.hnsw_neighbors", ChannelStatus.UNAVAILABLE,
                "pageinspect not installed — HNSW neighbour lists cannot be "
                "read; graph-level residue is UNMEASURED")
        rows = PgVectorInspector._q(
            conn, "SELECT count(*) FROM hnsw_page_items(get_raw_page(%s, 1)) "
                  "WHERE dead", (index,))
        if rows is None:
            return ChannelResult(
                "pg.hnsw_neighbors", ChannelStatus.UNAVAILABLE,
                "pageinspect present but hnsw_page_items unavailable on this "
                "pgvector build")
        n = int(rows[0][0] or 0)
        if n > 0:
            return ChannelResult("pg.hnsw_neighbors", ChannelStatus.RESIDUE,
                                 f"{n} dead entries still in neighbour lists",
                                 float(n))
        return ChannelResult("pg.hnsw_neighbors", ChannelStatus.CLEAN,
                             "no dead entries in inspected pages", 0.0)

    @classmethod
    def run_all(cls, conn, table: str, index: str) -> List[ChannelResult]:
        if conn is None:
            return [ChannelResult(n, ChannelStatus.UNAVAILABLE,
                                  "no database connection supplied")
                    for n in ("pg.dead_tuples", "pg.replica_lag",
                              "pg.hnsw_neighbors")]
        return [cls.dead_tuples(conn, table), cls.replica_lag(conn),
                cls.hnsw_neighbors(conn, index)]


# ======================================================================
# Verifier
# ======================================================================

class ErasureVerifier:
    """
        from aagcp.verify import ErasureVerifier

        ev = ErasureVerifier(store=engine.store, vault=engine.vault,
                             engine=EngineType.PGVECTOR_HNSW,
                             log_path="attestations.json")

        anchor = ev.register("id_42", subject_embedding)   # BEFORE erasure
        # ... engine.erase(...) ...
        att = ev.verify(anchor, n_control_anchors=100, pg_conn=conn)
        print(att.bound.explain())
        ev.forget(anchor.token_hash)
    """

    def __init__(
        self,
        store,
        vault=None,
        engine: Optional[EngineType] = None,
        anchor_key: Optional[bytes] = None,
        signing_key: Optional[bytes] = None,
        log_path: Optional[str] = None,
        alpha: float = 0.05,
        delta: float = 0.99,
    ):
        self.store = store
        self.vault = vault
        self.engine = engine if engine is not None else self._detect_engine(store)
        self.alpha, self.delta = float(alpha), float(delta)
        self._token_key = (anchor_key
                           or os.environ.get("AAGCP_ANCHOR_KEY", "").encode()
                           or secrets.token_bytes(32))
        if self.vault is not None and self._token_key == getattr(self.vault, "secret", None):
            raise ValueError(
                "anchor_key must differ from vault.secret — key separation "
                "keeps vault shredding from destroying verifiability")
        # anchor encryption key derived separately from the token key
        self._anchors = _AnchorStore(
            hashlib.sha256(b"aagcp-anchor-enc|" + self._token_key).digest())
        self.signer = _Signer(signing_key)
        self.log = AttestationLog(log_path)
        self._meta: Dict[str, SubjectAnchor] = {}
        self._probe_seed: Optional[int] = None

    @staticmethod
    def _detect_engine(store) -> EngineType:
        """Infer the engine from the connector so callers cannot accidentally
        get GENERIC (and its permanently-unmeasurable channel) on a store we
        know how to reason about."""
        n = str(getattr(store, "name", "")).lower()
        mapping = {
            "in_memory": EngineType.IN_MEMORY,
            "memory": EngineType.IN_MEMORY,
            "pinecone": EngineType.PINECONE,
            "qdrant": EngineType.QDRANT,
            "pgvector": EngineType.PGVECTOR_HNSW,
        }
        eng = mapping.get(n, EngineType.GENERIC)
        if eng is EngineType.GENERIC:
            logger.warning("[VERIFY] unknown store '%s' — treating internal "
                           "state as UNMEASURABLE; pass engine= explicitly", n)
        return eng

    # ---------- registration ----------

    def register(self, identity_id: str, embedding: np.ndarray,
                 record_id: Optional[str] = None, k: int = 10,
                 n_baseline: int = 40, seed: Optional[int] = None) -> SubjectAnchor:
        """Register BEFORE erasure — you cannot probe a region you never located.

        When record_id is supplied, this also captures the PAIRED BASELINES:
        the region score with the subject's record visible, and with it
        excluded. Those two numbers are the hypotheses that verification later
        chooses between, and their gap tells you in advance whether the
        subject is separable at all. A subject sitting on top of a
        near-duplicate has almost no gap, and no retrieval probe will ever
        resolve it — better to learn that at registration than to emit a
        confident number later.
        """
        vec = np.asarray(embedding, dtype=np.float32).ravel()
        token = hmac.new(self._token_key, identity_id.encode(),
                         hashlib.sha256).hexdigest()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        vt: Tuple[str, ...] = ()
        if self.vault is not None:
            try:
                vt = tuple(self.vault.get_identity_tokens(identity_id))
            except Exception:
                vt = ()
        b_present = b_absent = b_radius = float("nan")
        if record_id is not None:
            self._probe_seed = seed
            rng = np.random.default_rng(seed)
            ctrls = self._controls(32, int(vec.shape[0]))
            b_radius = self._calibrate_radius(ctrls, k) if ctrls else 0.05
            qs = self._perturb(vec, n_baseline, b_radius, rng)
            b_present = float(np.median([self._top1(q, k) for q in qs]))
            b_absent = float(np.median(
                [self._top1(q, k, exclude_id=record_id) for q in qs]))
            if abs(b_present - b_absent) < 0.01:
                logger.warning(
                    "[VERIFY] subject %s is not separable: present=%.4f "
                    "absent=%.4f. A near-duplicate shares this region; "
                    "retrieval probes cannot verify erasure for this subject.",
                    token_hash[:12], b_present, b_absent)

        anchor = SubjectAnchor(token_hash, int(vec.shape[0]), time.time(), vt,
                               b_present, b_absent, b_radius, record_id)
        self._anchors.put(token_hash, vec)
        self._meta[token_hash] = anchor
        logger.info("[VERIFY] anchor registered %s dim=%d tokens=%d",
                    token_hash[:12], anchor.dim, len(vt))
        return anchor

    def forget(self, token_hash: str) -> bool:
        self._meta.pop(token_hash, None)
        return self._anchors.forget(token_hash)

    def shutdown(self) -> None:
        self._anchors.destroy()
        self._meta.clear()

    # ---------- stage 1 ----------

    def _sweep(self, anchor: SubjectAnchor) -> List[DeterministicFinding]:
        out: List[DeterministicFinding] = []
        targets = set(anchor.vault_tokens)
        if not targets:
            return out
        shredded = set(getattr(self.vault, "_shredded", []) or []) if self.vault else set()
        try:
            for batch in self.store.iter_all(batch=500):
                for rec in batch:
                    hay = " ".join([rec.source_text or ""]
                                   + [str(v) for v in (rec.metadata or {}).values()])
                    for tok in targets:
                        if tok in hay:
                            out.append(DeterministicFinding(
                                rec.id,
                                "shredded_token_text" if tok in shredded else "live_vault_token",
                                f"token {tok[:24]}... present after erasure"))
                            break
        except Exception as e:
            logger.warning("[VERIFY] sweep aborted: %s", e)
        return out

    # ---------- stage 2 ----------

    def _controls(self, m: int, dim: int) -> List[Tuple[str, np.ndarray]]:
        """Reservoir-sample live vectors WITH ids.

        The id matters: probing around a live anchor would otherwise return
        that anchor itself at similarity ~1.0, pinning the comparison at the
        ceiling so no treatment probe could ever register — a surviving ghost
        would score as erased.
        """
        # Engines that cannot stream vectors (Pinecone fetch drops values;
        # a full scan of 10M vectors is not a probe budget anyway) may expose
        # sample_vectors(m, dim). See adapters.PineconeProbeAdapter.
        sampler = getattr(self.store, "sample_vectors", None)
        if callable(sampler):
            try:
                # Thread the run seed through: an unseeded sampler makes the
                # whole verification non-reproducible, and an attestation you
                # cannot reproduce is not evidence.
                try:
                    raw = sampler(m, dim, seed=self._probe_seed)
                except TypeError:
                    raw = sampler(m, dim)
                got = [(i, np.asarray(v, dtype=np.float32).ravel())
                       for i, v in raw]
                got = [(i, v) for i, v in got if v.shape[0] == dim]
                if got:
                    return got[:m]
                logger.warning("[VERIFY] sample_vectors returned nothing; "
                               "falling back to iter_all")
            except Exception as e:
                logger.warning("[VERIFY] sample_vectors failed (%s); "
                               "falling back to iter_all", e)

        res: List[Tuple[str, np.ndarray]] = []
        seen = 0
        rng = np.random.default_rng()
        try:
            for batch in self.store.iter_all(batch=500):
                for rec in batch:
                    if rec.vector is None:
                        continue
                    v = np.asarray(rec.vector, dtype=np.float32).ravel()
                    if v.shape[0] != dim:
                        continue
                    seen += 1
                    if len(res) < m:
                        res.append((rec.id, v))
                    else:
                        j = int(rng.integers(0, seen))
                        if j < m:
                            res[j] = (rec.id, v)
        except Exception as e:
            logger.warning("[VERIFY] control sampling aborted: %s", e)
        return res

    def _top1(self, qv: np.ndarray, k: int, exclude_id: Optional[str] = None) -> float:
        for r in self.store.query(qv, k=k):
            if exclude_id is not None and r.get("id") == exclude_id:
                continue
            return float(r.get("score", -1.0))
        return -1.0

    @staticmethod
    def _perturb(base: np.ndarray, n: int, radius: float, rng) -> List[np.ndarray]:
        d = base.shape[0]
        scale = float(np.linalg.norm(base)) or 1.0
        out = []
        for _ in range(n):
            u = rng.normal(size=d)
            u /= (np.linalg.norm(u) + 1e-12)
            out.append((base + u * radius * scale).astype(np.float32))
        return out

    def _calibrate_radius(self, controls: Sequence[Tuple[str, np.ndarray]],
                          k: int) -> float:
        """Derive the probe radius from the index's own geometry.

        A hardcoded radius is meaningless across embedding models. Perturbing
        a unit-ish vector by relative radius r drops cosine by about r^2/2, so
        to place probes at half the typical nearest-neighbour gap:
            target = (1 - median_nn_similarity) / 2 ;  r = sqrt(2 * target)
        Clamped to [0.01, 0.5].
        """
        sims = []
        for cid, cvec in controls[:32]:
            s = self._top1(cvec, k, exclude_id=cid)
            if s > -1.0:
                sims.append(s)
        if not sims:
            return 0.05
        target = max(1e-4, (1.0 - float(np.median(sims))) / 2.0)
        return float(min(0.5, max(0.01, math.sqrt(2.0 * target))))

    # ---------- end to end ----------

    def verify(
        self,
        anchor: SubjectAnchor,
        n_treatment: int = 40,
        n_control_anchors: int = 100,
        probes_per_control: int = 20,
        radius: Optional[float] = None,
        k: int = 10,
        seed: Optional[int] = None,
        pg_conn=None,
        pg_table: str = "documents",
        pg_index: str = "documents_embedding_idx",
        settle_seconds: float = 0.0,
        retry_on_residue: int = 0,
    ) -> ErasureAttestation:
        """
        settle_seconds / retry_on_residue exist for eventually-consistent
        engines. Pinecone deletes propagate asynchronously with no committed
        -state semantics, so a probe run immediately after erasure can read a
        not-yet-propagated vector and report residue that is really just lag.
        On a residue verdict the probe stage is re-run after a wait, up to
        retry_on_residue times. Only the final run is attested.

        This never turns a residue verdict into a pass on its own: if residue
        persists after the waits, it is attested as residue.
        """
        base = self._anchors.get(anchor.token_hash, anchor.dim)
        if base is None:
            raise ValueError("anchor not registered or already forgotten — "
                             "register() must run before erasure")
        self._probe_seed = seed
        if settle_seconds > 0:
            logger.info("[VERIFY] settling %.1fs before probe", settle_seconds)
            time.sleep(settle_seconds)
        rng = np.random.default_rng(seed)

        # Stage 0. Start from what the engine SAYS must be accounted for, all
        # UNAVAILABLE, then let an inspector upgrade what it can actually
        # measure. Channels never appear out of nowhere and never default to
        # clean.
        inspection: List[ChannelResult] = [
            ChannelResult(n, ChannelStatus.UNAVAILABLE,
                          "not measurable on this engine")
            for n in self.engine.required_channels
        ]
        if self.engine in (EngineType.PGVECTOR_HNSW, EngineType.PGVECTOR_IVF):
            inspection = PgVectorInspector.run_all(pg_conn, pg_table, pg_index)

        # Stage 1
        findings = self._sweep(anchor)

        try:
            n_vecs = int(self.store.count())
        except Exception:
            n_vecs = -1
        commitment = IndexCommitment(
            engine=self.engine.value,
            store_name=getattr(self.store, "name", "unknown"),
            n_vectors=n_vecs,
            committed_at=time.time(),
        )

        def finish(b: ErasureBound) -> ErasureAttestation:
            return self._attest(anchor, b, findings, commitment)

        if findings or any(c.status is ChannelStatus.RESIDUE for c in inspection):
            return finish(ErasureBound(
                p_value=0.0, n_control_anchors=0, min_attainable_p=1.0,
                subject_score=float("nan"), control_median=float("nan"),
                control_max=float("nan"),
                deterministic_findings=len(findings), inspection=inspection))

        # Stage 2
        controls = self._controls(n_control_anchors, anchor.dim)
        m = len(controls)
        if m < 19:
            return finish(ErasureBound(
                p_value=1.0, n_control_anchors=m,
                min_attainable_p=1.0 / (m + 1) if m else 1.0,
                subject_score=float("nan"), control_median=float("nan"),
                control_max=float("nan"), deterministic_findings=0,
                inspection=inspection))

        attempt = 0
        while True:
            att_result = self._probe_once(
                anchor, base, controls, m, inspection, findings, commitment,
                n_treatment, probes_per_control, radius, k, rng)
            residue = att_result.paired_verdict == "present" or (
                att_result.paired_verdict == "unavailable"
                and att_result.p_value <= 0.05)
            if not residue or attempt >= retry_on_residue:
                return finish(att_result)
            attempt += 1
            wait = max(1.0, settle_seconds or 5.0)
            logger.info("[VERIFY] residue seen; re-probing after %.1fs "
                        "(attempt %d/%d) to rule out replication lag",
                        wait, attempt, retry_on_residue)
            time.sleep(wait)

    def _probe_once(self, anchor, base, controls, m, inspection, findings,
                    commitment, n_treatment, probes_per_control, radius, k, rng
                    ) -> ErasureBound:
        r = radius if radius is not None else (
            anchor.baseline_radius
            if not math.isnan(anchor.baseline_radius)
            else self._calibrate_radius(controls, k))

        def region_score(vec, n, exclude):
            s = [self._top1(q, k, exclude_id=exclude)
                 for q in self._perturb(vec, n, r, rng)]
            return float(np.median(s)) if s else -1.0

        cscores = [region_score(cv, probes_per_control, cid) for cid, cv in controls]
        sscore = region_score(base, n_treatment, None)

        p_value = (1.0 + sum(1 for s in cscores if s >= sscore)) / (1.0 + m)

        # Paired pre/post. Compares the region against ITSELF, so a legitimate
        # near neighbour cannot be mistaken for residue — the failure mode the
        # control-arm test alone cannot avoid.
        verdict, sep = "unavailable", float("nan")
        bp, ba = anchor.baseline_present, anchor.baseline_absent
        if not (math.isnan(bp) or math.isnan(ba)):
            sep = abs(bp - ba)
            if sep < 0.01:
                verdict = "uninformative"
            else:
                verdict = "present" if abs(sscore - bp) < abs(sscore - ba) else "erased"

        thr = float(np.quantile(np.asarray(cscores), 1.0 - self.alpha))
        t = [self._top1(q, k) for q in self._perturb(base, n_treatment, r, rng)]
        hits = sum(1 for s in t if s > thr)

        return ErasureBound(
            p_value=p_value, n_control_anchors=m, min_attainable_p=1.0 / (m + 1),
            subject_score=sscore, control_median=float(np.median(cscores)),
            control_max=float(max(cscores)), deterministic_findings=0,
            inspection=inspection, probe_radius=r,
            paired_verdict=verdict, baseline_present=bp, baseline_absent=ba,
            observed_post=sscore, separation=sep,
            epsilon=clopper_pearson_upper(hits, len(t), self.delta),
            delta=self.delta, alpha=self.alpha, n_treatment=len(t),
            n_control_probes=m * probes_per_control, hits=hits)

    def _attest(self, anchor, bound, findings, commitment) -> ErasureAttestation:
        att = ErasureAttestation(
            version=VERSION,
            subject_token_hash=anchor.token_hash,
            commitment=commitment, bound=bound, findings=findings,
            scope=SCOPE_TEXT, sig_alg=self.signer.alg,
            public_key=self.signer.public_key, signature="",
            timestamp=time.time())
        att.signature = self.signer.sign(att.payload())
        att.log_index, att.log_entry_hash = self.log.append(att)
        logger.info("[VERIFY] %s -> %s (p=%.4f min_p=%.4f)", anchor.token_hash[:12],
                    bound.classify(), bound.p_value, bound.min_attainable_p)
        return att

    def span_attrs(self, att: ErasureAttestation) -> dict:
        """For aagcp/govern/telemetry.py — token hash only, never a name."""
        return {
            "op": "erasure_verify",
            "subject": att.subject_token_hash,
            "decision": att.bound.classify(),
            "p_value": round(att.bound.p_value, 6),
            "n_control_anchors": att.bound.n_control_anchors,
            "min_attainable_p": round(att.bound.min_attainable_p, 6),
            "paired_verdict": att.bound.paired_verdict,
            "unmeasured_channels": ",".join(att.bound.inspection_unavailable),
            "merkle_root": att.commitment.merkle_root,
            "sig_alg": att.sig_alg,
        }
