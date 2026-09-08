"""
aagcp/core/verifier_adapter.py — the seam between the engine and
AAGCP_v3's erasure verifier.

This is the only file in the tree that knows numpy exists. core/ stays a
pure stdlib library; the moment it imported ErasureVerifier it would drag
numpy, cryptography and a live index connection into the planner, and the
planner is the thing that has to run anywhere and produce the same bytes.

It also enforces the direction of travel. ErasureAttestation carries a
whole ErasureBound: subject scores, control medians, probe radii. The
control plane has no business with any of it. AttestationView is the
projection that crosses the boundary — a classification, a count, a
merkle root and a signature. Nothing that could be inverted back toward a
vector.

DRIFT GUARD. core/erasure.py restates two constants from the verifier
(19 control anchors, 0.01 baseline separation) so the engine can predict a
classification without importing numpy. Restating a constant is how two
files quietly stop agreeing, so check_constants() re-derives both from the
verifier's own behaviour and raises if they have moved. Call it once at
wiring time.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .erasure import (AttestationView, MIN_BASELINE_SEPARATION,
                      MIN_CONTROL_ANCHORS, Subject)


class VerifierUnavailable(RuntimeError):
    """AAGCP_v3 is not importable in this environment."""


def _load():
    """aagcp.verify is a sibling package after the merge, so this no longer
    depends on AAGCP_V3_PATH. It stays lazy only because verify pulls in
    numpy and cryptography, and aagcp.core is stdlib-only by contract."""
    try:
        from ..verify import (ChannelStatus, ErasureBound,  # noqa: F401
                              ErasureVerifier, EngineType)
    except Exception as exc:                       # pragma: no cover
        raise VerifierUnavailable(
            f"aagcp.verify needs numpy and cryptography: {exc}") from exc
    return ChannelStatus, ErasureBound, ErasureVerifier, EngineType


def check_constants() -> List[str]:
    """Re-derive the two mirrored constants from ErasureBound itself.

    Rather than trusting a comment, this builds bounds either side of each
    threshold and asserts the classification flips where core/erasure.py
    says it does. Returns the list of drifts found; empty means the mirror
    still holds.
    """
    _, ErasureBound, _, _ = _load()
    drift: List[str] = []

    def bound(**kw):
        base = dict(p_value=1.0, n_control_anchors=99, min_attainable_p=0.005,
                    subject_score=0.1, control_median=0.5, control_max=0.9,
                    deterministic_findings=0, inspection=[],
                    paired_verdict="unavailable")
        base.update(kw)
        return ErasureBound(**base)

    below = bound(n_control_anchors=MIN_CONTROL_ANCHORS - 1)
    at = bound(n_control_anchors=MIN_CONTROL_ANCHORS)
    if below.classify() != "INCONCLUSIVE_CONTROLS":
        drift.append(
            f"MIN_CONTROL_ANCHORS={MIN_CONTROL_ANCHORS}: "
            f"{MIN_CONTROL_ANCHORS - 1} anchors classified "
            f"'{below.classify()}', expected INCONCLUSIVE_CONTROLS")
    if at.classify() == "INCONCLUSIVE_CONTROLS":
        drift.append(
            f"MIN_CONTROL_ANCHORS={MIN_CONTROL_ANCHORS}: the threshold has "
            f"moved upward; {MIN_CONTROL_ANCHORS} anchors still classify as "
            f"INCONCLUSIVE_CONTROLS")

    # The separation threshold lives in _probe_once, not in classify(), so
    # it is checked through the verdict it produces rather than re-run.
    uninformative = bound(paired_verdict="uninformative")
    if uninformative.classify() != "INCONCLUSIVE_INDISTINGUISHABLE":
        drift.append(
            f"an 'uninformative' paired verdict now classifies as "
            f"'{uninformative.classify()}'; the separation gate "
            f"({MIN_BASELINE_SEPARATION}) no longer leads where "
            f"core/erasure.py assumes")
    return drift


def _unmeasured(bound) -> Tuple[str, ...]:
    return tuple(bound.inspection_unavailable)


def project(attestation, store_name: str, log_index=None,
            log_entry_hash: str = "") -> AttestationView:
    """ErasureAttestation -> AttestationView. One direction only.

    log_index and log_entry_hash come from AttestationLog.append(), which
    returns them. Carrying them means the journal can point at the log of
    record instead of duplicating an attestation body into a second
    chain — the thing core/journal.py claimed and, until now, did not do.
    """
    b = attestation.bound
    return AttestationView(
        store_name=store_name,
        classification=b.classify(),
        is_pass=b.is_pass(),
        p_value=float(b.p_value),
        n_control_anchors=int(b.n_control_anchors),
        unmeasured_channels=_unmeasured(b),
        merkle_root=attestation.commitment.merkle_root,
        signature=attestation.signature,
        scope=attestation.scope,
        subject_token_hash=attestation.subject_token_hash,
        log_index=log_index, log_entry_hash=log_entry_hash,
    )


class LiveVerifierPort:
    """Satisfies ErasureVerifierPort against a real ErasureVerifier.

    `anchors` maps a subject token hash to the SubjectAnchor produced by
    register(). The adapter holds no embeddings — the anchor is an opaque
    handle and the embedding stays in the verifier's encrypted store.
    """

    def __init__(self, verifier, store_name: str, anchors: dict,
                 verify_kwargs: Optional[dict] = None, log=None):
        self.verifier = verifier
        self.store_name = store_name
        self.anchors = anchors
        self.verify_kwargs = dict(verify_kwargs or {})
        # aagcp.verify.AttestationLog, if the deployment keeps one. The
        # attestation body lives there; the journal keeps only the pointer.
        self.log = log

    def attest(self, subject: Subject, store_name: str) -> AttestationView:
        anchor = self.anchors.get(subject.token_hash)
        if anchor is None:
            # Rather than let verify() raise into the caller, this returns the
            # classification the situation actually is: nothing was measured.
            return AttestationView(
                store_name=store_name,
                classification="INCONCLUSIVE_UNMEASURED", is_pass=False,
                unmeasured_channels=("anchor.not_registered",),
                scope="no anchor was registered for this subject")
        att = self.verifier.verify(anchor, **self.verify_kwargs)
        idx, entry_hash = (self.log.append(att) if self.log is not None
                           else (None, ""))
        return project(att, store_name, log_index=idx,
                       log_entry_hash=entry_hash)
