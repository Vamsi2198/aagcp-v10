"""End-to-end wiring of AAGCP_v3's real verifier into the erasure request.

    python3 tests/test_erasure_live.py     (needs pip install -e .[verify])

Everything else in test_erasure.py runs against hand-built AttestationViews,
which proves the state machine and proves nothing about the wire. This runs
a real index, a real erasure and a real signed attestation through the
adapter and into settle(), twice: once where the subject is genuinely gone,
once where a record was left behind.

If the second case ever closed, the whole module would be decoration.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.basicConfig(level=logging.ERROR)

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

try:
    import numpy as np
    from aagcp.store.connectors import InMemoryConnector, VectorRecord
    from aagcp.vault import PseudonymVault
    from aagcp.detect.detector import Finding as VFinding
    from aagcp.verify import ErasureVerifier
except Exception as exc:
    print(f"\n  SKIP  aagcp.verify not importable: {exc}")
    print("        pip install -e .[verify]")
    sys.exit(0)

from aagcp.core.erasure import (Subject, RowTarget, VectorTarget, ErasureRequest,
                          StructuredCheck, RequestState, EraseMode,
                          attestability)
from aagcp.core.verifier_adapter import LiveVerifierPort, project, check_constants
from aagcp.core.executors import AnchorHandle, VectorEraseExecutor

DIM = 128
CTRL = 100          # >= 99 for a p <= 0.01 claim; the verifier says so itself


def build(seed, leave_residue):
    """A store of 800 generic vectors plus one subject, then the erasure.
    When leave_residue is set the subject's vector is never deleted."""
    rng = np.random.default_rng(seed)
    st = InMemoryConnector()
    st.upsert([VectorRecord(id=f"v{i}",
                            vector=rng.normal(size=DIM).astype(np.float32),
                            source_text=f"generic record {i}", metadata={})
               for i in range(800)])
    vault = PseudonymVault(secret=b"k" * 32)
    vec = rng.normal(size=DIM).astype(np.float32)
    vault.token_for(VFinding("PERSON", "Test Subject", 0, 12, 1.0, "ner", "IN"),
                    "subj-7741", "Test Subject")
    st.upsert([VectorRecord(id="subj", vector=vec,
                            source_text="[REDACTED]", metadata={})])
    ev = ErasureVerifier(store=st, vault=vault, log_path="/tmp/aagcp_live.json")
    anchor = ev.register("subj-7741", vec, record_id="subj")
    return ev, anchor, st


ROWS = (RowTarget("ACME", "PUBLIC", "customers", "email",
                  mode=EraseMode.DELETE_ROW, citation="DPDP s.12(3)"),)


def run(leave_residue, seed):
    ev, anchor, st = build(seed, leave_residue)
    subject = Subject(key="subj-7741", key_kind="subject_id",
                      token_hash=anchor.token_hash)
    port = LiveVerifierPort(ev, "rag_index", {anchor.token_hash: anchor},
                            verify_kwargs=dict(n_control_anchors=CTRL, seed=7))
    target = VectorTarget("rag_index", "in_memory", citation="DPDP s.12(3)",
                          n_control_anchors=CTRL, anchor_registered=True,
                          baseline_separation=abs(anchor.baseline_present
                                                  - anchor.baseline_absent))
    req = ErasureRequest(subject, ROWS, (target,)).authorise()
    # The deletion goes through the executor, which refuses without an
    # anchor and records what it actually did.
    handle = AnchorHandle(token_hash=anchor.token_hash, store_name="rag_index",
                          registered_at="live", record_ids=("subj",))
    class NoOpDelete:
        """A store that accepts a delete and does not perform it — the
        realistic residue case, and the one the statistical attestation
        exists to catch."""
        def __init__(self, inner): self.inner = inner
        def delete(self, ids): pass
        def fetch(self, ids): return self.inner.fetch(ids)

    vx = VectorEraseExecutor(st if not leave_residue else NoOpDelete(st), target)
    vrec = vx.execute(handle)
    req.record_vector_execution(vrec)
    req.record_execution("COMPLETE")
    req.record_structured_check(StructuredCheck(ROWS[0].target, False, "0 rows"))
    req.verify_all(port)
    state = req.settle()
    ev.shutdown()
    return req, state, target, vrec


print("\n=== CONSTANTS ===")
check("mirrored constants match the live verifier", check_constants() == [],
      str(check_constants()))

print("\n=== SUBJECT GENUINELY ERASED ===")
req, state, target, vrec = run(leave_residue=False, seed=11)
view = req.attestations["rag_index"]
check("attestability predicted this was closable",
      attestability(target).attestable, attestability(target).detail)
check("the live classification is a pass",
      view.classification in ("STRONG_EVIDENCE_ERASED", "MODERATE_EVIDENCE_ERASED"),
      view.classification)
check("the attestation is signed", bool(view.signature))
check("the executor deleted the record and said so",
      vrec.verdict.value == "COMPLETE" and vrec.deleted_ids == ("subj",),
      vrec.explain().splitlines()[0])
check("the request closes COMPLETE", state is RequestState.COMPLETE,
      req.explain().splitlines()[0])
check("no open causes remain", req.open_causes() == [])
    # The bound the verifier produced carries the index's geometry: where
    # the subject scored, where the controls sat, how wide the probe was.
    # None of it may cross into the control plane. Checked by field name —
    # a substring search for "vector" only finds the scope text, which is
    # prose and is meant to be there.
GEOMETRY = ("subject_score", "control_median", "control_max", "probe_radius",
            "baseline_present", "baseline_absent", "observed_post",
            "separation", "hits", "n_treatment", "n_control_probes")
leaked = [f for f in GEOMETRY if f in view.to_dict()]
check("the projection drops every geometry field", leaked == [], str(leaked))
check("it keeps only what an auditor needs",
      set(view.to_dict()) == {"store_name", "classification", "is_pass",
                              "p_value", "n_control_anchors",
                              "unmeasured_channels", "merkle_root",
                              "signature_present", "scope",
                              "subject_token_hash",
                              # the pointer into AttestationLog, which holds
                              # the attestation body; still no geometry
                              "log_index", "log_entry_hash"},
      str(sorted(view.to_dict())))

print("\n=== SUBJECT LEFT BEHIND ===")
req2, state2, _, vrec2 = run(leave_residue=True, seed=11)
view2 = req2.attestations["rag_index"]
check("the live classification is not a pass", not view2.is_pass,
      view2.classification)
check("the request does NOT close", state2 is not RequestState.COMPLETE,
      state2.value)
check("the executor caught that the delete did not take",
      vrec2.verdict.value == "PARTIAL"
      and vrec2.still_addressable == ("subj",),
      f"{vrec2.cause}: {vrec2.still_addressable}")
check("the open cause names what happened",
      req2.open_causes() and any(
          c["cause"] in ("RESIDUE_DETECTED", "INCONCLUSIVE_UNMEASURED",
                         "NO_VECTOR_DELETION_RECORDED")
          for c in req2.open_causes()),
      str([(c["scope"], c["cause"]) for c in req2.open_causes()]))
print(f"  live verdict: {view2.classification} "
      f"(p={view2.p_value:.4f}, {view2.n_control_anchors} controls)")

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
