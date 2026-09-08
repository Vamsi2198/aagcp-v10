"""
Regression suite for aagcp/verify.  Run from the AAGCP_v3-main root:

    python3 aagcp/verify/test_erasure_verifier.py

The three invariant tests (I1/I2/I3) are the ones that matter. I1 and I2 each
catch a false negative that shipped in an earlier verifier: an inspection stub
that signed a pass with a dead database, and a probe engine that could not tell
a fully-present subject from an erased one.
"""
import sys
import logging

import numpy as np

sys.path.insert(0, ".")
logging.basicConfig(level=logging.ERROR)

from aagcp.store.connectors import InMemoryConnector, VectorRecord
from aagcp.vault import PseudonymVault
from aagcp.detect.detector import Finding
from aagcp.verify import (
    ErasureVerifier, EngineType, ChannelStatus, PgVectorInspector,
    verify_attestation, canonical,
)

DIM = 128
CTRL = 100          # >= 99 needed for a p <= 0.01 claim
FAILURES = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILURES.append(name)


def build(rng, n=800):
    st = InMemoryConnector()
    st.upsert([VectorRecord(id=f"v{i}",
                            vector=rng.normal(size=DIM).astype(np.float32),
                            source_text=f"generic record {i}", metadata={})
               for i in range(n)])
    return st


def scenario(seed, key, name, ident, present, keep_text):
    """Build store + vault + verifier; optionally leave the subject behind."""
    rng = np.random.default_rng(seed)
    st = build(rng)
    vault = PseudonymVault(secret=key)
    vec = rng.normal(size=DIM).astype(np.float32)
    tok = vault.token_for(Finding("PERSON", name, 0, len(name), 1.0, "ner", "IN"),
                          ident, name)
    st.upsert([VectorRecord(id="subj", vector=vec,
                            source_text=f"claim {tok}" if keep_text else "[REDACTED]",
                            metadata={})])
    ev = ErasureVerifier(store=st, vault=vault, log_path="/tmp/aagcp_att.json")
    anchor = ev.register(ident, vec)
    if not present:
        st.delete(["subj"])
        vault.crypto_shred_identity(ident)
    return ev, anchor


# ==================================================================
print("\n=== I1: an unmeasured channel can never produce a pass ===")

ev, anchor = scenario(7, b"k-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Kavya Pillai",
                      "id_42", present=False, keep_text=True)
ev.engine = EngineType.PGVECTOR_HNSW      # inspection channels now apply


class DeadConn:
    def cursor(self): raise RuntimeError("DB IS DOWN")


for label, conn in (("dead DB", DeadConn()), ("pg_conn=None", None)):
    att = ev.verify(anchor, n_control_anchors=CTRL, seed=1, pg_conn=conn)
    c = att.bound.classify()
    check(f"inspection unreachable ({label}) does not pass",
          not att.bound.is_pass(), c)
    check(f"unmeasured channels are named ({label})",
          len(att.bound.inspection_unavailable) == 3,
          ",".join(att.bound.inspection_unavailable))

res = PgVectorInspector.run_all(DeadConn(), "documents", "idx")
check("every failed inspection query -> UNAVAILABLE, never CLEAN",
      all(r.status is ChannelStatus.UNAVAILABLE for r in res))

ev.engine = EngineType.GENERIC


# ==================================================================
print("\n=== I2: a present subject is NEVER classified as erased ===")

for label, keep_text in (("token still in text", True),
                         ("text scrubbed, ghost vector", False)):
    e2, a2 = scenario(11 if keep_text else 13,
                      b"k-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" if keep_text
                      else b"k-cccccccccccccccccccccccccccccc",
                      "Ravi Kumar" if keep_text else "Asha Rao",
                      "id_99" if keep_text else "id_7",
                      present=True, keep_text=keep_text)
    att = e2.verify(a2, n_control_anchors=CTRL, seed=2)
    b = att.bound
    check(f"present subject not passed ({label})", not b.is_pass(),
          f"{b.classify()} p={b.p_value:.4f} subj={b.subject_score:.4f} "
          f"ctrl_med={b.control_median:.4f}")


# ==================================================================
print("\n=== Positive case: genuine erasure ===")

ev3, a3 = scenario(21, b"k-dddddddddddddddddddddddddddddd", "Meera Nair",
                   "id_5", present=False, keep_text=True)
attA = ev3.verify(a3, n_control_anchors=CTRL, seed=3)
b = attA.bound
check("erased subject passes", b.is_pass(),
      f"{b.classify()} p={b.p_value:.4f} radius={b.probe_radius:.4f}")
check("sweep found nothing", b.deterministic_findings == 0)


# ==================================================================
print("\n=== I3: confidence comes from controls, not probe count ===")

ev4, a4 = scenario(31, b"k-eeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "Test Subject",
                   "id_x", present=False, keep_text=True)
att = ev4.verify(a4, n_treatment=5000, n_control_anchors=10, seed=4)
check("10 controls + 5000 probes stays inconclusive",
      att.bound.classify() == "INCONCLUSIVE_CONTROLS",
      f"{att.bound.classify()} min_p={att.bound.min_attainable_p:.4f}")

att = ev4.verify(a4, n_treatment=40, n_control_anchors=30, seed=5)
check("30 controls -> min_p ~ 1/31, cannot claim p<=0.01",
      abs(att.bound.min_attainable_p - 1 / 31) < 1e-9
      and att.bound.classify() == "MODERATE_EVIDENCE_ERASED",
      f"min_p={att.bound.min_attainable_p:.4f} {att.bound.classify()}")


# ==================================================================
print("\n=== Null calibration: p should be ~uniform ===")

ps = []
for s in range(15):
    r = np.random.default_rng(300 + s)
    stn = build(r)
    e = ErasureVerifier(store=stn)
    ps.append(e.verify(e.register(f"n{s}", r.normal(size=DIM).astype(np.float32)),
                       n_control_anchors=CTRL, seed=s).bound.p_value)
ps = np.array(ps)
check("null p-values approximately uniform", 0.30 <= ps.mean() <= 0.70,
      f"mean={ps.mean():.3f} frac<=0.05={np.mean(ps <= 0.05):.3f}")


# ==================================================================
print("\n=== Paired pre/post test on clustered (realistic) embeddings ===")

D2 = 384


def clustered(rng, n=1200, nc=25, spread=0.18):
    C = rng.normal(size=(nc, D2))
    C /= np.linalg.norm(C, axis=1, keepdims=True)
    out = []
    for i in range(n):
        c = C[i % nc] + rng.normal(scale=spread, size=D2)
        out.append((c / np.linalg.norm(c)).astype(np.float32))
    return np.array(out)


def paired_case(label, jitter, expect_present, expect_erased):
    rng = np.random.default_rng(5)
    V = clustered(rng)
    st = InMemoryConnector()
    st.upsert([VectorRecord(id=f"v{i}", vector=V[i], source_text="x", metadata={})
               for i in range(len(V))])
    g = V[3] + rng.normal(scale=jitter, size=D2)
    g = (g / np.linalg.norm(g)).astype(np.float32)
    st.upsert([VectorRecord(id="subj", vector=g, source_text="[REDACTED]", metadata={})])
    e = ErasureVerifier(store=st)
    a = e.register("s", g, record_id="subj", seed=1)
    bp = e.verify(a, n_control_anchors=CTRL, seed=1).bound
    st.delete(["subj"])
    be = e.verify(a, n_control_anchors=CTRL, seed=1).bound
    check(f"{label}: present -> {expect_present}", bp.classify() == expect_present,
          f"{bp.classify()} paired={bp.paired_verdict}")
    check(f"{label}: erased -> {expect_erased}", be.classify() == expect_erased,
          f"{be.classify()} paired={be.paired_verdict} p={be.p_value:.4f}")
    return be


paired_case("distinct subject", 0.35, "RESIDUE_DETECTED", "STRONG_EVIDENCE_ERASED")
# Near-duplicate: the conformal test alone false-positives here (p=0.0099
# because the region is legitimately dense). The paired test overrides.
be = paired_case("near-duplicate", 0.02, "RESIDUE_DETECTED", "STRONG_EVIDENCE_ERASED")
check("paired test overrides a conformal false positive",
      be.p_value <= 0.05 and be.paired_verdict == "erased",
      f"p={be.p_value:.4f} paired={be.paired_verdict}")

# Exact duplicate: hypotheses are not separable; must refuse to answer.
rng = np.random.default_rng(9)
V = rng.normal(size=(600, D2))
V /= np.linalg.norm(V, axis=1, keepdims=True)
st = InMemoryConnector()
st.upsert([VectorRecord(id=f"v{i}", vector=V[i].astype(np.float32),
                        source_text="x", metadata={}) for i in range(600)])
g = V[10].astype(np.float32)
st.upsert([VectorRecord(id="subj", vector=g, source_text="[REDACTED]", metadata={})])
e = ErasureVerifier(store=st)
a = e.register("s", g, record_id="subj", seed=1)
st.delete(["subj"])
b = e.verify(a, n_control_anchors=CTRL, seed=1).bound
check("exact duplicate -> refuses to answer",
      b.classify() == "INCONCLUSIVE_INDISTINGUISHABLE" and not b.is_pass(),
      f"{b.classify()} sep={b.separation:.5f}")


print("\n=== Pinecone adapter ===")

from aagcp.store.connectors import PineconeConnector
from aagcp.verify import PineconeProbeAdapter, MockPineconeIndex, EngineType

PC_DIM = 256


def pc_setup(metric, present):
    rng = np.random.default_rng(4)
    ix = MockPineconeIndex(PC_DIM, metric=metric)
    C = rng.normal(size=(20, PC_DIM))
    C /= np.linalg.norm(C, axis=1, keepdims=True)
    vecs = []
    for i in range(600):
        v = C[i % 20] + rng.normal(scale=0.25, size=PC_DIM)
        vecs.append((v / np.linalg.norm(v)).astype(np.float32))
    ix.upsert(namespace="", vectors=[
        {"id": f"v{i}", "values": vecs[i], "metadata": {"source_text": f"rec {i}"}}
        for i in range(600)])
    g = C[3] + rng.normal(scale=0.30, size=PC_DIM)
    g = (g / np.linalg.norm(g)).astype(np.float32)
    ix.upsert(namespace="", vectors=[
        {"id": "subj", "values": g, "metadata": {"source_text": "[REDACTED]"}}])
    ad = PineconeProbeAdapter(PineconeConnector(ix, namespace=""))
    ev = ErasureVerifier(store=ad)
    a = ev.register("s", g, record_id="subj", seed=1)
    if not present:
        ix.delete(ids=["subj"], namespace="")
    return ix, ev, a, ad


ix0, ev0, a0, ad0 = pc_setup("cosine", True)
check("engine autodetected as PINECONE", ev0.engine is EngineType.PINECONE)
check("adapter samples control vectors the connector cannot supply",
      len(ad0.sample_vectors(50, PC_DIM, seed=1)) >= 40)
check("connector alone yields no vectors (why the adapter exists)",
      all(r.vector is None for b in PineconeConnector(ix0, namespace="").iter_all()
          for r in b))

for metric in ("cosine", "euclidean", "dotproduct"):
    ix, ev, a, ad = pc_setup(metric, True)
    b = ev.verify(a, n_control_anchors=100, seed=1).bound
    # I2 on every metric. Without score negation, euclidean inverts here.
    check(f"pinecone/{metric}: present subject not passed",
          not b.is_pass() and b.paired_verdict == "present",
          f"{b.classify()} paired={b.paired_verdict}")

    ix, ev, a, ad = pc_setup(metric, False)
    att = ev.verify(a, n_control_anchors=100, seed=1)
    b = att.bound
    check(f"pinecone/{metric}: deleted subject capped at INCONCLUSIVE_UNMEASURED",
          b.classify() == "INCONCLUSIVE_UNMEASURED" and not b.is_pass(),
          f"{b.classify()} paired={b.paired_verdict}")
    check(f"pinecone/{metric}: vector provably still in storage",
          ix.storage_contains("subj"),
          "tombstoned but resident — why the cap is correct")

check("all three pinecone channels reported UNAVAILABLE",
      sorted(b.inspection_unavailable) ==
      ["pinecone.compaction", "pinecone.replication", "pinecone.tombstones"],
      ",".join(sorted(b.inspection_unavailable)))

claim = PineconeProbeAdapter.attest_non_retrievability(att)
check("non-retrievability claim issued and correctly narrowed",
      "NON-RETRIEVABILITY ATTESTED" in claim and "does NOT attest" in claim.replace(
          "It does NOT attest", "does NOT attest"))
print("    " + claim[:150] + "...")


print("\n=== Crypto, serialization, log ===")

d = attA.to_dict()
check("Ed25519 signature verifies", verify_attestation(d, attA.public_key),
      attA.sig_alg)
d["bound"]["p_value"] = 0.99
check("tampered attestation rejected", not verify_attestation(d, attA.public_key))
check("public key is PEM", attA.public_key.startswith("-----BEGIN PUBLIC KEY-----"))
check("canonical JSON: 1e-9 != 4e-7",
      canonical({"e": 1e-9}) != canonical({"e": 4e-7}),
      canonical({"e": 1e-9}))
check("log chain intact", ev3.log.verify_chain())
check("merkle root present", len(attA.commitment.merkle_root) == 64)


# ==================================================================
print("\n=== Anchor privacy ===")

check("anchor handle carries no embedding",
      not any(isinstance(v, (bytes, np.ndarray))
              for v in vars(a3).values()))
check("forget() destroys the anchor", ev3.forget(a3.token_hash))
try:
    ev3.verify(a3, n_control_anchors=CTRL)
    check("verify after forget raises", False)
except ValueError:
    check("verify after forget raises", True)

print("\n" + "=" * 60)
print(f"{'ALL PASS' if not FAILURES else 'FAILURES: ' + ', '.join(FAILURES)}")
sys.exit(1 if FAILURES else 0)
