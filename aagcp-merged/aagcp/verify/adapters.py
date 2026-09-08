"""
aagcp/verify/adapters.py

Store adapters for erasure verification. ADDITIVE ONLY — nothing in
aagcp/store/connectors.py is modified. Each adapter wraps an existing
connector and supplies only what the verifier needs on top of it.

WHY PINECONE NEEDS AN ADAPTER
-----------------------------
Three things in PineconeConnector make it unusable for probing as-is. None
are bugs in the connector — they are fine for its own job (scan, tokenize,
retrieve) and simply do not carry what a verifier needs.

1. NO VECTOR VALUES.  _extract_records_from_fetch builds every record as
   VectorRecord(vid, None, ...). The verifier's control sampler skips
   rec.vector is None, so it would find zero control anchors and every
   verification would return INCONCLUSIVE_CONTROLS. The adapter fetches with
   include_values=True.

2. FULL SCAN DOES NOT SCALE.  iter_all pages list() across the whole index
   then fetches in chunks of 50. Reservoir-sampling 100 anchors out of 10M
   vectors is ~200k round trips. The adapter samples by firing random query
   vectors with include_values=True — one call each, ~100 calls total. The
   sample is biased toward dense regions, which is stated in the attestation
   and is the conservative direction: dense regions make the control
   distribution harder to exceed, so residue is under-reported rather than
   over-reported.

3. METRIC SIGN.  The verifier assumes higher score = nearer. True for cosine
   and dotproduct; FALSE for euclidean, where Pinecone returns squared
   distance and lower is nearer. Unfixed, a euclidean index inverts the
   paired test and a present subject reads as erased — an I2 violation. The
   adapter reads the index metric and negates distance-like scores.

WHAT THE ADAPTER CANNOT FIX
---------------------------
Pinecone exposes no tombstone count, no compaction state, no replica lag.
EngineType.PINECONE therefore declares those three channels permanently
UNAVAILABLE, which caps a Pinecone attestation at INCONCLUSIVE_UNMEASURED.

That cap is correct, not a defect. On Pinecone you can honestly attest that
a subject is NOT RETRIEVABLE THROUGH THE QUERY API over the sampled index
state. You cannot attest the vector is gone, because the platform gives you
no way to look. Use attest_non_retrievability() to emit that narrower claim
explicitly rather than dressing it up as erasure.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Iterator, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class PineconeProbeAdapter:
    """Wraps a PineconeConnector. Presents the store interface the verifier
    uses (name / count / query / iter_all) plus sample_vectors()."""

    name = "pinecone"

    #: metrics where a higher score means nearer
    _SIMILARITY_METRICS = {"cosine", "dotproduct", "dot_product"}

    def __init__(self, connector, metric: Optional[str] = None,
                 namespaces: Optional[Sequence[str]] = None):
        self._c = connector
        self._ix = getattr(connector, "_ix", None)
        self._ns = getattr(connector, "_ns", "") or ""
        self.metric = (metric or self._detect_metric() or "cosine").lower()
        self.higher_is_nearer = self.metric in self._SIMILARITY_METRICS
        self.namespaces = list(namespaces) if namespaces else self._detect_namespaces()
        if not self.higher_is_nearer:
            logger.info("[PINECONE-ADAPTER] metric=%s is a distance; scores "
                        "will be negated so higher = nearer", self.metric)
        if len(self.namespaces) > 1:
            logger.warning(
                "[PINECONE-ADAPTER] index has %d namespaces %s — Pinecone "
                "deletes are per-namespace. This verification covers '%s' "
                "ONLY. Run one verification per namespace the subject "
                "appears in.", len(self.namespaces), self.namespaces, self._ns)

    # ---------- introspection ----------

    def _describe(self) -> dict:
        try:
            st = self._ix.describe_index_stats()
            return st if isinstance(st, dict) else (
                st.to_dict() if hasattr(st, "to_dict") else {})
        except Exception as e:
            logger.info("[PINECONE-ADAPTER] describe_index_stats failed: %s", e)
            return {}

    def _detect_metric(self) -> Optional[str]:
        for src in (self._ix, self._c):
            for attr in ("metric", "_metric"):
                v = getattr(src, attr, None)
                if isinstance(v, str) and v:
                    return v
        d = self._describe()
        for key in ("metric", "index_metric"):
            if isinstance(d.get(key), str):
                return d[key]
        logger.warning("[PINECONE-ADAPTER] could not detect index metric; "
                       "assuming cosine. Pass metric= explicitly if this "
                       "index uses euclidean, or the paired test will invert.")
        return None

    def _detect_namespaces(self) -> List[str]:
        d = self._describe()
        ns = d.get("namespaces") or {}
        try:
            return sorted(ns.keys())
        except Exception:
            return []

    def dimension(self) -> Optional[int]:
        d = self._describe()
        v = d.get("dimension")
        return int(v) if v else None

    # ---------- store interface used by the verifier ----------

    def count(self) -> int:
        return int(self._c.count())

    def iter_all(self, batch: int = 500) -> Iterator[list]:
        """Delegated. Used only by the deterministic sweep, which needs
        source_text and metadata (both of which the connector does return)."""
        return self._c.iter_all(batch=batch)

    def _norm_score(self, raw: float) -> float:
        return float(raw) if self.higher_is_nearer else -float(raw)

    def query(self, vector, k: int = 5, where=None) -> List[dict]:
        rows = self._c.query(vector, k=k, where=where)
        for r in rows:
            r["score"] = self._norm_score(r.get("score", 0.0))
        return rows

    # ---------- the piece the connector cannot provide ----------

    def sample_vectors(self, m: int, dim: int,
                       seed: Optional[int] = None) -> List[Tuple[str, np.ndarray]]:
        """Sample up to m (id, vector) pairs using random query probes.

        Each call returns top_k matches WITH values, so a handful of random
        directions yields a spread of real vectors at a cost that does not
        grow with index size.
        """
        if self._ix is None:
            return []
        rng = np.random.default_rng(seed)
        out: dict = {}
        top_k = max(2, min(20, m))
        # over-sample directions because random queries collide in dense regions
        for _ in range(min(400, 3 * (m // top_k + 2))):
            if len(out) >= m:
                break
            q = rng.normal(size=dim)
            q /= (np.linalg.norm(q) + 1e-12)
            try:
                res = self._ix.query(
                    namespace=self._ns or None, vector=[float(x) for x in q],
                    top_k=top_k, include_values=True, include_metadata=False)
            except Exception as e:
                logger.warning("[PINECONE-ADAPTER] sampling query failed: %s", e)
                break
            matches = (res.get("matches") if isinstance(res, dict)
                       else getattr(res, "matches", None)) or []
            for mt in matches:
                mid = mt["id"] if isinstance(mt, dict) else getattr(mt, "id", None)
                vals = (mt.get("values") if isinstance(mt, dict)
                        else getattr(mt, "values", None))
                if mid is None or not vals:
                    continue
                v = np.asarray(vals, dtype=np.float32).ravel()
                if v.shape[0] == dim:
                    out[mid] = v
        if not out:
            logger.warning(
                "[PINECONE-ADAPTER] sampling returned no values. The index may "
                "be empty, or this Pinecone build ignores include_values.")
        return list(out.items())[:m]

    # ---------- narrower claim appropriate to a black-box engine ----------

    @staticmethod
    def attest_non_retrievability(att) -> str:
        """Restate a Pinecone attestation as the claim it actually supports.

        Pinecone can never reach STRONG_EVIDENCE_ERASED, because its internal
        channels are permanently UNAVAILABLE. That is not a failed run — it is
        the honest ceiling, and this is the sentence to put on the certificate.
        """
        b = att.bound
        if b.deterministic_findings or b.inspection_residue:
            return ("NOT ERASED. Direct evidence found; the subject remains "
                    "present. No non-retrievability claim can be made.")
        if b.paired_verdict == "present" or (b.n_control_anchors >= 19
                                             and b.p_value <= 0.05):
            return ("RESIDUE. The subject's region is still distinguishable "
                    "through the query API; the subject remains retrievable.")
        if b.n_control_anchors < 19:
            return (f"INCONCLUSIVE. Only {b.n_control_anchors} control anchors "
                    f"sampled; a conformal p-value cannot fall below "
                    f"1/(m+1). No claim issued.")
        return (
            f"NON-RETRIEVABILITY ATTESTED (Pinecone, namespace-scoped). Over "
            f"the sampled index state, the subject's region is statistically "
            f"indistinguishable from {b.n_control_anchors} matched control "
            f"regions (conformal p={b.p_value:.4f}; paired verdict "
            f"'{b.paired_verdict}'). This attests that the subject is NOT "
            f"RETRIEVABLE THROUGH THE QUERY API. It does NOT attest that the "
            f"vector has been removed from storage: Pinecone exposes no "
            f"tombstone count, compaction state or replica lag, so "
            f"{', '.join(b.inspection_unavailable)} are UNMEASURED. Deletes "
            f"are per-namespace and eventually consistent."
        )


class MockPineconeIndex:
    """Test double reproducing the Pinecone behaviours that matter here:
    values only on include_values, per-namespace deletes, configurable metric,
    and TOMBSTONES — deleted vectors are filtered from query results while
    remaining in storage, exactly the residue a query-path probe cannot see.
    """

    def __init__(self, dim: int, metric: str = "cosine"):
        self.dim = dim
        self.metric = metric
        self._ns: dict = {}
        self._tombstoned: dict = {}

    def _store(self, ns):
        return self._ns.setdefault(ns or "", {})

    def _tomb(self, ns):
        return self._tombstoned.setdefault(ns or "", {})

    def describe_index_stats(self):
        return {"dimension": self.dim, "metric": self.metric,
                "total_vector_count": sum(len(v) for v in self._ns.values()),
                "namespaces": {k: {"vector_count": len(v)}
                               for k, v in self._ns.items()}}

    def upsert(self, namespace=None, vectors=None):
        st = self._store(namespace)
        for v in vectors or []:
            st[v["id"]] = (np.asarray(v["values"], dtype=np.float32),
                           v.get("metadata") or {})

    def delete(self, ids=None, namespace=None):
        """Tombstone, not erase — the real behaviour."""
        st, tb = self._store(namespace), self._tomb(namespace)
        for i in ids or []:
            if i in st:
                tb[i] = st.pop(i)

    def storage_contains(self, vid, namespace=None) -> bool:
        """Not a Pinecone API. Ground truth for tests only."""
        return vid in self._tomb(namespace) or vid in self._store(namespace)

    def _score(self, a, b):
        if self.metric == "euclidean":
            return float(np.sum((a - b) ** 2))
        if self.metric == "dotproduct":
            return float(np.dot(a, b))
        na, nb = np.linalg.norm(a) + 1e-12, np.linalg.norm(b) + 1e-12
        return float(np.dot(a, b) / (na * nb))

    def query(self, namespace=None, vector=None, top_k=10,
              include_metadata=False, include_values=False, filter=None):
        q = np.asarray(vector, dtype=np.float32)
        rows = []
        for vid, (v, md) in self._store(namespace).items():
            rows.append((self._score(q, v), vid, v, md))
        rows.sort(key=lambda r: r[0], reverse=(self.metric != "euclidean"))
        out = []
        for sc, vid, v, md in rows[:top_k]:
            m = {"id": vid, "score": sc}
            if include_metadata:
                m["metadata"] = md
            if include_values:
                m["values"] = [float(x) for x in v]
            out.append(m)
        return {"matches": out}

    def list(self, namespace=None):
        yield {"vectors": [{"id": i} for i in self._store(namespace)]}

    def fetch(self, ids=None, namespace=None):
        st = self._store(namespace)
        return {"vectors": {i: {"metadata": st[i][1]} for i in (ids or []) if i in st}}
