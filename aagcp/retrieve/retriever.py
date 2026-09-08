"""
Retrieval — governed query over the (now-clean) index.

Dense similarity from the store, optionally blended with BM25 lexical scoring
for robustness on exact-token matches (deterministic tokens make this clean:
the SAME token appears in query and corpus, so lexical matching on tokens
works WITHOUT storing any raw PII — unlike naive schemes that keep originals
in metadata).

After retrieval, results are rehydrated per the caller's role. The vector DB
returns identical bytes to every role; the layer decides what is revealed.
"""

from __future__ import annotations
import math
import re
import logging
from typing import List, Optional
from collections import Counter

from ..embed.embedders import EmbedderAdapter
from ..store.connectors import VectorStoreConnector
from ..vault import PseudonymVault

logger = logging.getLogger(__name__)


def _toks(s: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


def _minmax(vals: List[float]) -> List[float]:
    if not vals:
        return []
    lo = min(vals)
    hi = max(vals)
    if hi - lo < 1e-12:
        return [0.0 for _ in vals]
    return [(v - lo) / (hi - lo) for v in vals]

def _bm25_scores(query_tokens: List[str], docs_tokens: List[List[str]], k1: float = 1.5, b:float=0.75) -> List[float]:
    n_docs = len(docs_tokens)
    if n_docs == 0:
        return []

    docs_lens = [len(d) for d in docs_tokens]
    avgdl = (sum(docs_lens)/n_docs) if n_docs else 0.0
    if avgdl <= 0.0:
        return [0.0 for _ in docs_tokens]
    
    df = Counter()
    for d in docs_tokens:
        for t in set(d):
            df[t] += 1

    q_terms = Counter(query_tokens)
    scores: List[float] = []

    for d, dl in zip(docs_tokens, docs_lens):
        tf = Counter(d)
        score = 0.0
        denom_norm = k1 * (1.0 - b + b * (dl / avgdl))

        for term, qf in q_terms.items():
            f = tf.get(term, 0)
            if f == 0:
                continue

            n_q = df.get(term, 0)
            idf = math.log(1.0 + (n_docs - n_q + 0.5) / (n_q + 0.5))
            score += qf * idf * ((f * (k1 + 1.0)) / (f + denom_norm))

        scores.append(score)

    return scores


def _contains_any_token(text: str, tokens: set[str]) -> bool:
    if not text or not tokens:
        return False
    for tok in tokens:
        if tok in text:
            return True
        esc = tok.replace("<", "&lt;").replace(">", "&gt;")
        if esc in text:
            return True
    return False


def _looks_like_person_name_query(text: str) -> bool:
    """Heuristic: plain alphabetic full name query (e.g., 'Kavya Pillai')."""
    q = (text or "").strip()
    if not q:
        return False
    # 2-4 alphabetic tokens, no digits/symbol-heavy identifiers.
    return bool(re.fullmatch(r"[A-Za-z]{2,}(?:\s+[A-Za-z]{2,}){1,3}", q))


def _extract_identifier_snippets(text: str) -> dict[str, set[str]]:
    """Extract high-signal identifier-like snippets from free-text query.

    This intentionally does not validate checksums so user-entered values with
    typos around labels (e.g. 'adhaar') can still be resolved via vault keys.
    """
    s = text or ""
    out: dict[str, set[str]] = {}

    patterns = {
        "AADHAAR": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.I),
        "MRN": re.compile(r"\bMRN[-:\s]?\d{5,10}\b", re.I),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    }

    for etype, pat in patterns.items():
        vals = {m.group(0).strip() for m in pat.finditer(s)}
        if vals:
            out[etype] = vals

    return out


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _token_prefixes_for_identifier_type(etype: str) -> tuple[str, ...]:
    if etype == "EMAIL":
        return ("<EMAIL_", "<EMAIL_ADDRESS_")
    return (f"<{etype}_",)



class GovernedRetriever:
    def __init__(self, store: VectorStoreConnector, embedder: EmbedderAdapter,
                 vault: PseudonymVault, detector=None):
        self.store = store
        self.embedder = embedder
        self.vault = vault
        self.detector = detector          # to tokenize PII in the query itself

    def query(
        self,
        text: str,
        role_reveal: set,
        role_partial: dict,
        k: int = 20,                # return top 20 chunks
        hybrid: bool = True,        # embed + BM25 by default
        candidate_k: int = 100,     # dense fetch pool for rerank recall
        dense_weight: float = 0.45, # 0.45 dense + 0.55 lexical
        max_identity_matches: int = 3,
    ) -> List[dict]:
        q = text
        if self.detector:
            findings = self.detector.scan(text)
            for f in sorted(findings, key=lambda x: x.start, reverse=True):
                tok = self.vault.token_for(f)
                q = q[:f.start] + tok + q[f.end:]

        query_id_hits: List[str] = []
        if hasattr(self.vault, "resolve_identities_by_query"):
            query_id_hits = self.vault.resolve_identities_by_query(text)
        elif hasattr(self.vault, "resolve_identities_by_name"):
            query_id_hits = self.vault.resolve_identities_by_name(text)

        # Mixed query support: extract exact identifier snippets from raw query
        # (works even when label is misspelled, e.g. 'adhaar').
        identifier_snippets = _extract_identifier_snippets(text)
        identifier_id_hits: List[str] = []
        if identifier_snippets and hasattr(self.vault, "resolve_identities_by_name"):
            for vals in identifier_snippets.values():
                for v in vals:
                    identifier_id_hits.extend(self.vault.resolve_identities_by_name(v))

        matched_ids = _dedupe_preserve_order(identifier_id_hits + query_id_hits)

        if max_identity_matches > 0:
            matched_ids = matched_ids[:max_identity_matches]

        matched_tokens: set[str] = set()
        if hasattr(self.vault, "get_identity_tokens"):
            for iid in matched_ids:
                matched_tokens.update(self.vault.get_identity_tokens(iid))

        # If query contains explicit identifiers, prefer only those token types
        # for identity boost to avoid broad person-name overlap noise.
        if matched_tokens and identifier_snippets:
            id_prefixes = tuple(
                p
                for et in identifier_snippets.keys()
                for p in _token_prefixes_for_identifier_type(et)
            )
            id_only_tokens = {t for t in matched_tokens if t.startswith(id_prefixes)}
            if id_only_tokens:
                logger.info(
                    "[RETRIEVER] Identifier snippets detected; restricting identity boost "
                    f"to identifier tokens ({len(id_only_tokens)} of {len(matched_tokens)})."
                )
                matched_tokens = id_only_tokens

        # Person-name queries should primarily anchor on PERSON tokens; using
        # every linked identifier (AADHAAR/MRN/PHONE) can over-boost a wrong chunk
        # when identity linkage is noisy in migrated historical data.
        if matched_tokens and _looks_like_person_name_query(text):
            person_tokens = {t for t in matched_tokens if t.startswith("<PERSON_")}
            if person_tokens:
                logger.info(
                    "[RETRIEVER] Name-like query detected; restricting identity boost "
                    f"to PERSON tokens ({len(person_tokens)} of {len(matched_tokens)})."
                )
                matched_tokens = person_tokens

        logger.info(f"[RETRIEVER] Query: '{text[:60]}...' | matched_ids={len(matched_ids)} ids | {len(matched_tokens)} matched_tokens")
        if identifier_snippets:
            logger.info(f"           Identifier snippets: { {k: sorted(list(v))[:2] for k, v in identifier_snippets.items()} }")
        if matched_ids:
            logger.info(f"           Identity IDs: {matched_ids[:3]}")  # Show first 3
            logger.info(f"           Tokens: {sorted(list(matched_tokens))[:3]}")  # Show first 3 tokens

        if matched_tokens:
            q = f"{q} " + " ".join(sorted(matched_tokens))

        qvec = self.embedder.embed(q)
        fetch_k = max(candidate_k, k)
        hits = self.store.query(qvec, k=fetch_k)

        if hybrid and hits:
            q_tokens = _toks(q)
            docs_tokens = [_toks(h.get("source_text") or "") for h in hits]

            bm25_raw = _bm25_scores(q_tokens, docs_tokens)
            dense_raw = [float(h.get("score", 0.0)) for h in hits]

            bm25_norm = _minmax(bm25_raw)
            dense_norm = _minmax(dense_raw)

            lexical_weight = 1.0 - dense_weight
            logger.info(f"[RETRIEVER] Weights: dense={dense_weight:.2f}, lexical={lexical_weight:.2f} | Total hits: {len(hits)}")
            
            for i, h in enumerate(hits):
                txt = h.get("source_text") or ""
                vault_boost = 0.35 if _contains_any_token(txt, matched_tokens) else 0.0
                h["dense_score"] = dense_raw[i]
                h["bm25_score"] = bm25_raw[i]
                h["vault_boost"] = vault_boost
                h["score"] = (
                    dense_weight * dense_norm[i]
                    + lexical_weight * bm25_norm[i]
                    + vault_boost
                )
                
                # Log top results for debugging
                if i < 3 or vault_boost > 0:
                    logger.info(f"  [{i}] {h['id'][:30]}... | "
                               f"dense_raw={dense_raw[i]:.4f} * {dense_weight} = {dense_weight * dense_norm[i]:.4f} | "
                               f"bm25_raw={bm25_raw[i]:.4f} * {lexical_weight} = {lexical_weight * bm25_norm[i]:.4f} | "
                               f"vault_boost={vault_boost} | final_score={h['score']:.4f}")

            hits = sorted(hits, key=lambda x: -x["score"])[:k]
            logger.info(f"[RETRIEVER] Top {min(k, len(hits))} results after reranking:")
            for i, h in enumerate(hits[:5]):
                logger.info(f"  #{i+1} {h['id'][:40]}... score={h['score']:.4f}")
        else:
            hits = hits[:k]

        for h in hits:
            h["text"] = self.vault.rehydrate(
                h.get("source_text") or "",
                role_reveal,
                role_partial,
            )

        return hits
