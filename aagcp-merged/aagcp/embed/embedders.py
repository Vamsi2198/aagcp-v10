"""
Embedder adapters.

HashingEmbedder   — deterministic, dependency-free; proves all logic here.
SentenceTransformerEmbedder — real model (all-MiniLM-L6-v2 etc.); written
                    against the real API, enabled when the package is
                    installed. Same interface, so the engine is unchanged.
"""

from __future__ import annotations
import hashlib
import re
from abc import ABC, abstractmethod
from typing import List
import numpy as np


class EmbedderAdapter(ABC):
    dim: int
    name: str

    @abstractmethod
    def embed(self, text: str) -> np.ndarray: ...

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        return np.vstack([self.embed(t) for t in texts])


class HashingEmbedder(EmbedderAdapter):
    """Feature-hashing over words + char trigrams. Deterministic, no deps."""
    name = "hashing"

    def __init__(self, dim: int = 384):
        self.dim = dim

    def embed(self, text: str) -> np.ndarray:
        text = text.lower()
        words = re.findall(r"[a-z0-9<>_]+", text)
        feats = list(words)
        joined = " ".join(words)
        feats += [joined[i:i+3] for i in range(len(joined) - 2)]
        v = np.zeros(self.dim, dtype=np.float32)
        for f in feats:
            h = int(hashlib.md5(f.encode()).hexdigest(), 16)
            v[h % self.dim] += 1.0 if (h >> 1) % 2 else -1.0
        n = np.linalg.norm(v)
        return v / n if n else v


class SentenceTransformerEmbedder(EmbedderAdapter):
    """
    Real semantic embeddings. pip install sentence-transformers.
        emb = SentenceTransformerEmbedder("all-MiniLM-L6-v2")
    Normalizes to unit length so inner product == cosine (matches the stores).
    """
    name = "sentence_transformers"

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self._m = SentenceTransformer(model_name)
        self.dim = self._m.get_sentence_embedding_dimension()

    def embed(self, text: str) -> np.ndarray:
        return self._m.encode(text, normalize_embeddings=True).astype(np.float32)

    def embed_batch(self, texts):
        return self._m.encode(texts, normalize_embeddings=True).astype(np.float32)


class OpenAIEmbedder(EmbedderAdapter):
    """
    OpenAI embeddings via API — NO torch, tiny memory footprint, so it deploys
    on free tiers where sentence-transformers/torch runs out of memory.
        pip install openai ; export OPENAI_API_KEY=...
    Vectors are already unit-normalized by OpenAI, matching the stores.
    """
    name = "openai"

    def __init__(self, model: str = "text-embedding-3-small", api_key: str = None):
        from openai import OpenAI
        self._client = OpenAI(api_key=api_key) if api_key else OpenAI()
        self._model = model
        self.dim = 1536 if "small" in model else 3072

    def embed(self, text: str) -> np.ndarray:
        r = self._client.embeddings.create(model=self._model, input=text or " ")
        return np.array(r.data[0].embedding, dtype=np.float32)

    def embed_batch(self, texts):
        r = self._client.embeddings.create(model=self._model,
                                           input=[t or " " for t in texts])
        return np.vstack([np.array(d.embedding, dtype=np.float32) for d in r.data])


def auto_embedder(dim: int = 384):
    """
    Pick the best available embedder without failing:
      OPENAI_API_KEY set & dim matches  -> OpenAIEmbedder (API, no torch, deploy-friendly)
      SentenceTransformers available    -> SentenceTransformerEmbedder (no API needed)
      else                              -> HashingEmbedder (dependency-free, always runs)
    This is what lets the same app run on a laptop, a free-tier host, or prod.
    """
    import os
    
    # Try OpenAI only if dimension matches (1536 for small, 3072 for large)
    if os.environ.get("OPENAI_API_KEY") and dim in (1536, 3072):
        try:
            return OpenAIEmbedder()
        except Exception:
            pass
    
    # Try SentenceTransformer for other dimensions
    try:
        return SentenceTransformerEmbedder()
    except Exception:
        pass
    
    # Fall back to hashing
    return HashingEmbedder(dim)
