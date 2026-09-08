"""
VectorStoreConnector — the plug-and-play seam.

The engine needs exactly five operations from any vector store, so any DB
that can do them plugs in:

    count()                  → how many vectors (for uncapped scanning)
    iter_all(batch)          → stream EVERY vector + its payload (no cap)
    fetch(ids)               → get specific vectors
    upsert(records)          → write/replace vectors (for re-embed migration)
    query(vector, k, filter) → similarity search (retrieval)
    delete(ids)              → remove vectors (quarantine fallback)

InMemoryConnector is the runnable reference (proven here). The Pinecone,
Qdrant, and pgvector connectors are written against each client's real API
and gated on that client being installed — smoke-tested in your environment.

Payload convention: each vector carries {"source_text": ..., "metadata": {...}}.
'source_text' is what we re-embed from during cleaning. If a production index
does NOT store source text, cleaning degrades to quarantine/delete — see
engine.py. This is a physics limit, surfaced honestly, not hidden.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional
import numpy as np
import logging

logger = logging.getLogger(__name__)


@dataclass
class VectorRecord:
    id: str
    vector: Optional[np.ndarray]
    source_text: Optional[str]
    metadata: dict = field(default_factory=dict)


class VectorStoreConnector(ABC):
    name: str = "abstract"

    @abstractmethod
    def count(self) -> int: ...

    @abstractmethod
    def iter_all(self, batch: int = 500) -> Iterator[List[VectorRecord]]:
        """Stream ALL records in batches. No limit — scans the whole index."""

    @abstractmethod
    def fetch(self, ids: List[str]) -> List[VectorRecord]: ...

    @abstractmethod
    def upsert(self, records: List[VectorRecord]): ...

    @abstractmethod
    def query(self, vector: np.ndarray, k: int = 5,
              where: Optional[dict] = None) -> List[dict]: ...

    @abstractmethod
    def delete(self, ids: List[str]): ...


class InMemoryConnector(VectorStoreConnector):
    """Runnable reference store — simulates a production index (proven here)."""
    name = "in_memory"

    def __init__(self):
        self._data: Dict[str, VectorRecord] = {}

    def count(self) -> int:
        return len(self._data)

    def iter_all(self, batch: int = 500):
        items = list(self._data.values())
        for i in range(0, len(items), batch):
            yield items[i:i + batch]

    def fetch(self, ids):
        return [self._data[i] for i in ids if i in self._data]

    def upsert(self, records):
        for r in records:
            self._data[r.id] = r

    def query(self, vector, k=5, where=None):
        qn = np.linalg.norm(vector)
        q = vector / qn if qn > 0 else vector

        rows = []
        for r in self._data.values():
            if r.vector is None:
                continue
            if where and not all(r.metadata.get(kk) == vv for kk, vv in where.items()):
                continue
            rn = np.linalg.norm(r.vector)
            if rn == 0:
                continue
            sim = float(np.dot(q, r.vector / rn))  # true cosine similarity
            rows.append({"id": r.id, "score": sim,
                        "source_text": r.source_text, "metadata": r.metadata})
        return sorted(rows, key=lambda x: -x["score"])[:k]

    def delete(self, ids):
        for i in ids:
            self._data.pop(i, None)


# ── Real production adapters (written; enabled when the client is installed) ──

class PineconeConnector(VectorStoreConnector):
    """
    Pinecone. pip install pinecone-client.
        from pinecone import Pinecone
        pc = Pinecone(api_key=...); index = pc.Index(host=...)
    iter_all uses index.list()/fetch paginated; upsert/query/delete map 1:1.
    Store source_text in metadata at ingest so cleaning can re-embed from it.
    """
    name = "pinecone"

    def __init__(self, index, namespace: str = ""):
        self._ix = index
        self._ns = namespace
        logger.info(f"[PINECONE] Connector initialized with namespace='{namespace}'")
        # Pinecone fetch uses query params; large ID lists can trip 414 URI limits.
        self._fetch_id_chunk_size = 50

    def count(self):
        return int(self._ix.describe_index_stats().get("total_vector_count", 0))

    def _extract_ids_from_list_response(self, list_response):
        ids = []
        if hasattr(list_response, 'vectors') and list_response.vectors:
            for item in list_response.vectors:
                if hasattr(item, 'id'):
                    ids.append(item.id)
                elif isinstance(item, dict) and 'id' in item:
                    ids.append(item['id'])
        elif isinstance(list_response, dict) and 'vectors' in list_response:
            for item in list_response['vectors'] or []:
                if isinstance(item, dict) and 'id' in item:
                    ids.append(item['id'])
        return ids

    def _get_id_and_metadata(self, item):
        if item is None:
            return None, {}
        if isinstance(item, dict):
            vid = item.get('id')
            md = item.get('metadata') or item.get('meta') or {}
        elif isinstance(item, tuple) and len(item) == 2:
            vid, item_value = item
            if isinstance(vid, str):
                md = getattr(item_value, 'metadata', None) or getattr(item_value, 'meta', None) or {}
            else:
                vid = None
                md = {}
        else:
            vid = getattr(item, 'id', None)
            md = getattr(item, 'metadata', None) or getattr(item, 'meta', None) or {}
        if hasattr(md, 'to_dict'):
            try:
                md = md.to_dict()
            except Exception:
                md = dict(md or {})
        elif not isinstance(md, dict):
            md = dict(md or {})
        return vid, md

    def _extract_records_from_fetch(self, fetched):
        recs = []
        vectors = None
        payload = None
        if hasattr(fetched, 'vectors'):
            vectors = fetched.vectors
        elif isinstance(fetched, dict):
            payload = fetched
            vectors = fetched.get('vectors')
        elif hasattr(fetched, 'to_dict'):
            payload = fetched.to_dict()
            vectors = payload.get('vectors')
        else:
            vectors = None

        if payload is None and hasattr(fetched, 'to_dict'):
            payload = fetched.to_dict()
        if payload is None and isinstance(fetched, dict):
            payload = fetched

        if vectors is None and isinstance(payload, dict):
            vectors = payload.get('results') or payload.get('items') or payload.get('vectors')
            if hasattr(vectors, '__len__') and len(vectors) == 0:
                vectors = None

            def looks_like_vector_map(candidate):
                if not isinstance(candidate, dict) or not candidate:
                    return False
                sample_vals = list(candidate.values())[:3]
                return all(
                    isinstance(val, dict) and (
                        'metadata' in val or 'meta' in val or 'values' in val or hasattr(val, 'metadata') or hasattr(val, 'values')
                    )
                    for val in sample_vals
                )

            def find_vector_container(obj, depth=0):
                if depth > 5 or not isinstance(obj, dict):
                    return None
                if looks_like_vector_map(obj):
                    return obj
                for key, value in obj.items():
                    if isinstance(value, dict):
                        found = find_vector_container(value, depth + 1)
                        if found is not None:
                            return found
                    elif isinstance(value, list):
                        for item in value[:5]:
                            if isinstance(item, dict):
                                found = find_vector_container(item, depth + 1)
                                if found is not None:
                                    return found
                return None

            if vectors is None:
                if looks_like_vector_map(payload):
                    vectors = payload
                elif len(payload) == 1:
                    nested = next(iter(payload.values()))
                    if looks_like_vector_map(nested):
                        vectors = nested
                if vectors is None:
                    found = find_vector_container(payload)
                    if found is not None:
                        vectors = found
                        logger.info(
                            "[PINECONE] _extract_records_from_fetch found nested vector container",
                            extra={"vectors_type": type(vectors).__name__, "vectors_len": len(vectors)}
                        )
                if vectors is None:
                    for key in ('results', 'items', 'matches', 'records', 'vectors'):
                        candidate = payload.get(key)
                        if candidate and hasattr(candidate, '__len__') and len(candidate) > 0:
                            vectors = candidate
                            logger.info(
                                "[PINECONE] _extract_records_from_fetch falling back to payload key",
                                extra={"payload_key": key, "candidate_type": type(candidate).__name__, "candidate_len": len(candidate)}
                            )
                            break
                if vectors is None:
                    for key, candidate in payload.items():
                        if key in ('namespace', 'index', 'status', 'query'):
                            continue
                        if isinstance(candidate, dict) and candidate:
                            vectors = candidate
                            logger.info(
                                "[PINECONE] _extract_records_from_fetch using non-empty payload field",
                                extra={"payload_key": key, "candidate_type": type(candidate).__name__, "candidate_len": len(candidate)}
                            )
                            break
                        if isinstance(candidate, list) and candidate:
                            vectors = candidate
                            logger.info(
                                "[PINECONE] _extract_records_from_fetch using non-empty payload list",
                                extra={"payload_key": key, "candidate_type": type(candidate).__name__, "candidate_len": len(candidate)}
                            )
                            break
                if vectors is None:
                    logger.info(
                        "[PINECONE] _extract_records_from_fetch could not find vector payload container",
                        extra={"payload_keys": list(payload.keys())}
                    )

        if isinstance(vectors, dict):
            for vid, v in vectors.items():
                item = {'id': vid, 'metadata': getattr(v, 'metadata', None) or (v.get('metadata') if isinstance(v, dict) else None)}
                vid2, md = self._get_id_and_metadata(item)
                if vid2 is not None:
                    recs.append(VectorRecord(vid2, None,
                                            md.get("source_text") or md.get("text"),
                                            md))
        elif hasattr(vectors, 'items') and not isinstance(vectors, list):
            for vid, v in vectors.items():
                item = {'id': vid, 'metadata': getattr(v, 'metadata', None) or (v.get('metadata') if isinstance(v, dict) else None)}
                vid2, md = self._get_id_and_metadata(item)
                if vid2 is not None:
                    recs.append(VectorRecord(vid2, None,
                                            md.get("source_text") or md.get("text"),
                                            md))
        elif isinstance(vectors, (list, tuple)):
            for item in vectors:
                vid, md = self._get_id_and_metadata(item)
                if vid is not None:
                    recs.append(VectorRecord(vid, None,
                                            md.get("source_text") or md.get("text"),
                                            md))
        elif vectors is not None:
            try:
                for item in list(vectors):
                    vid, md = self._get_id_and_metadata(item)
                    if vid is not None:
                        recs.append(VectorRecord(vid, None,
                                                md.get("source_text") or md.get("text"),
                                                md))
            except Exception:
                pass

        if not recs:
            logger.warning("[PINECONE] _extract_records_from_fetch found no records", extra={
                "fetched_type": type(fetched).__name__,
                "vectors_type": type(vectors).__name__ if vectors is not None else None,
                "vectors_len": len(vectors) if hasattr(vectors, '__len__') else None,
            })
        return recs

    def iter_all(self, batch: int = 500):
        """
        Stream ALL records in batches via index.list() pagination.
        Pinecone's list() returns ListResponse objects with .vectors (ListItems with IDs only).
        We then fetch the actual vector data in batches.
        """
        list_gen = self._ix.list(namespace=self._ns if self._ns else None)
        
        # Collect IDs from all list responses
        all_ids = []
        for list_response in list_gen:
            ids = self._extract_ids_from_list_response(list_response)
            all_ids.extend(ids)

        logger.info("[PINECONE] iter_all collected IDs", extra={"count": len(all_ids)})
        if not all_ids:
            logger.warning("[PINECONE] iter_all found no IDs from list()")

        # Fetch actual vectors in batches and yield.
        # Each fetch is further split to avoid 414 Request-URI Too Large.
        for i in range(0, len(all_ids), batch):
            batch_ids = all_ids[i:i + batch]
            if batch_ids:
                recs_batch = []
                for j in range(0, len(batch_ids), self._fetch_id_chunk_size):
                    sub_ids = batch_ids[j:j + self._fetch_id_chunk_size]
                    try:
                        fetched = self._ix.fetch(ids=sub_ids, namespace=self._ns if self._ns else None)
                        vectors = None
                        if hasattr(fetched, 'vectors'):
                            vectors = fetched.vectors
                        elif isinstance(fetched, dict):
                            vectors = fetched.get('vectors')

                        recs = self._extract_records_from_fetch(fetched)
                        if not recs:
                            logger.warning(
                                "[PINECONE] fetch returned no records",
                                extra={
                                    "sub_ids": len(sub_ids),
                                    "fetched_type": type(fetched).__name__,
                                    "vectors_type": type(vectors).__name__ if vectors is not None else None,
                                    "vectors_len": len(vectors) if hasattr(vectors, '__len__') else None,
                                }
                            )
                        else:
                            recs_batch.extend(recs)
                    except Exception as exc:
                        logger.exception("[PINECONE] fetch failed in iter_all", exc_info=exc)
                        continue

                if recs_batch:
                    yield recs_batch

    def fetch(self, ids):
        out = []
        for i in range(0, len(ids), self._fetch_id_chunk_size):
            sub_ids = ids[i:i + self._fetch_id_chunk_size]
            fetched = self._ix.fetch(ids=sub_ids, namespace=self._ns)
            out.extend(self._extract_records_from_fetch(fetched))
        return out

    def upsert(self, records):
        self._ix.upsert(namespace=self._ns, vectors=[
            {"id": r.id, "values": list(map(float, r.vector)),
             "metadata": {**r.metadata,
                          "source_text": r.source_text or "",
                          "text": r.source_text or ""}}
            for r in records])

    def query(self, vector, k=5, where=None):
        res = self._ix.query(namespace=self._ns, vector=list(map(float, vector)),
                             top_k=k, include_metadata=True, filter=where or None)
        return [{"id": m["id"], "score": m["score"],
                 "source_text": ((m.get("metadata") or {}).get("source_text") or
                                 (m.get("metadata") or {}).get("text")),
                 "metadata": m.get("metadata") or {}} for m in res["matches"]]

    def delete(self, ids):
        self._ix.delete(ids=ids, namespace=self._ns)


class QdrantConnector(VectorStoreConnector):
    """
    Qdrant. pip install qdrant-client.
        from qdrant_client import QdrantClient
        client = QdrantClient(url=..., api_key=...)
    iter_all uses scroll(); upsert uses PointStruct; query uses search().
    """
    name = "qdrant"

    def __init__(self, client, collection: str):
        self._c = client
        self._col = collection

    def count(self):
        return int(self._c.count(self._col, exact=True).count)

    def iter_all(self, batch: int = 500):
        offset = None
        while True:
            points, offset = self._c.scroll(self._col, limit=batch, offset=offset,
                                             with_payload=True, with_vectors=False)
            if not points:
                break
            yield [VectorRecord(str(p.id), None,
                                (p.payload or {}).get("source_text") or
                                (p.payload or {}).get("text"), p.payload or {})
                   for p in points]
            if offset is None:
                break

    def fetch(self, ids):
        pts = self._c.retrieve(self._col, ids=ids, with_payload=True)
        return [VectorRecord(str(p.id), None,
                             (p.payload or {}).get("source_text") or
                             (p.payload or {}).get("text"), p.payload or {})
                for p in pts]

    def upsert(self, records):
        from qdrant_client.models import PointStruct
        self._c.upsert(self._col, points=[
            PointStruct(id=r.id, vector=list(map(float, r.vector)),
                        payload={**r.metadata,
                                 "source_text": r.source_text or "",
                                 "text": r.source_text or ""})
            for r in records])

    def query(self, vector, k=5, where=None):
        res = self._c.search(self._col, query_vector=list(map(float, vector)),
                             limit=k, with_payload=True)
        return [{"id": str(h.id), "score": float(h.score),
                 "source_text": ((h.payload or {}).get("source_text") or
                                 (h.payload or {}).get("text")),
                 "metadata": h.payload or {}} for h in res]

    def delete(self, ids):
        self._c.delete(self._col, points_selector=ids)


class PgVectorConnector(VectorStoreConnector):
    """
    Postgres + pgvector. pip install psycopg[binary] pgvector.
    Assumes a table: (id text pk, embedding vector, source_text text, metadata jsonb).
    """
    name = "pgvector"

    def __init__(self, conn, table: str = "documents"):
        self._conn = conn
        self._t = table

    def count(self):
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {self._t}")
            return int(cur.fetchone()[0])

    def iter_all(self, batch: int = 500):
        with self._conn.cursor(name="scan") as cur:
            cur.itersize = batch
            cur.execute(f"SELECT id, source_text, metadata FROM {self._t}")
            buf = []
            for row in cur:
                source_text = row[1] or (row[2] or {}).get("text")
                buf.append(VectorRecord(str(row[0]), None, source_text, row[2] or {}))
                if len(buf) >= batch:
                    yield buf; buf = []
            if buf:
                yield buf

    def fetch(self, ids):
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT id, source_text, metadata FROM {self._t} "
                        f"WHERE id = ANY(%s)", (ids,))
            return [VectorRecord(str(r[0]), None,
                                 r[1] or (r[2] or {}).get("text"), r[2] or {})
                    for r in cur.fetchall()]

    def upsert(self, records):
        import json
        with self._conn.cursor() as cur:
            for r in records:
                cur.execute(
                    f"INSERT INTO {self._t} (id, embedding, source_text, metadata) "
                    f"VALUES (%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET "
                    f"embedding=EXCLUDED.embedding, source_text=EXCLUDED.source_text, "
                    f"metadata=EXCLUDED.metadata",
                    (r.id, list(map(float, r.vector)), r.source_text or "",
                     json.dumps({**r.metadata,
                                 "source_text": r.source_text or "",
                                 "text": r.source_text or ""})))
        self._conn.commit()

    def query(self, vector, k=5, where=None):
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT id, source_text, metadata, 1-(embedding <=> %s::vector) AS score "
                f"FROM {self._t} ORDER BY embedding <=> %s::vector LIMIT %s",
                (list(map(float, vector)), list(map(float, vector)), k))
            return [{"id": str(r[0]), "source_text": r[1], "metadata": r[2] or {},
                     "score": float(r[3])} for r in cur.fetchall()]

    def delete(self, ids):
        with self._conn.cursor() as cur:
            cur.execute(f"DELETE FROM {self._t} WHERE id = ANY(%s)", (ids,))
        self._conn.commit()
