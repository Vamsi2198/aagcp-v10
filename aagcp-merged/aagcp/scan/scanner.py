"""
Scanner — uncapped PII inventory of an existing (production) index.

Streams EVERY vector via the connector's iter_all (no cap, batched), runs the
global detector on each vector's source_text, and aggregates a full exposure
report: total PII instances, by type, by jurisdiction, which vectors are
affected, and which have no source_text (cleanable-by-re-embed vs
quarantine-only).

The count is whatever the index actually contains. Nothing is capped.
"""

from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Iterable
import logging

from ..detect.detector import PIIDetector, Finding
from ..store.connectors import VectorStoreConnector

logger = logging.getLogger(__name__)


@dataclass
class VectorExposure:
    vector_id: str
    findings: List[Finding]
    has_source: bool
    risk: float


@dataclass
class ScanReport:
    total_vectors: int = 0
    scanned_vectors: int = 0
    vectors_with_pii: int = 0
    total_pii_instances: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    by_jurisdiction: Dict[str, int] = field(default_factory=dict)
    cleanable: int = 0             # has source_text → re-embed
    quarantine_only: int = 0       # no source_text → can only delete
    exposures: List[VectorExposure] = field(default_factory=list)
    detector_coverage: dict = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "total_vectors": self.total_vectors,
            "scanned_vectors": self.scanned_vectors,
            "vectors_with_pii": self.vectors_with_pii,
            "total_pii_instances": self.total_pii_instances,
            "by_type": dict(sorted(self.by_type.items(), key=lambda x: -x[1])),
            "by_jurisdiction": dict(sorted(self.by_jurisdiction.items(), key=lambda x: -x[1])),
            "cleanable_by_reembed": self.cleanable,
            "quarantine_only_no_source": self.quarantine_only,
            "detector_coverage": self.detector_coverage,
        }


class Scanner:
    def __init__(self, detector: PIIDetector):
        self.detector = detector
        logger.info(f"[SCANNER] Initialized with detector coverage: {detector.coverage()}")

    def _scan_records(self, records: Iterable, total_vectors: int | None = None, progress=None) -> ScanReport:
        rep = ScanReport(total_vectors=total_vectors if total_vectors is not None else 0,
                         detector_coverage=self.detector.coverage())
        type_ctr: Counter = Counter()
        juris_ctr: Counter = Counter()

        for rec in records:
            text = rec.source_text or ""
            findings = self.detector.scan(text) if text else []

            if findings:
                rep.vectors_with_pii += 1
                rep.total_pii_instances += len(findings)
                for f in findings:
                    type_ctr[f.entity_type] += 1
                    juris_ctr[f.jurisdiction or "GLOBAL"] += 1

                if rec.source_text:
                    rep.cleanable += 1
                else:
                    rep.quarantine_only += 1

                rep.exposures.append(VectorExposure(
                    rec.id, findings, bool(rec.source_text),
                    self.detector.risk_score(findings)))

            rep.scanned_vectors += 1
            if progress:
                progress(rep.scanned_vectors, rep.total_vectors or rep.scanned_vectors)

        rep.by_type = dict(type_ctr)
        rep.by_jurisdiction = dict(juris_ctr)
        return rep

    def scan(self, store: VectorStoreConnector, batch: int = 500,
             progress=None) -> ScanReport:
        logger.info(f"[SCANNER] Starting scan - total_vectors={store.count()}, batch_size={batch}")
        rep = ScanReport(total_vectors=store.count(),
                         detector_coverage=self.detector.coverage())
        type_ctr: Counter = Counter()
        juris_ctr: Counter = Counter()
        batch_count = 0
        logger.info(f"[SCANNER] Connected successfully to store={type(store).__name__}")
        logger.info(f"[SCANNER] Beginning iteration of store.iter_all(batch={batch})")

        for chunk in store.iter_all(batch=batch):
            batch_count += 1
            logger.info(f"[SCANNER] Received batch {batch_count} from store.iter_all, len={len(chunk)}")
            if len(chunk) == 0:
                logger.warning("[SCANNER] store.iter_all returned an empty batch")

            if batch_count == 1:
                logger.info(f"[SCANNER] First batch content: {chunk}")
            logger.info(f"[SCANNER] Processing batch {batch_count} with {len(chunk)} records")

            for rec in chunk:
                rep.scanned_vectors += 1
                text = rec.source_text or ""
                findings = self.detector.scan(text) if text else []

                if findings:
                    rep.vectors_with_pii += 1
                    rep.total_pii_instances += len(findings)
                    for f in findings:
                        type_ctr[f.entity_type] += 1
                        juris_ctr[f.jurisdiction or "GLOBAL"] += 1

                    if rec.source_text:
                        rep.cleanable += 1
                    else:
                        rep.quarantine_only += 1

                    if len(rep.exposures) < 10:  # Log first 10 for visibility
                        logger.debug(f"[SCANNER] Vector {rec.id}: {len(findings)} PII instances found")

                    rep.exposures.append(VectorExposure(
                        rec.id, findings, bool(rec.source_text),
                        self.detector.risk_score(findings)))
                elif rec.source_text is None:
                    pass

            if progress:
                progress(rep.scanned_vectors, rep.total_vectors)

            if batch_count % 5 == 0:
                logger.info(f"[SCANNER] Progress: scanned {rep.scanned_vectors}/{rep.total_vectors}, "
                           f"PII found in {rep.vectors_with_pii} vectors, "
                           f"total instances: {rep.total_pii_instances}")

        rep.by_type = dict(type_ctr)
        rep.by_jurisdiction = dict(juris_ctr)

        logger.info(f"[SCANNER] Scan complete - scanned={rep.scanned_vectors}, "
                   f"pii_vectors={rep.vectors_with_pii}, "
                   f"total_pii={rep.total_pii_instances}, "
                   f"by_type={dict(type_ctr)}, "
                   f"cleanable={rep.cleanable}, "
                   f"quarantine_only={rep.quarantine_only}")
        return rep

    def scan_records(self, records: Iterable, progress=None) -> ScanReport:
        record_list = list(records)
        logger.info(f"[SCANNER] Scanning {len(record_list)} provided records")
        return self._scan_records(record_list, total_vectors=len(record_list), progress=progress)
