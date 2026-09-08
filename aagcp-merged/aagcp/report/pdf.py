"""
Branded PII Exposure Audit Report (PDF).

Turns a ScanReport into a regulator-ready PDF a DPO can file: overview,
category distribution with percentages, jurisdiction breakdown, risk summary,
and a remediation recommendation. Pure reportlab — no network, no heavy deps.
"""

from __future__ import annotations
import io
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT

# Brand palette
INK = colors.HexColor("#0c1118")
SLATE = colors.HexColor("#334155")
SAFE = colors.HexColor("#0e9f6e")
AMBER = colors.HexColor("#b45309")
LINE = colors.HexColor("#cbd5e1")
BG = colors.HexColor("#f1f5f9")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Brand", parent=ss["Title"], fontSize=20,
                          textColor=INK, spaceAfter=2, leading=24))
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], fontSize=9.5,
                          textColor=SLATE, spaceAfter=10))
    ss.add(ParagraphStyle("H", parent=ss["Heading2"], fontSize=12.5,
                          textColor=INK, spaceBefore=12, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5,
                          textColor=SLATE, leading=14))
    ss.add(ParagraphStyle("KV", parent=ss["Normal"], fontSize=9.5,
                          textColor=INK, leading=15))
    return ss


def build_audit_pdf(summary: dict, *, store_name: str = "connected index",
                    embedder_name: str = "", detector_coverage: Optional[dict] = None,
                    org: str = "AAGCP-Vector") -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="PII Exposure Audit Report")
    ss = _styles()
    E = []

    # ── Header / brand ──────────────────────────────────────────────
    E.append(Paragraph(f"{org} &nbsp;·&nbsp; PII Exposure Audit", ss["Brand"]))
    E.append(Paragraph("Governance control plane for vector databases — "
                       "detection, remediation, and erasure evidence.", ss["Sub"]))
    E.append(HRFlowable(width="100%", thickness=1.2, color=INK, spaceAfter=10))

    total = summary.get("total_vectors", 0)
    withpii = summary.get("vectors_with_pii", 0)
    instances = summary.get("total_pii_instances", 0)
    pct = (withpii / total * 100) if total else 0.0

    # ── Overview KV ─────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ner = (detector_coverage or {}).get("ner_backend", "regex only")
    ov = [
        ["Timestamp", ts],
        ["Data source", store_name],
        ["Embedding model", embedder_name or "n/a"],
        ["Detection", f"{(detector_coverage or {}).get('regex_entity_count','?')} pattern types"
                      f" + NER ({ner})"],
        ["Vectors scanned", f"{total:,}"],
        ["Vectors with PII", f"{withpii:,}  ({pct:.1f}%)"],
        ["Total PII instances", f"{instances:,}"],
    ]
    t = Table(ov, colWidths=[42 * mm, None])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), SLATE),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("TEXTCOLOR", (1, 5), (1, 6), AMBER if instances else SAFE),
        ("FONTNAME", (1, 5), (1, 6), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, -1), BG),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    E.append(t)

    # ── Category distribution ───────────────────────────────────────
    E.append(Paragraph("PII Category Distribution", ss["H"]))
    by_type = summary.get("by_type", {})
    rows = [["Entity type", "Count", "% of PII", "% of corpus"]]
    for etype, cnt in by_type.items():
        rows.append([etype,
                     f"{cnt:,}",
                     f"{(cnt/instances*100):.1f}%" if instances else "0%",
                     f"{(cnt/ (total or 1) *100):.1f}%"])
    if len(rows) == 1:
        rows.append(["— none detected —", "0", "0%", "0%"])
    ct = Table(rows, colWidths=[70 * mm, 28 * mm, 30 * mm, 30 * mm])
    ct.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG]),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, INK),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (0, -1), 8),
    ]))
    E.append(ct)

    # ── Jurisdiction ────────────────────────────────────────────────
    by_j = summary.get("by_jurisdiction", {})
    if by_j:
        E.append(Paragraph("Exposure by Jurisdiction", ss["H"]))
        jrows = [["Jurisdiction", "PII instances"]] + \
                [[k, f"{v:,}"] for k, v in by_j.items()]
        jt = Table(jrows, colWidths=[70 * mm, 40 * mm])
        jt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 0), (-1, 0), SLATE),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG]),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (0, -1), 8),
        ]))
        E.append(jt)

    # ── Remediation ─────────────────────────────────────────────────
    E.append(Paragraph("Remediation", ss["H"]))
    cleanable = summary.get("cleanable_by_reembed", 0)
    quar = summary.get("quarantine_only_no_source", 0)
    if instances:
        rec = (f"{cleanable:,} affected vectors retain source text and can be "
               f"cleaned in place by re-embedding the tokenized (masked) text — "
               f"no full-corpus re-embed. ")
        if quar:
            rec += (f"{quar:,} vectors lack source text and can only be "
                    f"quarantined (deleted), since a poisoned vector cannot be "
                    f"reconstructed without its source. ")
        rec += ("After remediation, PII is replaced by deterministic vault "
                "tokens; access is role-gated at query time and erasure is a "
                "reference-counted vault-key deletion (GDPR/DPDP Art. 17).")
        color = AMBER
    else:
        rec = ("No PII detected in scanned vectors. Index is clean under the "
               "active detector. Maintain governance at ingestion to keep it so.")
        color = SAFE
    E.append(Paragraph(rec, ParagraphStyle("Rec", parent=ss["Body"], textColor=color)))

    E.append(Spacer(1, 12))
    E.append(HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=6))
    E.append(Paragraph("Generated by AAGCP-Vector. This report reflects PII "
                       "detectable from vector source text under the active "
                       "detector configuration.", ss["Sub"]))

    doc.build(E)
    return buf.getvalue()
