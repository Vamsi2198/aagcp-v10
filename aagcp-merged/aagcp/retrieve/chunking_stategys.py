"""
Generalized "one chunk per record" strategy for PDFs with mixed layouts:
  - Header-marker records:  "#0001 Name: ..."  (financial customer master)
  - Header-marker records:  "Subj 001 ..."      (pharma trial subjects)
  - Plain data table rows:  DOB | SSN | PAN | Credit Card | ... (no header marker per row)
  - JSON-line records:      { "user_id": "usr_291061", ... }
  - Catalog table rows:     Asset.Column | Type | PII Class | ...

Strategy:
  1. Extract text page-by-page AND tables page-by-page with pdfplumber.
  2. For each page, try known "record header" regexes (extensible list).
     If a page matches one, split on that marker -> one chunk per record.
  3. If no header marker matches, but pdfplumber found a table on that page,
     chunk by table row instead (each row -> one chunk, header row attached
     as context so the chunk is self-describing).
  4. If neither applies, check for JSON-lines format (>=50% lines are valid JSON objects).
  5. Every chunk carries metadata: doc name, page number, chunk type,
     record id (if detected), and the source pattern used - useful for
     filtering/citation at retrieval time.

Install:
    pip install pdfplumber
"""

import re
import json
import logging
import pdfplumber

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Known "record starts here" patterns. Add more as you meet new formats.
#    Each tuple: (name, compiled regex with lookahead so the delimiter stays)
# ---------------------------------------------------------------------------
RECORD_HEADER_PATTERNS = [
    ("hash_id",   re.compile(r"(?=#\d{3,6}\s*(?:Name)?:?)")),   # "#0001 Name:"
    ("subj_id",   re.compile(r"(?=Subj\s+\d{3,6}\b)")),          # "Subj 001"
    ("row_id",    re.compile(r"(?=Row\s+\d{3,6}\b)")),           # generic "Row NNN"
]

JSON_LINE_PATTERN = re.compile(r"^\s*\{.*\}\s*,?\s*$", re.MULTILINE)


def looks_like_json_lines(text: str) -> bool:
    """Check if text is JSONL format: >=50% of non-empty lines are valid JSON objects."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    
    json_count = 0
    for line in lines:
        # Remove trailing comma (common in JSONL)
        line = line.rstrip(",")
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            json.loads(line)
            json_count += 1
        except (json.JSONDecodeError, ValueError):
            pass
    
    ratio = json_count / len(lines) if lines else 0
    is_jsonl = ratio >= 0.5
    logger.info(f"[CHUNKING] JSON-lines detection: {json_count}/{len(lines)} valid = {ratio:.1%} -> {is_jsonl}")
    return is_jsonl


def chunk_json_lines(text, doc_name, page_num):
    """Split JSONL into one chunk per record. Handles both single-line and 
    multi-line JSON objects (when formatted with newlines inside braces)."""
    chunks = []
    
    # Try single-line-per-object first (most common JSONL)
    chunks_by_line = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            obj = json.loads(line)
            record_id = obj.get("user_id") or obj.get("id") or obj.get("name")
            chunks_by_line.append({
                "doc": doc_name,
                "page": page_num,
                "chunk_type": "json_line",
                "record_id": record_id,
                "text": line,
            })
        except json.JSONDecodeError:
            pass
    
    if chunks_by_line:
        logger.info(f"[CHUNKING] Split {len(chunks_by_line)} JSON-line objects (single-line format)")
        return chunks_by_line
    
    # Fallback: multi-line JSON objects (find brace-balanced blocks)
    buffer = ""
    brace_depth = 0
    for line in text.splitlines():
        buffer += line + "\n"
        brace_depth += line.count("{") - line.count("}")
        
        # When braces balance at 0, we have a complete JSON object
        if brace_depth == 0 and "{" in buffer:
            obj_text = buffer.strip().rstrip(",")
            try:
                obj = json.loads(obj_text)
                record_id = obj.get("user_id") or obj.get("id") or obj.get("name")
                chunks.append({
                    "doc": doc_name,
                    "page": page_num,
                    "chunk_type": "json_line_multiline",
                    "record_id": record_id,
                    "text": obj_text,
                })
                logger.debug(f"[CHUNKING] Parsed multi-line JSON record: {record_id}")
            except json.JSONDecodeError as e:
                logger.warning(f"[CHUNKING] Failed to parse multi-line JSON: {e}")
            buffer = ""
    
    if chunks:
        logger.info(f"[CHUNKING] Split {len(chunks)} JSON-line objects (multi-line format)")
    
    return chunks


def chunk_by_header_pattern(text, doc_name, page_num):
    """Try each known header regex; return chunks for the first one that
    actually splits the page into >1 piece."""
    for pattern_name, pattern in RECORD_HEADER_PATTERNS:
        pieces = pattern.split(text)
        pieces = [p.strip() for p in pieces if p.strip()]
        if len(pieces) > 1:
            chunks = []
            for p in pieces:
                id_match = re.match(r"#?(\d{3,6})", p)
                chunks.append({
                    "doc": doc_name,
                    "page": page_num,
                    "chunk_type": f"header:{pattern_name}",
                    "record_id": id_match.group(1) if id_match else None,
                    "text": p,
                })
            return chunks
    return None


def chunk_table_rows(page, doc_name, page_num):
    """Fallback: no header marker found, but the page has a real table.
    Chunk one row at a time, prefixing the header row as context so the
    chunk stands alone (e.g. 'DOB: 1993-11-15 | SSN: 295-51-5101 | ...')."""
    tables = page.extract_tables()
    if not tables:
        return None

    all_chunks = []
    for t_idx, table in enumerate(tables):
        if not table or len(table) < 2:
            continue
        header = [ (c or "").strip() for c in table[0] ]
        for r_idx, row in enumerate(table[1:], start=1):
            row = [ (c or "").strip() for c in row ]
            if not any(row):
                continue
            pairs = [f"{h}: {v}" for h, v in zip(header, row) if v]
            row_text = " | ".join(pairs)
            all_chunks.append({
                "doc": doc_name,
                "page": page_num,
                "chunk_type": "table_row",
                "record_id": f"table{t_idx}_row{r_idx}",
                "text": row_text,
            })
    return all_chunks or None


def chunk_page(page, doc_name, page_num):
    text = page.extract_text() or ""

    # 1. JSON-line records (JSONL streams)
    if looks_like_json_lines(text):
        chunks = chunk_json_lines(text, doc_name, page_num)
        if chunks:
            logger.info(f"[CHUNKING] Page {page_num}: JSONL strategy -> {len(chunks)} chunks")
            return chunks

    # 2. Header-marker records (#0001, Subj 001, etc.)
    chunks = chunk_by_header_pattern(text, doc_name, page_num)
    if chunks:
        logger.info(f"[CHUNKING] Page {page_num}: Header-marker strategy -> {len(chunks)} chunks")
        return chunks

    # 3. Plain table rows (no per-row header marker)
    chunks = chunk_table_rows(page, doc_name, page_num)
    if chunks:
        logger.info(f"[CHUNKING] Page {page_num}: Table-row strategy -> {len(chunks)} chunks")
        return chunks

    # 4. Nothing recognized -> whole page as one chunk (rare fallback)
    if text.strip():
        logger.warning(f"[CHUNKING] Page {page_num}: No pattern matched, using full_page_fallback (1 chunk)")
        return [{
            "doc": doc_name,
            "page": page_num,
            "chunk_type": "full_page_fallback",
            "record_id": None,
            "text": text.strip(),
        }]
    return []


def chunk_pdf(pdf_path):
    doc_name = pdf_path.split("/")[-1]
    all_chunks = []
    with pdfplumber.open(pdf_path) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            all_chunks.extend(chunk_page(page, doc_name, page_num))
    return all_chunks


def save_jsonl(chunks, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        for c in chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import sys
    import glob

    # Accept one or more PDF paths / a glob pattern as CLI args, else default.
    pdf_paths = sys.argv[1:] if len(sys.argv) > 1 else glob.glob("*.pdf")
    if not pdf_paths:
        print("Usage: python chunk_records.py file1.pdf file2.pdf ...")
        sys.exit(1)

    total = []
    for path in pdf_paths:
        chunks = chunk_pdf(path)
        print(f"{path}: {len(chunks)} chunks")
        total.extend(chunks)

    save_jsonl(total, "chunks.jsonl")
    print(f"\nTotal chunks: {len(total)} -> saved to chunks.jsonl")
    if total:
        print("\nSample chunk:")
        print(json.dumps(total[0], indent=2, ensure_ascii=False))