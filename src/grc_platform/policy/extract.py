"""Extracts text and a best-effort last-review date from policy documents
(.docx, .pdf, .md, .txt).
"""

import re
from datetime import date
from pathlib import Path

from dateutil import parser as dateutil_parser
from docx import Document
from pypdf import PdfReader

_REVIEW_DATE_LINE = re.compile(
    r"(last review(?:ed)?|review date|last updated|effective date)\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)


def extract_text(path: str | Path) -> str:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".docx":
        doc = Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs)
    if suffix == ".pdf":
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if suffix in (".md", ".txt"):
        return path.read_text()
    raise ValueError(f"Unsupported policy document type: {suffix}")


def extract_review_date(text: str) -> date | None:
    for line in text.splitlines():
        match = _REVIEW_DATE_LINE.search(line)
        if not match:
            continue
        try:
            return dateutil_parser.parse(match.group(2).strip(), fuzzy=True).date()
        except (ValueError, OverflowError):
            continue
    return None
