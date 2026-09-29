"""Loads raw findings from CSV or JSON into the Finding model, auto-scoring
severity from likelihood/impact when a severity isn't already assigned, and
computing each finding's SLA due date.
"""

import csv
import json
from datetime import date
from pathlib import Path

from grc_platform.common.control_registry import load_controls
from grc_platform.common.models import Finding, FindingSource, Severity
from grc_platform.remediation.scoring import score_severity
from grc_platform.remediation.sla import assign_due_date


def _parse_severity(row: dict) -> Severity:
    if row.get("severity"):
        return Severity(row["severity"].strip().title())
    return score_severity(int(row["likelihood"]), int(row["impact"]))


def _parse_control_ids(raw: str) -> list[str]:
    known = load_controls()
    ids = [c.strip() for c in raw.split(";") if c.strip()]
    return [c for c in ids if c in known]


def _row_to_finding(row: dict) -> Finding:
    discovered = date.fromisoformat(row["discovered_date"])
    severity = _parse_severity(row)
    return Finding(
        id=row["id"],
        title=row["title"],
        description=row.get("description", ""),
        source=FindingSource(row["source"]),
        control_ids=_parse_control_ids(row.get("control_ids", "")),
        severity=severity,
        discovered_date=discovered,
        due_date=assign_due_date(discovered, severity),
        owner=row.get("owner") or None,
    )


def load_findings_csv(path: str | Path) -> list[Finding]:
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return [_row_to_finding(row) for row in reader]


def load_findings_json(path: str | Path) -> list[Finding]:
    with open(path) as f:
        rows = json.load(f)
    return [_row_to_finding(row) for row in rows]
