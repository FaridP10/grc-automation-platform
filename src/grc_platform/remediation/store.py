"""Lightweight JSON-file-backed persistence for finding status over time.

A full database is unnecessary for a single-tenant POA&M tracker; a JSON file
keeps the module dependency-free and easy to inspect or diff during a demo.
"""

import json
from pathlib import Path

from grc_platform.common.models import Finding, RemediationStatus

DEFAULT_STORE_PATH = Path(__file__).resolve().parents[3] / "data" / "state" / "findings.json"


class FindingStore:
    def __init__(self, path: Path = DEFAULT_STORE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]")

    def load(self) -> dict[str, Finding]:
        raw = json.loads(self.path.read_text())
        findings = [Finding(**f) for f in raw]
        return {f.id: f for f in findings}

    def save(self, findings: dict[str, Finding]) -> None:
        payload = [json.loads(f.model_dump_json()) for f in findings.values()]
        self.path.write_text(json.dumps(payload, indent=2))

    def upsert_many(self, new_findings: list[Finding]) -> None:
        findings = self.load()
        for f in new_findings:
            findings[f.id] = f
        self.save(findings)

    def get(self, finding_id: str) -> Finding | None:
        return self.load().get(finding_id)

    def list_findings(self, status: RemediationStatus | None = None) -> list[Finding]:
        findings = list(self.load().values())
        if status is not None:
            findings = [f for f in findings if f.status == status]
        return findings

    def overdue(self) -> list[Finding]:
        return [f for f in self.load().values() if f.is_overdue]

    def update_status(self, finding_id: str, status: RemediationStatus, notes: str | None = None) -> Finding:
        findings = self.load()
        if finding_id not in findings:
            raise KeyError(f"Unknown finding id: {finding_id}")
        current = findings[finding_id]
        updated = current.model_copy(update={
            "status": status,
            "remediation_notes": notes if notes is not None else current.remediation_notes,
        })
        findings[finding_id] = updated
        self.save(findings)
        return updated
