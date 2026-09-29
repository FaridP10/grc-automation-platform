"""Shared data contracts used across the posture, remediation, and policy modules."""

from datetime import date, datetime
from enum import Enum

from pydantic import BaseModel, Field


class Control(BaseModel):
    id: str
    theme: str
    title: str


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# Remediation SLA windows in days, keyed by severity. Standard risk-acceptance
# timelines used across the remediation and posture modules.
SLA_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 60,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
}


class FindingSource(str, Enum):
    PENTEST = "pentest"
    GAP_ASSESSMENT = "gap_assessment"
    VENDOR_REVIEW = "vendor_review"
    AWS_POSTURE_SCAN = "aws_posture_scan"
    MANUAL = "manual"


class RemediationStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    REMEDIATED = "Remediated"
    RISK_ACCEPTED = "Risk Accepted"


class Finding(BaseModel):
    id: str
    title: str
    description: str
    source: FindingSource
    control_ids: list[str] = Field(default_factory=list)
    severity: Severity
    status: RemediationStatus = RemediationStatus.OPEN
    discovered_date: date
    due_date: date | None = None
    owner: str | None = None
    remediation_notes: str | None = None
    github_issue_url: str | None = None

    @property
    def is_overdue(self) -> bool:
        if self.due_date is None or self.status in (RemediationStatus.REMEDIATED, RemediationStatus.RISK_ACCEPTED):
            return False
        return date.today() > self.due_date


class PolicyGap(BaseModel):
    control_id: str
    control_title: str
    required_policy: str
    status: str  # "present" | "missing" | "stale"
    detail: str | None = None


class PostureCheckResult(BaseModel):
    check_id: str
    control_ids: list[str]
    resource_id: str
    resource_type: str
    compliant: bool
    detail: str
    checked_at: datetime
