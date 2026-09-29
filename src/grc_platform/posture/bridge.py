"""Converts non-compliant posture check results into remediation Findings,
so an AWS posture scan feeds the same POA&M pipeline as pentest, gap
assessment, or vendor review findings.
"""

from datetime import date

from grc_platform.common.models import Finding, FindingSource, PostureCheckResult, Severity
from grc_platform.remediation.sla import assign_due_date

_SEVERITY_BY_CHECK: dict[str, Severity] = {
    "s3_public_access": Severity.CRITICAL,
    "iam_privileged_mfa": Severity.CRITICAL,
    "cloudtrail_logging": Severity.HIGH,
    "s3_default_encryption": Severity.MEDIUM,
    "iam_password_policy": Severity.MEDIUM,
}

_TITLE_BY_CHECK: dict[str, str] = {
    "s3_public_access": "S3 bucket allows public access",
    "iam_privileged_mfa": "Privileged IAM user missing MFA",
    "cloudtrail_logging": "CloudTrail logging not enabled",
    "s3_default_encryption": "S3 bucket missing default encryption",
    "iam_password_policy": "IAM account password policy below minimum requirements",
}


def posture_results_to_findings(
    results: list[PostureCheckResult],
    discovered_date: date | None = None,
) -> list[Finding]:
    discovered_date = discovered_date or date.today()
    findings = []
    for r in results:
        if r.compliant:
            continue
        severity = _SEVERITY_BY_CHECK.get(r.check_id, Severity.MEDIUM)
        findings.append(
            Finding(
                id=f"POSTURE-{r.check_id}-{r.resource_id}",
                title=f"{_TITLE_BY_CHECK.get(r.check_id, r.check_id)}: {r.resource_id}",
                description=r.detail,
                source=FindingSource.AWS_POSTURE_SCAN,
                control_ids=r.control_ids,
                severity=severity,
                discovered_date=discovered_date,
                due_date=assign_due_date(discovered_date, severity),
            )
        )
    return findings
