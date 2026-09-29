"""Orchestrates the end-to-end remediation flow: ingest -> map/score -> SLA ->
persist -> optionally open a GitHub Issue per finding.
"""

from dataclasses import dataclass, field
from pathlib import Path

from grc_platform.common.models import Finding
from grc_platform.remediation.github_issues import GitHubIssueClient
from grc_platform.remediation.ingest import load_findings_csv, load_findings_json
from grc_platform.remediation.store import FindingStore


@dataclass
class IngestResult:
    findings: list[Finding]
    issues_created: list[str] = field(default_factory=list)
    issues_skipped_reason: str | None = None


def ingest_findings(
    path: str | Path,
    store: FindingStore | None = None,
    create_github_issues: bool = False,
    github_client: GitHubIssueClient | None = None,
) -> IngestResult:
    path = Path(path)
    loader = load_findings_json if path.suffix == ".json" else load_findings_csv
    findings = loader(path)

    store = store or FindingStore()
    result = IngestResult(findings=findings)

    if create_github_issues:
        client = github_client or GitHubIssueClient()
        if client.is_configured:
            for f in findings:
                f.github_issue_url = client.create_issue_for_finding(f)
                result.issues_created.append(f.github_issue_url)
        else:
            result.issues_skipped_reason = "GITHUB_TOKEN / GITHUB_REPO not set"

    store.upsert_many(findings)
    return result
