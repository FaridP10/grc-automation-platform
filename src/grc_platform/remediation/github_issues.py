"""Creates a GitHub Issue for each remediation finding, so tracking status can
live where engineering already works. Requires GITHUB_TOKEN and GITHUB_REPO
("owner/repo") to be set; when they aren't, is_configured is False and the
caller (pipeline.ingest_findings) skips issue creation instead of failing
the whole ingest.
"""

import os

from github import Github

from grc_platform.common.models import Finding, Severity

_LABELS = {
    Severity.CRITICAL: "severity:critical",
    Severity.HIGH: "severity:high",
    Severity.MEDIUM: "severity:medium",
    Severity.LOW: "severity:low",
}


class GitHubIssueClient:
    def __init__(self, token: str | None = None, repo: str | None = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.repo_name = repo or os.environ.get("GITHUB_REPO")

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.repo_name)

    def create_issue_for_finding(self, finding: Finding) -> str:
        if not self.is_configured:
            raise RuntimeError("GITHUB_TOKEN and GITHUB_REPO must be set to create issues")
        gh = Github(self.token)
        repo = gh.get_repo(self.repo_name)
        body = (
            f"**Source:** {finding.source.value}\n"
            f"**Severity:** {finding.severity.value}\n"
            f"**Controls:** {', '.join(finding.control_ids) or 'none mapped'}\n"
            f"**Due date:** {finding.due_date}\n\n"
            f"{finding.description}"
        )
        issue = repo.create_issue(
            title=f"[{finding.severity.value}] {finding.title}",
            body=body,
            labels=["grc-finding", _LABELS[finding.severity]],
        )
        return issue.html_url
