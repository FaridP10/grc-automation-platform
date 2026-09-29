from datetime import date
from pathlib import Path

import pytest

from grc_platform.common.models import RemediationStatus, Severity
from grc_platform.remediation.github_issues import GitHubIssueClient
from grc_platform.remediation.ingest import load_findings_csv
from grc_platform.remediation.pipeline import ingest_findings
from grc_platform.remediation.sla import assign_due_date
from grc_platform.remediation.scoring import score_severity
from grc_platform.remediation.store import FindingStore

FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


# --- scoring ---

def test_score_severity_bands():
    assert score_severity(5, 5) == Severity.CRITICAL  # 25
    assert score_severity(4, 3) == Severity.HIGH       # 12
    assert score_severity(3, 2) == Severity.MEDIUM     # 6
    assert score_severity(1, 1) == Severity.LOW        # 1


def test_score_severity_rejects_out_of_range():
    with pytest.raises(ValueError):
        score_severity(0, 3)
    with pytest.raises(ValueError):
        score_severity(3, 6)


# --- sla ---

def test_assign_due_date():
    d = date(2026, 1, 1)
    assert assign_due_date(d, Severity.CRITICAL) == date(2026, 1, 31)
    assert assign_due_date(d, Severity.LOW) == date(2026, 6, 30)


# --- ingest ---

def test_load_findings_csv_with_explicit_severity():
    findings = load_findings_csv(FIXTURES / "sample_findings.csv")
    assert len(findings) == 6
    f1 = next(f for f in findings if f.id == "FIND-001")
    assert f1.severity == Severity.CRITICAL
    assert f1.control_ids == ["A.8.3", "A.5.15"]
    assert f1.due_date == assign_due_date(f1.discovered_date, Severity.CRITICAL)


def test_load_findings_csv_with_risk_scoring():
    findings = load_findings_csv(FIXTURES / "sample_findings_risk_scored.csv")
    by_id = {f.id: f for f in findings}
    assert by_id["FIND-101"].severity == Severity.HIGH   # 4*4=16
    assert by_id["FIND-102"].severity == Severity.LOW    # 2*2=4


def test_ingest_drops_unknown_control_ids(tmp_path):
    csv_path = tmp_path / "bad.csv"
    csv_path.write_text(
        "id,title,description,source,control_ids,severity,discovered_date,owner\n"
        "X-1,Bad control ref,desc,manual,A.5.15;A.99.99,Low,2026-01-01,\n"
    )
    findings = load_findings_csv(csv_path)
    assert findings[0].control_ids == ["A.5.15"]


# --- store ---

def test_store_upsert_list_and_status(tmp_path):
    store = FindingStore(path=tmp_path / "findings.json")
    findings = load_findings_csv(FIXTURES / "sample_findings.csv")
    store.upsert_many(findings)

    assert len(store.list_findings()) == 6
    assert len(store.list_findings(status=RemediationStatus.OPEN)) == 6

    updated = store.update_status("FIND-001", RemediationStatus.REMEDIATED, notes="Bucket policy fixed")
    assert updated.status == RemediationStatus.REMEDIATED
    assert store.get("FIND-001").remediation_notes == "Bucket policy fixed"


def test_store_overdue_detection(tmp_path):
    store = FindingStore(path=tmp_path / "findings.json")
    findings = load_findings_csv(FIXTURES / "sample_findings.csv")  # discovered in 2026-08/09
    store.upsert_many(findings)
    overdue = store.overdue()
    assert all(f.due_date < date.today() for f in overdue)


def test_store_update_unknown_id_raises(tmp_path):
    store = FindingStore(path=tmp_path / "findings.json")
    with pytest.raises(KeyError):
        store.update_status("NOPE", RemediationStatus.REMEDIATED)


# --- github issue creation (no network: only checks the skip path) ---

def test_github_client_not_configured_without_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPO", raising=False)
    client = GitHubIssueClient()
    assert client.is_configured is False


def test_pipeline_skips_issue_creation_when_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPO", raising=False)
    store = FindingStore(path=tmp_path / "findings.json")

    result = ingest_findings(
        FIXTURES / "sample_findings.csv",
        store=store,
        create_github_issues=True,
    )
    assert result.issues_skipped_reason == "GITHUB_TOKEN / GITHUB_REPO not set"
    assert result.issues_created == []
    assert len(store.list_findings()) == 6
