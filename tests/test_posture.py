from datetime import date

import boto3
from moto import mock_aws

from grc_platform.common.models import Severity
from grc_platform.posture.bridge import posture_results_to_findings
from grc_platform.posture.checks import (
    check_cloudtrail_logging,
    check_iam_password_policy,
    check_iam_privileged_mfa,
    check_s3_encryption,
    check_s3_public_access,
)
from grc_platform.posture.demo_seed import seed_demo_environment
from grc_platform.posture.scanner import run_all_checks


def _seeded_session() -> boto3.Session:
    session = boto3.Session(region_name="ca-central-1")
    seed_demo_environment(session)
    return session


@mock_aws
def test_s3_public_access_check_flags_public_bucket():
    results = check_s3_public_access(_seeded_session())
    by_id = {r.resource_id: r for r in results}
    assert by_id["prod-app-data"].compliant is True
    assert by_id["prod-uploads"].compliant is False


@mock_aws
def test_s3_encryption_check():
    results = check_s3_encryption(_seeded_session())
    by_id = {r.resource_id: r for r in results}
    assert by_id["prod-app-data"].compliant is True
    assert by_id["prod-uploads"].compliant is False


@mock_aws
def test_iam_privileged_mfa_check():
    results = check_iam_privileged_mfa(_seeded_session())
    by_id = {r.resource_id: r for r in results}
    assert by_id["alice.admin"].compliant is True
    assert by_id["bob.admin"].compliant is False


@mock_aws
def test_iam_password_policy_check_flags_weak_policy():
    results = check_iam_password_policy(_seeded_session())
    assert results[0].compliant is False
    assert "minimum length < 14" in results[0].detail


@mock_aws
def test_cloudtrail_check_flags_missing_trail():
    results = check_cloudtrail_logging(_seeded_session())
    assert results[0].compliant is False


@mock_aws
def test_run_all_checks_covers_every_check_type():
    results = run_all_checks(_seeded_session())
    check_ids = {r.check_id for r in results}
    assert check_ids == {
        "s3_public_access",
        "s3_default_encryption",
        "iam_privileged_mfa",
        "iam_password_policy",
        "cloudtrail_logging",
    }


@mock_aws
def test_posture_results_to_findings_only_includes_noncompliant():
    results = run_all_checks(_seeded_session())
    findings = posture_results_to_findings(results, discovered_date=date(2026, 1, 1))

    assert len(findings) == sum(1 for r in results if not r.compliant)
    public_bucket_finding = next(f for f in findings if "prod-uploads" in f.id and "s3_public_access" in f.id)
    assert public_bucket_finding.severity == Severity.CRITICAL
    assert public_bucket_finding.due_date == date(2026, 1, 31)
