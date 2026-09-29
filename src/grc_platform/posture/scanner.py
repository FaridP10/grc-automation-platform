"""Runs all AWS posture checks against a boto3 session (real or moto-mocked)."""

import boto3

from grc_platform.common.models import PostureCheckResult
from grc_platform.posture.checks import (
    check_cloudtrail_logging,
    check_iam_password_policy,
    check_iam_privileged_mfa,
    check_s3_encryption,
    check_s3_public_access,
)

ALL_CHECKS = [
    check_s3_public_access,
    check_s3_encryption,
    check_iam_privileged_mfa,
    check_iam_password_policy,
    check_cloudtrail_logging,
]


def run_all_checks(session: boto3.Session | None = None) -> list[PostureCheckResult]:
    session = session or boto3.Session(region_name="ca-central-1")
    results: list[PostureCheckResult] = []
    for check in ALL_CHECKS:
        results.extend(check(session))
    return results
