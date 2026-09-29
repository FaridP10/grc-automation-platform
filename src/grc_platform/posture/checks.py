"""Individual AWS posture checks. Each takes a boto3 Session (real or
moto-mocked) and returns a PostureCheckResult per resource examined, mapped
to the ISO 27001 Annex A control(s) it evidences.
"""

from datetime import datetime, timezone

import boto3

from grc_platform.common.models import PostureCheckResult


def _now() -> datetime:
    return datetime.now(timezone.utc)


def check_s3_public_access(session: boto3.Session) -> list[PostureCheckResult]:
    """Flags buckets whose policy grants Principal "*" or whose ACL grants
    AllUsers/AuthenticatedUsers. A string-match heuristic on the policy JSON,
    not a full IAM policy evaluator -- adequate for a posture-scan demo.
    """
    s3 = session.client("s3")
    results = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        reasons = []

        try:
            policy = s3.get_bucket_policy(Bucket=name)["Policy"]
            if any(needle in policy for needle in ('"Principal": "*"', '"Principal":"*"', '"AWS": "*"', '"AWS":"*"')):
                reasons.append("bucket policy grants access to Principal *")
        except s3.exceptions.ClientError:
            pass

        for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                reasons.append("bucket ACL grants access to AllUsers/AuthenticatedUsers")

        results.append(
            PostureCheckResult(
                check_id="s3_public_access",
                control_ids=["A.8.3", "A.5.15"],
                resource_id=name,
                resource_type="s3_bucket",
                compliant=not reasons,
                detail="; ".join(reasons) if reasons else "No public policy or ACL grant found.",
                checked_at=_now(),
            )
        )
    return results


def check_s3_encryption(session: boto3.Session) -> list[PostureCheckResult]:
    s3 = session.client("s3")
    results = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
            compliant, detail = True, "Default encryption is enabled."
        except s3.exceptions.ClientError:
            compliant, detail = False, "No default encryption configured."
        results.append(
            PostureCheckResult(
                check_id="s3_default_encryption",
                control_ids=["A.8.24"],
                resource_id=name,
                resource_type="s3_bucket",
                compliant=compliant,
                detail=detail,
                checked_at=_now(),
            )
        )
    return results


def check_iam_privileged_mfa(session: boto3.Session) -> list[PostureCheckResult]:
    iam = session.client("iam")
    results = []
    for user in iam.list_users()["Users"]:
        username = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        is_privileged = any("Administrator" in p["PolicyName"] or "PowerUser" in p["PolicyName"] for p in attached)
        if not is_privileged:
            continue
        has_mfa = len(iam.list_mfa_devices(UserName=username)["MFADevices"]) > 0
        results.append(
            PostureCheckResult(
                check_id="iam_privileged_mfa",
                control_ids=["A.8.2", "A.8.5"],
                resource_id=username,
                resource_type="iam_user",
                compliant=has_mfa,
                detail="MFA device attached." if has_mfa else "Privileged user has no MFA device attached.",
                checked_at=_now(),
            )
        )
    return results


def check_iam_password_policy(session: boto3.Session) -> list[PostureCheckResult]:
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return [
            PostureCheckResult(
                check_id="iam_password_policy",
                control_ids=["A.8.5"],
                resource_id="account",
                resource_type="iam_account_password_policy",
                compliant=False,
                detail="No account password policy is configured.",
                checked_at=_now(),
            )
        ]

    issues = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append("minimum length < 14")
    if not policy.get("RequireSymbols"):
        issues.append("symbols not required")
    if not policy.get("RequireNumbers"):
        issues.append("numbers not required")

    return [
        PostureCheckResult(
            check_id="iam_password_policy",
            control_ids=["A.8.5"],
            resource_id="account",
            resource_type="iam_account_password_policy",
            compliant=not issues,
            detail="Password policy meets minimum requirements." if not issues else f"Weak password policy: {', '.join(issues)}.",
            checked_at=_now(),
        )
    ]


def check_cloudtrail_logging(session: boto3.Session) -> list[PostureCheckResult]:
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    if not trails:
        return [
            PostureCheckResult(
                check_id="cloudtrail_logging",
                control_ids=["A.8.15", "A.8.16"],
                resource_id="account",
                resource_type="cloudtrail",
                compliant=False,
                detail="No CloudTrail trail configured.",
                checked_at=_now(),
            )
        ]

    results = []
    for trail in trails:
        status = ct.get_trail_status(Name=trail["TrailARN"])
        logging_on = status.get("IsLogging", False)
        results.append(
            PostureCheckResult(
                check_id="cloudtrail_logging",
                control_ids=["A.8.15", "A.8.16"],
                resource_id=trail["Name"],
                resource_type="cloudtrail",
                compliant=logging_on,
                detail="Logging is enabled." if logging_on else "Trail exists but logging is not enabled.",
                checked_at=_now(),
            )
        )
    return results
