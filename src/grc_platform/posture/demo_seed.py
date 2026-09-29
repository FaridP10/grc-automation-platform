"""Seeds a small AWS environment inside an active moto mock -- one compliant
and one non-compliant resource per check -- so the posture scanner is
runnable end-to-end without a real AWS account.
"""

import json

import boto3


def seed_demo_environment(session: boto3.Session) -> None:
    _seed_s3(session)
    _seed_iam(session)
    # CloudTrail is intentionally left unconfigured to demonstrate that finding.


def _seed_s3(session: boto3.Session) -> None:
    s3 = session.client("s3")
    region = session.region_name

    def create(name: str) -> None:
        if region == "us-east-1":
            s3.create_bucket(Bucket=name)
        else:
            s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})

    # Compliant: private, encrypted.
    create("prod-app-data")
    s3.put_bucket_encryption(
        Bucket="prod-app-data",
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    )

    # Non-compliant: public read policy, no encryption.
    create("prod-uploads")
    s3.put_bucket_policy(
        Bucket="prod-uploads",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::prod-uploads/*",
                    }
                ],
            }
        ),
    )


def _seed_iam(session: boto3.Session) -> None:
    iam = session.client("iam")

    # Non-compliant: below the 14-char / symbols-required bar checked in checks.py.
    iam.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=False,
        RequireNumbers=True,
    )

    # moto doesn't ship the real AWS-managed AdministratorAccess policy, so create
    # an equivalent customer-managed one under the same name for the check to key off.
    admin_policy_arn = iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )["Policy"]["Arn"]

    for username, has_mfa in [("alice.admin", True), ("bob.admin", False)]:
        iam.create_user(UserName=username)
        iam.attach_user_policy(UserName=username, PolicyArn=admin_policy_arn)
        if has_mfa:
            device = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{username}-mfa")["VirtualMFADevice"]
            iam.enable_mfa_device(
                UserName=username,
                SerialNumber=device["SerialNumber"],
                AuthenticationCode1="123456",
                AuthenticationCode2="654321",
            )
