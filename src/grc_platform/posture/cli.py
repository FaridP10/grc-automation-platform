"""Command-line entrypoint for the AWS posture scanning module.

Runs against a moto-mocked AWS account seeded with demo resources, so no
AWS credentials are required.

    python -m grc_platform.posture.cli scan
    python -m grc_platform.posture.cli scan --to-remediation
"""

import argparse

import boto3
from moto import mock_aws

from grc_platform.posture.bridge import posture_results_to_findings
from grc_platform.posture.demo_seed import seed_demo_environment
from grc_platform.posture.scanner import run_all_checks
from grc_platform.remediation.store import FindingStore


def _cmd_scan(args):
    with mock_aws():
        session = boto3.Session(region_name=args.region)
        seed_demo_environment(session)
        results = run_all_checks(session)

        for r in results:
            status = "PASS" if r.compliant else "FAIL"
            print(f"[{status}] {r.check_id:24} {r.resource_id:20} {r.detail}")

        non_compliant = [r for r in results if not r.compliant]
        print(f"\n{len(results)} check(s) run, {len(non_compliant)} finding(s).")

        if args.to_remediation:
            findings = posture_results_to_findings(results)
            FindingStore().upsert_many(findings)
            print(f"Pushed {len(findings)} finding(s) to the remediation store.")


def main():
    parser = argparse.ArgumentParser(prog="grc-posture")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run posture checks against a moto-mocked demo AWS account")
    p_scan.add_argument("--region", default="ca-central-1")
    p_scan.add_argument("--to-remediation", action="store_true", help="Push findings into the remediation store")
    p_scan.set_defaults(func=_cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
