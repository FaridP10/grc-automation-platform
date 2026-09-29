"""Command-line entrypoint for the remediation module.

    python -m grc_platform.remediation.cli ingest data/fixtures/sample_findings.csv
    python -m grc_platform.remediation.cli list --overdue
    python -m grc_platform.remediation.cli status FIND-001 Remediated --notes "Patched"
"""

import argparse

from grc_platform.common.models import RemediationStatus
from grc_platform.remediation.pipeline import ingest_findings
from grc_platform.remediation.store import FindingStore


def _cmd_ingest(args):
    result = ingest_findings(args.file, create_github_issues=args.create_issues)
    print(f"Ingested {len(result.findings)} finding(s).")
    for f in result.findings:
        print(f"  {f.id}  [{f.severity.value}]  due {f.due_date}  {f.title}")
    if args.create_issues:
        if result.issues_skipped_reason:
            print(f"GitHub issue creation skipped: {result.issues_skipped_reason}")
        else:
            print(f"Created {len(result.issues_created)} GitHub issue(s).")


def _cmd_list(args):
    store = FindingStore()
    status = RemediationStatus(args.status) if args.status else None
    findings = store.overdue() if args.overdue else store.list_findings(status=status)
    if not findings:
        print("No findings.")
        return
    for f in findings:
        flag = " OVERDUE" if f.is_overdue else ""
        print(f"{f.id}  [{f.severity.value}]  {f.status.value}{flag}  due {f.due_date}  {f.title}")


def _cmd_status(args):
    store = FindingStore()
    updated = store.update_status(args.finding_id, RemediationStatus(args.new_status), notes=args.notes)
    print(f"{updated.id} -> {updated.status.value}")


def main():
    parser = argparse.ArgumentParser(prog="grc-remediation")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Load findings from a CSV/JSON file")
    p_ingest.add_argument("file")
    p_ingest.add_argument("--create-issues", action="store_true")
    p_ingest.set_defaults(func=_cmd_ingest)

    p_list = sub.add_parser("list", help="List tracked findings")
    p_list.add_argument("--status", choices=[s.value for s in RemediationStatus])
    p_list.add_argument("--overdue", action="store_true")
    p_list.set_defaults(func=_cmd_list)

    p_status = sub.add_parser("status", help="Update a finding's status")
    p_status.add_argument("finding_id")
    p_status.add_argument("new_status", choices=[s.value for s in RemediationStatus])
    p_status.add_argument("--notes")
    p_status.set_defaults(func=_cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
