"""Command-line entrypoint for the policy assessment module.

    python -m grc_platform.policy.cli assess data/fixtures/policy_manifest.yaml
    python -m grc_platform.policy.cli assess data/fixtures/policy_manifest.yaml --out report.json
"""

import argparse
import json

import yaml

from grc_platform.policy.gap_analysis import assess_all, coverage_summary


def _cmd_assess(args):
    with open(args.manifest) as f:
        raw = yaml.safe_load(f)
    manifest = raw.get("policies", {})

    gaps = assess_all(manifest)
    for g in gaps:
        print(f"[{g.status.upper():10}] {g.required_policy} ({g.control_id})  {g.detail or ''}")

    summary = coverage_summary(gaps)
    print(
        f"\nCoverage: {summary['present']}/{summary['total']} ({summary['coverage_pct']}%)  "
        f"missing={summary['missing']} incomplete={summary['incomplete']} stale={summary['stale']}"
    )

    if args.out:
        with open(args.out, "w") as f:
            json.dump([json.loads(g.model_dump_json()) for g in gaps], f, indent=2)
        print(f"\nWrote report to {args.out}")


def main():
    parser = argparse.ArgumentParser(prog="grc-policy")
    sub = parser.add_subparsers(dest="command", required=True)

    p_assess = sub.add_parser("assess", help="Assess policy documents against the required-policy catalog")
    p_assess.add_argument("manifest", help="YAML file mapping policy_id -> document path")
    p_assess.add_argument("--out", help="Write the gap report as JSON to this path")
    p_assess.set_defaults(func=_cmd_assess)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
