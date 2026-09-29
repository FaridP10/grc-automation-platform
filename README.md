# GRC Automation Platform

[![Tests](https://github.com/FaridP10/grc-automation-platform/actions/workflows/tests.yml/badge.svg)](https://github.com/FaridP10/grc-automation-platform/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An integrated platform that automates three manual GRC workflows against a shared
ISO 27001 Annex A control set:

- **Posture monitoring** — scans AWS (Config, Security Hub, IAM) for control compliance and produces audit evidence. Runs against `moto`-mocked AWS APIs, so no AWS account is required.
- **Remediation automation (POA&M)** — ingests assessment findings, maps them to controls, scores severity, assigns SLA due dates, tracks status through to closure, and opens a GitHub Issue per finding.
- **Policy assessment** — checks policy documents against the required-policy set for a framework and reports gaps.

## Status

Remediation, policy assessment, and posture scanning are implemented and tested,
tied together in a Streamlit dashboard. No FastAPI layer yet -- everything runs
via CLI or the dashboard.

## Stack

Python 3.11+, FastAPI, Streamlit, boto3/moto, PyGithub.

## Layout

```
src/grc_platform/
  common/      # shared models + ISO 27001 Annex A control registry
  remediation/ # POA&M ingestion, scoring, SLA, GitHub Issues
  policy/      # policy document gap analysis
  posture/     # AWS posture scanning
  api/         # FastAPI app
  dashboard/   # Streamlit dashboard
data/controls/ # ISO 27001 Annex A reference data
tests/
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Usage

```bash
# Remediation (POA&M)
python -m grc_platform.remediation.cli ingest data/fixtures/sample_findings.csv
python -m grc_platform.remediation.cli list --overdue
python -m grc_platform.remediation.cli status FIND-001 Remediated --notes "Patched"

# Policy assessment
python -m grc_platform.policy.cli assess data/fixtures/policy_manifest.yaml

# AWS posture scan (moto-mocked demo account, no AWS credentials needed)
python -m grc_platform.posture.cli scan --to-remediation

# Dashboard tying all three together
streamlit run src/grc_platform/dashboard/app.py
```
