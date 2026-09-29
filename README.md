# GRC Automation Platform

An integrated platform that automates three manual GRC workflows against a shared
ISO 27001 Annex A control set:

- **Posture monitoring** — scans AWS (Config, Security Hub, IAM) for control compliance and produces audit evidence. Runs against `moto`-mocked AWS APIs, so no AWS account is required.
- **Remediation automation (POA&M)** — ingests assessment findings, maps them to controls, scores severity, assigns SLA due dates, tracks status through to closure, and opens a GitHub Issue per finding.
- **Policy assessment** — checks policy documents against the required-policy set for a framework and reports gaps.

## Status

Early scaffolding: shared control registry and data models are in place. Module logic
(remediation, policy, posture, API, dashboard) is in progress.

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
