"""Streamlit dashboard tying the remediation, policy assessment, and posture
scanning modules into one view.

    streamlit run src/grc_platform/dashboard/app.py
"""

import tempfile
from pathlib import Path

import boto3
import pandas as pd
import streamlit as st
import yaml
from moto import mock_aws

from grc_platform.common.models import RemediationStatus, Severity
from grc_platform.policy.gap_analysis import assess_all, coverage_summary
from grc_platform.posture.bridge import posture_results_to_findings
from grc_platform.posture.demo_seed import seed_demo_environment
from grc_platform.posture.scanner import run_all_checks
from grc_platform.remediation.pipeline import ingest_findings
from grc_platform.remediation.store import FindingStore

st.set_page_config(page_title="GRC Automation Platform", layout="wide")

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = REPO_ROOT / "data" / "fixtures" / "policy_manifest.yaml"
SAMPLE_FINDINGS = REPO_ROOT / "data" / "fixtures" / "sample_findings.csv"


def _load_manifest(manifest_path: Path) -> dict:
    """Loads a policy manifest and resolves its relative paths against the
    repo root, since the dashboard process may not be launched from there.
    """
    with open(manifest_path) as f:
        raw = yaml.safe_load(f).get("policies", {})
    return {
        policy_id: (REPO_ROOT / path if path and not Path(path).is_absolute() else path)
        for policy_id, path in raw.items()
    }


def _findings_df() -> pd.DataFrame:
    findings = FindingStore().list_findings()
    if not findings:
        return pd.DataFrame(
            columns=["id", "title", "source", "severity", "status", "discovered_date", "due_date", "overdue", "control_ids"]
        )
    rows = [
        {
            "id": f.id,
            "title": f.title,
            "source": f.source.value,
            "severity": f.severity.value,
            "status": f.status.value,
            "discovered_date": f.discovered_date,
            "due_date": f.due_date,
            "overdue": f.is_overdue,
            "control_ids": ", ".join(f.control_ids),
        }
        for f in findings
    ]
    return pd.DataFrame(rows).sort_values("due_date")


def _highlight_overdue(row: pd.Series) -> list[str]:
    return ["background-color: #5c1a1a" if row["overdue"] else ""] * len(row)


def render_overview() -> None:
    st.header("Overview")
    df = _findings_df()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total findings", len(df))
    col2.metric("Open", int((df["status"] == RemediationStatus.OPEN.value).sum()) if not df.empty else 0)
    col3.metric("Overdue", int(df["overdue"].sum()) if not df.empty else 0)
    critical_high = (
        int(df["severity"].isin([Severity.CRITICAL.value, Severity.HIGH.value]).sum()) if not df.empty else 0
    )
    col4.metric("Critical/High open", critical_high)

    if DEFAULT_MANIFEST.exists():
        summary = coverage_summary(assess_all(_load_manifest(DEFAULT_MANIFEST)))
        st.subheader("Policy coverage")
        st.progress(summary["coverage_pct"] / 100)
        st.caption(f"{summary['present']}/{summary['total']} required policies present ({summary['coverage_pct']}%)")

    if not df.empty:
        st.subheader("Findings by severity")
        st.bar_chart(df["severity"].value_counts())
    else:
        st.info("No findings yet. Load sample findings on the Remediation tab, or run a posture scan.")


def render_remediation() -> None:
    st.header("Remediation (POA&M)")
    store = FindingStore()

    col1, col2 = st.columns(2)
    if col1.button("Load sample findings"):
        result = ingest_findings(SAMPLE_FINDINGS, store=store)
        st.success(f"Ingested {len(result.findings)} sample finding(s).")
        st.rerun()

    with col2.expander("Ingest your own CSV/JSON"):
        uploaded = st.file_uploader("Findings file", type=["csv", "json"])
        create_issues = st.checkbox("Create a GitHub Issue per finding (requires GITHUB_TOKEN/GITHUB_REPO)")
        if uploaded and st.button("Ingest uploaded file"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded.name).suffix) as tmp:
                tmp.write(uploaded.getvalue())
                tmp_path = Path(tmp.name)
            result = ingest_findings(tmp_path, store=store, create_github_issues=create_issues)
            st.success(f"Ingested {len(result.findings)} finding(s).")
            if create_issues and result.issues_skipped_reason:
                st.warning(result.issues_skipped_reason)
            st.rerun()

    df = _findings_df()
    if df.empty:
        st.info("No findings yet.")
        return

    fcol1, fcol2 = st.columns(2)
    severities = fcol1.multiselect("Severity", [s.value for s in Severity], default=[s.value for s in Severity])
    statuses = fcol2.multiselect("Status", [s.value for s in RemediationStatus], default=[s.value for s in RemediationStatus])
    filtered = df[df["severity"].isin(severities) & df["status"].isin(statuses)]

    st.dataframe(filtered.style.apply(_highlight_overdue, axis=1), use_container_width=True, hide_index=True)

    st.subheader("Update a finding's status")
    ucol1, ucol2, ucol3, ucol4 = st.columns([2, 1, 2, 1])
    finding_id = ucol1.selectbox("Finding", df["id"])
    new_status = ucol2.selectbox("New status", [s.value for s in RemediationStatus])
    notes = ucol3.text_input("Notes")
    if ucol4.button("Update"):
        store.update_status(finding_id, RemediationStatus(new_status), notes=notes or None)
        st.success(f"{finding_id} -> {new_status}")
        st.rerun()


def render_policy() -> None:
    st.header("Policy Assessment")
    manifest_path = st.text_input("Manifest path", value=str(DEFAULT_MANIFEST))

    if st.button("Run assessment"):
        if not Path(manifest_path).exists():
            st.error(f"Manifest not found: {manifest_path}")
            return
        gaps = assess_all(_load_manifest(Path(manifest_path)))
        summary = coverage_summary(gaps)

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Coverage", f"{summary['coverage_pct']}%")
        m2.metric("Present", summary["present"])
        m3.metric("Missing", summary["missing"])
        m4.metric("Incomplete", summary["incomplete"])
        m5.metric("Stale", summary["stale"])

        gap_df = pd.DataFrame([g.model_dump() for g in gaps])
        st.dataframe(gap_df, use_container_width=True, hide_index=True)


def render_posture() -> None:
    st.header("AWS Posture Scan")
    st.caption("Runs against a moto-mocked demo AWS account -- no AWS credentials required.")

    if st.button("Run demo scan"):
        with mock_aws():
            session = boto3.Session(region_name="ca-central-1")
            seed_demo_environment(session)
            st.session_state["posture_results"] = run_all_checks(session)

    results = st.session_state.get("posture_results")
    if not results:
        st.info("Run a scan to see results.")
        return

    result_df = pd.DataFrame([r.model_dump() for r in results])
    st.dataframe(result_df, use_container_width=True, hide_index=True)

    non_compliant = [r for r in results if not r.compliant]
    st.write(f"{len(results)} check(s) run, {len(non_compliant)} finding(s).")

    if st.button("Push findings to remediation store"):
        findings = posture_results_to_findings(results)
        FindingStore().upsert_many(findings)
        st.success(f"Pushed {len(findings)} finding(s) to the remediation store.")


def main() -> None:
    st.title("GRC Automation Platform")
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Remediation", "Policy Assessment", "AWS Posture"])
    with tab1:
        render_overview()
    with tab2:
        render_remediation()
    with tab3:
        render_policy()
    with tab4:
        render_posture()


main()
