"""Checks each catalog policy against a provided document (or its absence)
and produces a PolicyGap: missing, incomplete (required content not found),
stale (review date past the catalog's max age or unreadable), or present.
"""

from datetime import date, timedelta
from pathlib import Path

from grc_platform.common.models import PolicyGap
from grc_platform.policy.catalog import PolicyRequirement, load_policy_catalog
from grc_platform.policy.extract import extract_review_date, extract_text


def assess_policy(requirement: PolicyRequirement, file_path: str | Path | None) -> PolicyGap:
    base = dict(control_id=requirement.control_ids[0], control_title=requirement.name, required_policy=requirement.name)

    if file_path is None:
        return PolicyGap(**base, status="missing", detail="No document provided for this policy.")

    text = extract_text(file_path)
    text_lower = text.lower()
    missing_clauses = [c for c in requirement.required_clauses if c.lower() not in text_lower]
    if missing_clauses:
        return PolicyGap(**base, status="incomplete", detail=f"Missing expected content: {', '.join(missing_clauses)}")

    review_date = extract_review_date(text)
    if review_date is None:
        return PolicyGap(**base, status="stale", detail="No review/effective date found in the document.")

    if date.today() - review_date > timedelta(days=requirement.max_review_age_days):
        return PolicyGap(
            **base,
            status="stale",
            detail=f"Last reviewed {review_date.isoformat()}, exceeds {requirement.max_review_age_days}-day review cycle.",
        )

    return PolicyGap(**base, status="present", detail=f"Last reviewed {review_date.isoformat()}.")


def assess_all(manifest: dict[str, str | Path | None]) -> list[PolicyGap]:
    catalog = load_policy_catalog()
    return [assess_policy(requirement, manifest.get(policy_id)) for policy_id, requirement in catalog.items()]


def coverage_summary(gaps: list[PolicyGap]) -> dict[str, int | float]:
    total = len(gaps)
    present = sum(1 for g in gaps if g.status == "present")
    return {
        "total": total,
        "present": present,
        "missing": sum(1 for g in gaps if g.status == "missing"),
        "incomplete": sum(1 for g in gaps if g.status == "incomplete"),
        "stale": sum(1 for g in gaps if g.status == "stale"),
        "coverage_pct": round(100 * present / total, 1) if total else 0.0,
    }
