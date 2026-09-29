"""SLA due-date assignment based on finding severity."""

from datetime import date, timedelta

from grc_platform.common.models import SLA_DAYS, Severity


def assign_due_date(discovered_date: date, severity: Severity) -> date:
    return discovered_date + timedelta(days=SLA_DAYS[severity])
