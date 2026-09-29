"""Severity scoring for findings that arrive without a pre-assigned severity."""

from grc_platform.common.models import Severity

# 5x5 likelihood x impact risk matrix -> severity band, standard risk-scoring approach.
_RISK_BANDS: list[tuple[int, Severity]] = [
    (20, Severity.CRITICAL),
    (12, Severity.HIGH),
    (6, Severity.MEDIUM),
    (0, Severity.LOW),
]


def score_severity(likelihood: int, impact: int) -> Severity:
    if not (1 <= likelihood <= 5) or not (1 <= impact <= 5):
        raise ValueError("likelihood and impact must each be in the range 1-5")
    risk_score = likelihood * impact
    for threshold, severity in _RISK_BANDS:
        if risk_score >= threshold:
            return severity
    return Severity.LOW
