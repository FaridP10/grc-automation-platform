"""Regenerates the coverage badge in README.md from coverage.json (produced
by `pytest --cov-report=json`). Run by CI on every push to main so the badge
reflects real, current coverage rather than a static claim.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_JSON = REPO_ROOT / "coverage.json"
README = REPO_ROOT / "README.md"

_THRESHOLDS = [(90, "brightgreen"), (75, "green"), (50, "yellow"), (0, "red")]


def _color_for(pct: float) -> str:
    for threshold, color in _THRESHOLDS:
        if pct >= threshold:
            return color
    return "red"


def main() -> None:
    totals = json.loads(COVERAGE_JSON.read_text())["totals"]
    pct = round(totals["percent_covered"])
    color = _color_for(pct)
    badge_url = f"https://img.shields.io/badge/coverage-{pct}%25-{color}.svg"

    readme = README.read_text()
    updated = re.sub(
        r"!\[Coverage\]\(https://img\.shields\.io/badge/coverage-[^)]+\)",
        f"![Coverage]({badge_url})",
        readme,
    )
    README.write_text(updated)
    print(f"Coverage: {pct}% -> {badge_url}")


if __name__ == "__main__":
    main()
