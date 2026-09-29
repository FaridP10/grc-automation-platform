"""Loads the catalog of required policy documents: which controls each one
is expected to satisfy, what content it must contain, and how often it must
be reviewed.
"""

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "controls" / "required_policies.yaml"


class PolicyRequirement(BaseModel):
    id: str
    name: str
    control_ids: list[str]
    required_clauses: list[str]
    max_review_age_days: int


@lru_cache(maxsize=1)
def load_policy_catalog(path: Path = DEFAULT_CATALOG_PATH) -> dict[str, PolicyRequirement]:
    with open(path) as f:
        raw = yaml.safe_load(f)
    requirements = [PolicyRequirement(**p) for p in raw["policies"]]
    return {r.id: r for r in requirements}
