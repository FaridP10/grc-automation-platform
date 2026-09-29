"""Loads the shared ISO 27001 Annex A control set used by all three modules."""

from functools import lru_cache
from pathlib import Path

import yaml

from grc_platform.common.models import Control

DEFAULT_CONTROLS_PATH = Path(__file__).resolve().parents[3] / "data" / "controls" / "iso27001_annex_a.yaml"


@lru_cache(maxsize=1)
def load_controls(path: Path = DEFAULT_CONTROLS_PATH) -> dict[str, Control]:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    controls = [Control(**c) for c in raw["controls"]]
    return {c.id: c for c in controls}


def get_control(control_id: str) -> Control:
    registry = load_controls()
    if control_id not in registry:
        raise KeyError(f"Unknown control id: {control_id}")
    return registry[control_id]
