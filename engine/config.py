"""
Cognitive Memory — tunable config

Thresholds that self-regulation adjusts live, kept in config.json so the recall
path reads current values without code edits and `cogmem tune` can rewrite them.
"""

import json
from pathlib import Path

CONFIG = Path(__file__).resolve().parent / "config.json"
DEFAULTS = {"recall_floor": 0.62, "recall_gap": 6.0, "provenance_enforce": False}


def load() -> dict:
    if CONFIG.exists():
        try:
            return {**DEFAULTS, **json.loads(CONFIG.read_text())}
        except (json.JSONDecodeError, OSError):
            return dict(DEFAULTS)
    return dict(DEFAULTS)


def save(cfg: dict) -> None:
    CONFIG.write_text(json.dumps(cfg, indent=2))
