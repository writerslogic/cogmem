"""
Cognitive Memory — tunable config

Thresholds that self-regulation adjusts live, kept in config.json so the recall
path reads current values without code edits and `cogmem tune` can rewrite them.
"""

import json
from pathlib import Path

CONFIG = Path(__file__).resolve().parent / "config.json"

# LLM ids per pipeline role and the local recall models, in one place so upgrades
# don't need code edits and a config.json can override any of them.
_MODELS = {
    "detect": "claude-haiku-4-5-20251001",  # cheap signal check, every session
    "extract": "claude-sonnet-4-6",  # rule extraction, only on signal
    "judge": "claude-haiku-4-5-20251001",  # feedback verdicts
    "consolidate": "claude-sonnet-4-6",  # dedup classification
    "selfmodel": "claude-sonnet-4-6",
    "projectstate": "claude-sonnet-4-6",
    "usermodel": "claude-sonnet-4-6",
    "narrative": "claude-sonnet-4-6",
    "artifacts": "claude-sonnet-4-6",
    "eval_gen": "claude-haiku-4-5-20251001",
}
_EMBED_MODEL = "BAAI/bge-small-en-v1.5"
_RERANK_MODEL = "Xenova/ms-marco-MiniLM-L-6-v2"

DEFAULTS = {
    "recall_floor": 0.62,
    "recall_gap": 6.0,
    "provenance_enforce": False,
    "keychain": False,
    "models": _MODELS,
    "embed_model": _EMBED_MODEL,
    "rerank_model": _RERANK_MODEL,
}


def load() -> dict:
    if CONFIG.exists():
        try:
            return {**DEFAULTS, **json.loads(CONFIG.read_text())}
        except (json.JSONDecodeError, OSError):
            return dict(DEFAULTS)
    return dict(DEFAULTS)


def model(role: str) -> str:
    """LLM id for a pipeline role; a partial "models" map in config.json overrides
    individual roles, falling back to the built-in default for any role it omits."""
    return load().get("models", {}).get(role, _MODELS[role])


def embed_model() -> str:
    return load().get("embed_model", _EMBED_MODEL)


def rerank_model() -> str:
    return load().get("rerank_model", _RERANK_MODEL)


def save(cfg: dict) -> None:
    CONFIG.write_text(json.dumps(cfg, indent=2))
