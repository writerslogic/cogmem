"""
Cognitive Memory — Self-Regulation

Closes the loop a human otherwise closes by hand. It runs the recall eval sweep,
writes the best-scoring thresholds back to config.json, and health-checks the
store, warning when signals drift (e.g. the Layer-A approval queue growing too
large, which means the extractor is marking too much as always-load).

Usage:
  python tune.py            # tune thresholds + health report
  python tune.py --health   # health report only (no eval, no API)
"""

import logging
import sys
from pathlib import Path

from cogmem import config
from cogmem.common import VAULT

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cogmem.tune")

PENDING_WARN = 15        # pending Layer-A rules above this suggests too-liberal capture
RULES_WARN = 200         # Layer-B rules above this suggests dedup is too loose


def tune_thresholds() -> None:
    from cogmem import eval as evalmod
    data = evalmod.load_eval_set(regen=False)
    if not data:
        log.info("No eval set; skipping threshold tuning.")
        return
    best = None
    for floor in (0.55, 0.60, 0.62, 0.65, 0.70):
        for gap in (4.0, 6.0, 8.0):
            m = evalmod.evaluate(data, floor, gap)
            score = m["recall_at_k"] - 0.5 * m["false_pos_rate"]
            if best is None or score > best[0]:
                best = (score, floor, gap, m)
    cfg = config.load()
    cfg["recall_floor"], cfg["recall_gap"] = best[1], best[2]
    config.save(cfg)
    log.info("Tuned: recall_floor=%.2f recall_gap=%.1f (recall@5=%.3f fp=%.3f)",
             best[1], best[2], best[3]["recall_at_k"], best[3]["false_pos_rate"])


def _count(p: Path) -> int:
    return len(list(p.glob("*.md"))) if p.exists() else 0


def health() -> None:
    pending = _count(VAULT / "pending")
    rules = _count(VAULT / "rules")
    quarantine = _count(VAULT / "quarantine")
    log.info("Health: %d Layer-B rules, %d pending, %d quarantined", rules, pending, quarantine)
    if pending > PENDING_WARN:
        log.info("  WARN: %d rules pending approval (> %d). The extractor is marking too "
                 "much as Layer-A; run `cogmem review list` to curate, and consider "
                 "tightening the Layer-A bar.", pending, PENDING_WARN)
    if rules > RULES_WARN:
        log.info("  WARN: %d Layer-B rules (> %d). Consolidation dedup may be too loose.",
                 rules, RULES_WARN)
    if quarantine:
        log.info("  WARN: %d quarantined notes need a look.", quarantine)


if __name__ == "__main__":
    if "--health" not in sys.argv:
        tune_thresholds()
    health()
