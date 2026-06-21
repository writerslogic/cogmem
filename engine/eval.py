"""
Cognitive Memory — Recall Evaluation Harness

Makes recall quality a measured number instead of a claim. For each rule it
generates realistic queries that SHOULD recall it (positives), plus off-topic
negatives that should recall nothing. It then measures recall@k, MRR, and the
false-positive rate, and can sweep the cosine floor / rerank gap to find the best
operating point empirically.

The generated eval set is cached (eval_set.json) so runs are reproducible and do
not re-call the model. Querying goes through the warm daemon.

Usage:
  python eval.py            # evaluate at current thresholds
  python eval.py --sweep    # grid-search floor/gap, recommend best
  python eval.py --regen    # regenerate the eval set from current rules
"""

import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, api_call, parse_json_block, read_note
import recall

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cogmem.eval")

RULES = VAULT / "rules"
EVAL_SET = Path(__file__).resolve().parent / "eval_set.json"
GEN_MODEL = "claude-haiku-4-5-20251001"

NEGATIVES = [
    "write a haiku about the ocean",
    "what's a good recipe for carbonara",
    "explain the plot of Hamlet",
    "what time zone is Tokyo in",
    "suggest a name for my cat",
]


def generate_eval_set() -> dict:
    rules = {}
    for f in sorted(RULES.glob("*.md"))[:18]:   # cap to keep generation within token budget
        meta, body = read_note(f)
        rules[meta.get("id", f.stem)] = body
    if not rules:
        return {}
    listing = "\n".join(f"- {rid}: {body[:200]}" for rid, body in rules.items())
    prompt = (
        "For each rule below, write 2 realistic, natural developer prompts that this "
        "rule SHOULD be recalled to help with. Vary the phrasing and do NOT quote the "
        "rule text. Return ONLY JSON mapping rule id to a list of 2 prompts:\n"
        '{"<id>": ["prompt one", "prompt two"], ...}\n\nRULES:\n' + listing
    )
    raw = api_call(GEN_MODEL, prompt, max_tokens=3000)
    parsed = parse_json_block(raw) if raw else None
    return parsed if isinstance(parsed, dict) else {}


def load_eval_set(regen: bool) -> dict:
    if EVAL_SET.exists() and not regen:
        return json.loads(EVAL_SET.read_text())
    log.info("Generating eval set from current rules...")
    data = generate_eval_set()
    if data:
        EVAL_SET.write_text(json.dumps(data, indent=2))
    return data


def evaluate(eval_set: dict, floor: float, gap: float, k: int = 5) -> dict:
    positives = [(q, rid) for rid, qs in eval_set.items() for q in qs]
    hits = 0
    rr_sum = 0.0
    for q, expected in positives:
        try:
            raw = recall.recall(q, k=8, scope=None)
        except Exception:  # noqa: BLE001 — daemon down: count as miss, keep going
            raw = []
        ranked = recall.filter_results(raw, floor, gap)[:k]
        ids = [r["id"] for r in ranked]
        if expected in ids:
            hits += 1
            rr_sum += 1.0 / (ids.index(expected) + 1)

    false_pos = 0
    for q in NEGATIVES:
        try:
            raw = recall.recall(q, k=8, scope=None)
        except Exception:  # noqa: BLE001
            raw = []
        if recall.filter_results(raw, floor, gap):
            false_pos += 1

    n = len(positives) or 1
    return {
        "positives": len(positives),
        "recall_at_k": round(hits / n, 3),
        "mrr": round(rr_sum / n, 3),
        "false_pos_rate": round(false_pos / (len(NEGATIVES) or 1), 3),
    }


def sweep(eval_set: dict) -> None:
    log.info("floor  gap   recall@5  mrr    fp_rate   score")
    best = None
    for floor in (0.55, 0.60, 0.62, 0.65, 0.70):
        for gap in (4.0, 6.0, 8.0):
            m = evaluate(eval_set, floor, gap)
            # reward recall, penalize false positives
            score = m["recall_at_k"] - 0.5 * m["false_pos_rate"]
            log.info("%.2f   %.1f   %.3f     %.3f  %.3f     %.3f",
                     floor, gap, m["recall_at_k"], m["mrr"], m["false_pos_rate"], score)
            if best is None or score > best[0]:
                best = (score, floor, gap, m)
    log.info("")
    log.info("BEST: floor=%.2f gap=%.1f  (recall@5=%.3f, fp=%.3f)",
             best[1], best[2], best[3]["recall_at_k"], best[3]["false_pos_rate"])


if __name__ == "__main__":
    regen = "--regen" in sys.argv
    data = load_eval_set(regen)
    if not data:
        log.error("No eval set (no rules, or generation failed).")
        sys.exit(1)
    if "--sweep" in sys.argv:
        sweep(data)
    else:
        m = evaluate(data, floor=0.62, gap=6.0)
        log.info("Recall eval @ floor=0.62 gap=6.0: %s", m)
