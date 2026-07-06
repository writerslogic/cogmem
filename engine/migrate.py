"""
Cognitive Memory — Migrate legacy JSON store into the markdown vault

Converts the original per-file JSON hypotheses and episodes into the open
markdown+frontmatter vault format, so the vault becomes the single source of
truth. Hypotheses become Layer-B recall rules (situational, query-gated);
episodes become episode notes. Originals are left in place; this is additive.

Usage:
  python migrate.py            # write vault notes from hypotheses/ + episodes/
  python migrate.py --dry-run
"""

import json
import logging
import sys

from cogmem.common import COGMEM, VAULT, write_note

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.migrate")

HYP_DIR = COGMEM / "hypotheses"
EP_DIR = COGMEM / "episodes"
RULES = VAULT / "rules"
EPISODES = VAULT / "episodes"


def scope_of(hyp: dict) -> str:
    domain = hyp.get("domain", "universal")
    if domain in ("language", "project"):
        return (hyp.get("domain_scope") or "universal").strip() or "universal"
    return "universal"


def hyp_body(hyp: dict) -> str:
    parts = [hyp.get("claim", "").strip()]
    if hyp.get("causal_model"):
        parts.append(f"\n**Why:** {hyp['causal_model'].strip()}")
    if hyp.get("prediction"):
        parts.append(f"\n**Predict:** {hyp['prediction'].strip()}")
    return "\n".join(p for p in parts if p)


def migrate_hypotheses(dry_run: bool) -> int:
    n = 0
    for f in sorted(HYP_DIR.glob("*.json")):
        hyp = json.loads(f.read_text())
        meta = {
            "id": hyp.get("id", f.stem),
            "layer": "B",
            "scope": scope_of(hyp),
            "status": "active",
            "origin": "migrated-hypothesis",
            "confidence": hyp.get("confidence", 0.4),
            "evidence_for": hyp.get("evidence_for", 0),
            "evidence_against": hyp.get("evidence_against", 0),
            "tags": ", ".join(hyp.get("tags", [])),
            "legacy_status": hyp.get("status", "candidate"),
            "created": hyp.get("created", ""),
        }
        if dry_run:
            log.info("  [B/%s] %s", meta["scope"], meta["id"])
        else:
            write_note(RULES / f"{meta['id']}.md", meta, hyp_body(hyp))
            log.info("  rule: %s", meta["id"])
        n += 1
    return n


def migrate_episodes(dry_run: bool) -> int:
    n = 0
    for f in sorted(EP_DIR.glob("*.json")):
        ep = json.loads(f.read_text())
        meta = {
            "id": ep.get("id", f.stem),
            "kind": "episode",
            "project": ep.get("project", ""),
            "task_type": ep.get("task_type", ""),
            "outcome": ep.get("outcome", ""),
            "timestamp": ep.get("timestamp", ""),
        }
        body_parts = []
        if ep.get("context"):
            body_parts.append(f"**Context:** {ep['context']}")
        if ep.get("surprise"):
            body_parts.append(f"**Surprise:** {ep['surprise']}")
        for c in ep.get("corrections", []) or []:
            body_parts.append(f"**Correction:** {c}")
        if ep.get("counterfactual"):
            body_parts.append(f"**Counterfactual:** {ep['counterfactual']}")
        if dry_run:
            log.info("  [episode] %s (%s)", meta["id"], meta["project"])
        else:
            write_note(EPISODES / f"{meta['id']}.md", meta, "\n\n".join(body_parts))
            log.info("  episode: %s", meta["id"])
        n += 1
    return n


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    h = migrate_hypotheses(dry)
    e = migrate_episodes(dry)
    log.info("Migrated %d hypotheses + %d episodes%s", h, e, " (dry-run)" if dry else "")
