"""
Cognitive Memory — Consolidation / Dedup

Candidate rules from acquisition are noisy: some restate knowledge already in
CLAUDE.md or the mode files, some overlap each other. This step is load-bearing.
Without it, the always-loaded layer re-learns what it already knows and bloats the
context budget.

For each candidate it asks a model: is this already covered by existing knowledge
(known), genuinely new (new), or an overlap that adds detail (refine)? Then it routes:
  - known   -> vault/rejected/   (kept for audit, with reason)
  - new/refine, layer B -> vault/rules/    (active; gets semantically indexed)
  - new/refine, layer A -> vault/pending/   (queued for human approval)

Usage:
  python consolidate.py            # process all candidates
  python consolidate.py --dry-run  # classify and print, write nothing
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (VAULT, CLAUDE_DIR, api_call, parse_json_block, read_note,
                    write_note, validate_note)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.consolidate")

CANDIDATES = VAULT / "candidates"
RULES = VAULT / "rules"
PENDING = VAULT / "pending"
REJECTED = VAULT / "rejected"

JUDGE_MODEL = "claude-sonnet-4-6"


# The dedup prompt is one API call; its input must stay bounded as the vault grows,
# or it eventually exceeds the model's context window, the call fails, and candidates
# pile up unconsolidated forever. Curated always-on files are always included (they
# are the authoritative dedup target); accepted rules fill the rest of the budget,
# newest first, and candidates are classified in batches so a large backlog can't
# blow the prompt either.
KNOWLEDGE_BUDGET = 48_000   # chars of existing-knowledge corpus per dedup call
BATCH = 30                  # candidates classified per call


def load_existing_knowledge() -> str:
    """The corpus a candidate must be checked against: curated always-on files
    plus rules already accepted into the vault, bounded to KNOWLEDGE_BUDGET chars."""
    parts = []
    claude_md = CLAUDE_DIR / "CLAUDE.md"
    if claude_md.exists():
        parts.append("# CLAUDE.md\n" + claude_md.read_text(errors="replace"))
    for f in sorted((CLAUDE_DIR / "modes").glob("*.md")):
        parts.append(f"# modes/{f.name}\n" + f.read_text(errors="replace"))

    used = sum(len(p) for p in parts)
    # Newest rules first: recent acceptances are the likeliest near-duplicates.
    rule_files = sorted(RULES.glob("*.md")) + sorted(PENDING.glob("*.md"))
    rule_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    omitted = 0
    for f in rule_files:
        meta, body = read_note(f)
        kind = "pending rule" if f.parent == PENDING else "rule"
        chunk = f"# {kind} {meta.get('id', f.stem)}\n{body}"
        if used + len(chunk) > KNOWLEDGE_BUDGET:
            omitted += 1
            continue
        parts.append(chunk)
        used += len(chunk)
    if omitted:
        log.warning("Knowledge corpus capped at ~%d chars; %d older rule(s) omitted "
                    "from this dedup pass.", KNOWLEDGE_BUDGET, omitted)
    return "\n\n".join(parts)


QUARANTINE = VAULT / "quarantine"


def load_candidates() -> list[tuple[Path, dict, str]]:
    out = []
    for f in sorted(CANDIDATES.glob("*.md")):
        meta, body = read_note(f)
        problems = validate_note(meta, body)
        if problems:
            QUARANTINE.mkdir(parents=True, exist_ok=True)
            f.rename(QUARANTINE / f.name)
            log.warning("Quarantined malformed candidate %s: %s", f.name, problems)
            continue
        out.append((f, meta, body))
    return out


JUDGE_PROMPT = """You are the consolidation step of a coding assistant's memory system.
Below is the assistant's EXISTING KNOWLEDGE (always-loaded instruction files and
already-accepted rules), then a list of CANDIDATE rules just extracted from a session.

For each candidate, classify it relative to existing knowledge:
- "known"  : already covered by existing knowledge; would be redundant to add
- "new"    : genuinely new and worth keeping
- "refine" : overlaps existing knowledge but adds a meaningful detail or correction

Be strict: when in doubt between known and new, prefer known. The cost of a false
"new" is permanent context bloat.

Return ONLY a JSON array, one object per candidate, in the same order:
[{{"id": "<candidate id>", "verdict": "known|new|refine", "reason": "<one line>"}}]

=== EXISTING KNOWLEDGE ===
{knowledge}

=== CANDIDATES ===
{candidates}"""


def classify(candidates: list[tuple[Path, dict, str]], knowledge: str) -> dict[str, dict]:
    listing = "\n".join(
        f'- id: {meta.get("id", f.stem)} | layer: {meta.get("layer")} | '
        f'scope: {meta.get("scope")} | rule: {body}'
        for f, meta, body in candidates
    )
    raw = api_call(
        JUDGE_MODEL,
        JUDGE_PROMPT.format(knowledge=knowledge, candidates=listing),
        max_tokens=1500,
    )
    if raw is None:
        return {}
    parsed = parse_json_block(raw)
    if not isinstance(parsed, list):
        log.error("Judge did not return an array.")
        return {}
    return {item.get("id"): item for item in parsed if isinstance(item, dict)}


def route(path: Path, meta: dict, body: str, verdict: dict, now: str, dry_run: bool) -> str:
    decision = verdict.get("verdict", "new")
    reason = verdict.get("reason", "")
    layer = meta.get("layer", "B").upper()

    if decision == "known":
        dest_dir, status = REJECTED, "rejected-known"
    elif layer == "A":
        dest_dir, status = PENDING, "pending-approval"
    else:
        dest_dir, status = RULES, "active"

    label = f"{decision} -> {status}"
    if dry_run:
        log.info("  [%s] %s (%s)", label, meta.get("id"), reason)
        return label

    meta["status"] = status
    meta["consolidated"] = now
    if reason:
        meta["consolidation_reason"] = reason
    write_note(dest_dir / path.name, meta, body)
    path.unlink()
    log.info("  %s: %s", label, meta.get("id"))
    return label


def consolidate(dry_run: bool = False) -> dict[str, int]:
    candidates = load_candidates()
    if not candidates:
        log.info("No candidates to consolidate.")
        return {}
    log.info("Consolidating %d candidate(s)...", len(candidates))
    knowledge = load_existing_knowledge()
    now = datetime.now(timezone.utc).isoformat()
    tally: dict[str, int] = {}
    for i in range(0, len(candidates), BATCH):
        batch = candidates[i:i + BATCH]
        verdicts = classify(batch, knowledge)
        if not verdicts:
            log.error("Classification failed for batch %d; left in place for retry.",
                      i // BATCH + 1)
            continue
        for f, meta, body in batch:
            v = verdicts.get(meta.get("id"), {"verdict": "new", "reason": "unclassified"})
            label = route(f, meta, body, v, now, dry_run)
            tally[label] = tally.get(label, 0) + 1
    log.info("Consolidation summary: %s", tally)
    return tally


if __name__ == "__main__":
    consolidate(dry_run="--dry-run" in sys.argv)
