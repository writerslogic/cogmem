"""
Cognitive Memory — Approval Surface

Layer-A rules are always-loaded, so each one costs context budget in every relevant
session forever. That makes them the one thing a human must vet. This is that gate.

  review.py list                  # show pending Layer-A rules
  review.py promote <id> [--to F] # accept: append to a managed block in F
  review.py reject  <id>          # decline: move to vault/rejected

Default promote target is routed by scope into cogmem-owned files under
vault/learned/ (universal.md, rust.md, ...), so the user's hand-written CLAUDE.md
and mode files are never mutated unless --to names one explicitly. The cutover step
wires the learned files to load. Only the rule text goes into the loaded file;
evidence and provenance stay in the vault note.
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, CLAUDE_DIR, read_note, write_note
from metrics import scope_tokens, PER_SCOPE_CAP

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cogmem.review")

PENDING = VAULT / "pending"
REJECTED = VAULT / "rejected"
LEARNED = VAULT / "learned"
PROMOTED = VAULT / "promoted"

KNOWN_MODES = {"rust", "swift", "web", "c2pa", "ietf", "company", "narrative", "research"}

BLOCK_START = "<!-- cogmem:learned:start -->"
BLOCK_END = "<!-- cogmem:learned:end -->"


def find_pending(token: str) -> Path | None:
    matches = [f for f in PENDING.glob("*.md") if token in f.stem]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        log.error("Ambiguous id '%s' matches %d rules; be more specific.", token, len(matches))
    else:
        log.error("No pending rule matches '%s'.", token)
    return None


def default_target(scope: str) -> Path:
    # Lowercase everywhere so scope/project case never has to match exactly
    # (SessionStart lowercases its lookup too).
    scope = (scope or "universal").strip().lower()
    if scope == "universal":
        return LEARNED / "universal.md"
    return LEARNED / f"{scope}.md"


def append_to_block(target: Path, rule_text: str, rule_id: str) -> None:
    """Insert a rule bullet inside the managed block, creating the block if absent.
    Idempotent on rule_id so re-promotion does not duplicate."""
    target.parent.mkdir(parents=True, exist_ok=True)
    bullet = f"- {rule_text}  <!-- {rule_id} -->"
    if target.exists():
        text = target.read_text()
    else:
        text = ""
    if rule_id in text:
        log.info("Already present in %s; skipping.", target.name)
        return
    if BLOCK_START in text and BLOCK_END in text:
        text = text.replace(BLOCK_END, bullet + "\n" + BLOCK_END, 1)
    else:
        block = f"\n{BLOCK_START}\n## Learned (cogmem)\n{bullet}\n{BLOCK_END}\n"
        text = text.rstrip() + "\n" + block if text.strip() else block.lstrip()
    target.write_text(text)


def cmd_list() -> None:
    pend = sorted(PENDING.glob("*.md"))
    if not pend:
        log.info("No Layer-A rules pending approval.")
        return
    log.info("=== Pending Layer-A rules (%d) ===", len(pend))
    for f in pend:
        meta, body = read_note(f)
        log.info("\n[%s]  scope: %s", meta.get("id", f.stem), meta.get("scope"))
        log.info("  rule: %s", body)
        if meta.get("evidence"):
            log.info("  why:  %s", meta["evidence"])
        log.info("  promote: review.py promote %s", f.stem.split("-")[0] + "...")


def cmd_promote(token: str, to: str | None, force: bool = False) -> None:
    f = find_pending(token)
    if not f:
        return
    meta, body = read_note(f)

    target = Path(to) if to else default_target(meta.get("scope", "universal"))
    if to and not target.is_absolute():
        target = CLAUDE_DIR / target

    # Budget gate: a session loads universal + one scope file, so cap per-scope
    # (not globally). Block a promotion that would push the target file over.
    cost = len(body) // 4
    existing = scope_tokens(target)
    if existing + cost > PER_SCOPE_CAP and not force:
        log.error("Scope '%s' would exceed per-scope cap: ~%d + ~%d > %d tokens.",
                  target.stem, existing, cost, PER_SCOPE_CAP)
        log.error("Prune a rule from %s first, or re-run with --force.", target.name)
        return
    append_to_block(target, body, meta.get("id", f.stem))
    meta["status"] = "promoted"
    meta["promoted_to"] = str(target)
    meta["promoted_at"] = datetime.now(timezone.utc).isoformat()
    write_note(PROMOTED / f.name, meta, body)
    f.unlink()
    log.info("Promoted %s -> %s", meta.get("id"), target)


def cmd_reject(token: str) -> None:
    f = find_pending(token)
    if not f:
        return
    meta, body = read_note(f)
    meta["status"] = "rejected-by-user"
    meta["rejected_at"] = datetime.now(timezone.utc).isoformat()
    write_note(REJECTED / f.name, meta, body)
    f.unlink()
    log.info("Rejected %s", meta.get("id"))


if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = args[0] if args else "list"
    if cmd == "list":
        cmd_list()
    elif cmd == "promote" and len(args) >= 2:
        to = args[args.index("--to") + 1] if "--to" in args else None
        cmd_promote(args[1], to, force="--force" in args)
    elif cmd == "reject" and len(args) >= 2:
        cmd_reject(args[1])
    else:
        log.error("Usage: review.py [list | promote <id> [--to FILE] | reject <id>]")
        sys.exit(1)
