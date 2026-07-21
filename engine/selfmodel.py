"""
Cognitive Memory — Self-Model (assistant failure modes)

Domain rules say what is true about the user's work. This is different: it tracks
where CLAUDE itself goes wrong in that work, so the same mistake stops recurring.
For each signal-session it extracts the assistant's own missteps (things the user
corrected or that caused rework), distinct from domain knowledge, and dedups them
against the existing self-model so a recurring mistake strengthens (count++) rather
than duplicating.

Stored in vault/failures/ and surfaced by SessionStart as a pre-flight self-check.

Usage:
  python selfmodel.py <transcript.jsonl>
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from cogmem.common import VAULT, api_call, parse_json_block, read_note, write_note
from cogmem import config
from cogmem.acquire import extract_conversation, slugify

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.selfmodel")

FAILURES = VAULT / "failures"
MODEL = config.model("selfmodel")


def load_existing() -> list[tuple[str, str]]:
    out = []
    for f in sorted(FAILURES.glob("*.md")):
        meta, body = read_note(f)
        out.append((meta.get("id", f.stem), body))
    return out


PROMPT = """You are the self-model of a coding assistant. Read the session transcript
and identify the assistant's OWN failure modes: specific things the assistant (not the
user) did suboptimally that the user had to correct, or that caused avoidable rework.

These are about the assistant's behavior, NOT domain facts. Examples of the shape:
"ran the build after every edit instead of batching", "declared a task done before
verifying", "over-refactored beyond the request", "accepted a result without checking
for a bug first".

For each failure mode give:
- mode: a self-directive naming the mistake and the correct behavior, second person
  ("You did X; instead do Y")
- scope: a project name, a language, or "universal"
- trigger: the situation in which this mistake tends to happen
- tripwire: IF and ONLY IF the mistake is mechanically detectable in a shell command or
  file path about to be run (e.g. a specific flag, command, or token), give a concrete
  substring or simple regex that would appear right before the mistake. Otherwise null.
- guard: "warn" (default) or "block" (only for clearly destructive/irreversible mistakes)

You are also given the EXISTING failure modes. If a new observation matches one of
them, return it with action "recur" and that id (so it strengthens). Otherwise action
"new". Be strict: only real, repeatable missteps, not one-off noise. If none, return
{{"failures": []}}.

Return ONLY JSON: {{"failures": [{{"action": "new|recur", "id": "<id if recur>",
"mode": "...", "scope": "...", "trigger": "..."}}]}}

=== EXISTING FAILURE MODES ===
{existing}

=== TRANSCRIPT ===
{convo}"""


def run(transcript: Path) -> dict:
    convo = extract_conversation(transcript)
    if len(convo) < 200:
        return {}
    existing = load_existing()
    listing = "\n".join(f"- {fid}: {body}" for fid, body in existing) or "(none yet)"
    raw = api_call(MODEL, PROMPT.format(existing=listing, convo=convo), max_tokens=1200)
    if raw is None:
        return {}
    result = parse_json_block(raw)
    if not isinstance(result, dict):
        return {}
    failures = result.get("failures", [])
    now = datetime.now(timezone.utc).isoformat()
    FAILURES.mkdir(parents=True, exist_ok=True)
    tally = {"new": 0, "recur": 0}

    def _bump(path: Path) -> int:
        """Increment an existing failure-mode note's recurrence count + last_seen."""
        meta, body = read_note(path)
        meta["count"] = int(meta.get("count", 1)) + 1
        meta["last_seen"] = now
        write_note(path, meta, body)
        tally["recur"] += 1
        return meta["count"]

    for item in failures:
        mode = (item.get("mode") or "").strip()
        if not mode:
            continue
        if item.get("action") == "recur" and item.get("id"):
            path = FAILURES / f"{item['id']}.md"
            if path.exists():
                log.info("  RECUR (x%s): %s", _bump(path), item["id"])
                continue
        scope = (item.get("scope") or "universal").strip()
        slug = f"{scope}-{slugify(mode)}"
        path = FAILURES / f"{slug}.md"
        if path.exists():
            _bump(path)
            continue
        tripwire = (item.get("tripwire") or "").strip()
        meta = {
            "id": slug,
            "scope": scope,
            "kind": "failure-mode",
            "count": 1,
            "created": now,
            "last_seen": now,
            "trigger": (item.get("trigger") or "").replace('"', "'"),
        }
        if tripwire and tripwire.lower() != "null":
            meta["tripwire"] = tripwire
            meta["guard"] = (item.get("guard") or "warn").strip() or "warn"
        write_note(path, meta, mode)
        tally["new"] += 1
        log.info("  NEW: %s", slug)
    log.info("Self-model update: %s", tally)
    return tally


def activate(scopes: list[str], limit: int = 5) -> str:
    """Format the top failure modes for the given scopes as a self-check block,
    most-recurrent first. Returns '' if there are none."""
    want = {s.lower() for s in scopes if s}
    items = []
    for f in FAILURES.glob("*.md"):
        meta, body = read_note(f)
        if (meta.get("scope") or "").lower() in want:
            items.append((int(meta.get("count", 1)), body))
    items.sort(key=lambda t: t[0], reverse=True)
    if not items:
        return ""
    lines = ["COGMEM self-check (your known failure modes here, avoid repeating):"]
    for count, body in items[:limit]:
        tag = f" (seen x{count})" if count > 1 else ""
        lines.append(f"- {body}{tag}")
    return "\n".join(lines)


if __name__ == "__main__":
    if "--activate" in sys.argv:
        scopes = [a for a in sys.argv[1:] if a != "--activate"] or ["universal"]
        block = activate(scopes)
        if block:
            sys.stdout.write(block)
        sys.exit(0)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        log.error("Usage: selfmodel.py <transcript.jsonl> | --activate <scope...>")
        sys.exit(1)
    tp = Path(args[0])
    if not tp.exists():
        log.error("Transcript not found: %s", tp)
        sys.exit(1)
    run(tp)
