"""
Cognitive Memory — Project-State Model

The leap from passive retrieval to a stateful collaborator. Instead of timeless
tips, this maintains a living model of where each project actually stands: its
goal, its claims (each with status and evidence), open questions, decisions made,
blockers, and current focus. It updates incrementally from each session and flags
contradictions where new evidence undercuts a standing claim, so the assistant can
reason across time ("today's result undercuts the claim you wrote Tuesday") rather
than just recall facts.

Stored as vault/projects/<project>.md, injected at SessionStart for continuity.

Usage:
  python projectstate.py <transcript.jsonl> <project>
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, api_call
import config
from acquire import extract_conversation

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.projectstate")

PROJECTS = VAULT / "projects"
NOTES = VAULT / ".notes.jsonl"
MODEL = config.model("projectstate")
ALERTS = VAULT / ".state-alerts.jsonl"


def recent_notes(project: str) -> str:
    """In-the-loop notes the assistant recorded for this project, to fold into the
    state update. Matched by working-directory basename; bounded to the last day."""
    if not NOTES.exists():
        return ""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    out = []
    for line in NOTES.read_text(errors="replace").splitlines():
        try:
            n = json.loads(line)
        except json.JSONDecodeError:
            continue
        cwd_base = Path(n.get("cwd", "")).name.lower()
        if cwd_base == project.lower() and n.get("ts", "") >= cutoff:
            out.append(f"- {n.get('text', '')}")
    return "\n".join(out)


PROMPT = """You maintain a living state model for a software/research project, so a
coding assistant can resume with full situational awareness instead of starting cold.

Below is the CURRENT STATE (may be empty for a new project) and a NEW SESSION transcript.
Produce an UPDATED state as compact markdown with exactly these sections:

## Goal
(one or two sentences: what this project is trying to achieve/prove)
## Claims
(bullet list; each: the claim, then [supported|contradicted|open] and a brief evidence note)
## Open questions
(bullets)
## Decisions
(bullets: decisions made and why, most recent first; keep the durable ones)
## Blockers
(bullets, or "none")
## Current focus
(one or two sentences: what is actively being worked on)

Rules:
- Integrate the new session into the existing state; revise claim statuses as evidence
  changes. Keep it tight; drop stale detail. This is always-loaded, so be economical.
- If new evidence CONTRADICTS a previously supported claim, mark it contradicted AND
  list it under a final section "## Contradictions flagged" (claim + what undercut it).
  Omit that section if there are none.

=== CURRENT STATE ===
{state}

=== NEW SESSION ===
{convo}"""


def state_path(project: str) -> Path:
    return PROJECTS / f"{project.lower()}.md"


def _section(body: str, name: str) -> str:
    if f"## {name}" not in body:
        return ""
    seg = body.split(f"## {name}", 1)[1]
    return seg.split("\n## ", 1)[0].strip()


def snapshot(project: str, body: str, now: str) -> None:
    """Append a compact point-in-time record so progress can be reasoned about
    over weeks (e.g. a blocker persisting across snapshots = stalled)."""
    history = PROJECTS / f"{project.lower()}.history.jsonl"
    snap = {
        "ts": now,
        "supported": body.count("[supported]"),
        "contradicted": body.count("[contradicted]"),
        "open": body.count("[open]"),
        "blockers": _section(body, "Blockers")[:300],
        "focus": _section(body, "Current focus")[:200],
    }
    with history.open("a") as fh:
        fh.write(json.dumps(snap) + "\n")


def update(transcript: Path, project: str) -> bool:
    convo = extract_conversation(transcript)
    if len(convo) < 200:
        return False
    path = state_path(project)
    current = path.read_text(errors="replace") if path.exists() else "(new project, no state yet)"
    notes = recent_notes(project)
    if notes:
        convo += "\n\n=== EXPLICIT IN-LOOP NOTES (high signal) ===\n" + notes
    raw = api_call(MODEL, PROMPT.format(state=current, convo=convo), max_tokens=1500)
    if raw is None:
        return False
    body = raw.strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[1].rsplit("```", 1)[0].strip()

    now = datetime.now(timezone.utc).isoformat()
    PROJECTS.mkdir(parents=True, exist_ok=True)
    header = f"<!-- cogmem project-state: {project}, updated {now} -->\n"
    path.write_text(header + body + "\n")
    snapshot(project, body, now)

    # Record any flagged contradictions as alerts to surface next session.
    if "## Contradictions flagged" in body:
        section = body.split("## Contradictions flagged", 1)[1].strip()
        ALERTS.parent.mkdir(parents=True, exist_ok=True)
        with ALERTS.open("a") as fh:
            fh.write(json.dumps({"project": project, "ts": now, "note": section[:500]}) + "\n")
        log.info("Contradiction flagged in %s", project)
    log.info("Updated project state: %s", path.name)
    return True


def activate(project: str) -> str:
    """Return the project state for injection, minus the HTML comment header."""
    path = state_path(project)
    if not path.exists():
        return ""
    return "\n".join(l for l in path.read_text(errors="replace").splitlines()
                     if not l.startswith("<!--"))


if __name__ == "__main__":
    if "--activate" in sys.argv:
        rest = [a for a in sys.argv[1:] if a != "--activate"]
        sys.stdout.write(activate(rest[0]) if rest else "")
        sys.exit(0)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        log.error("Usage: projectstate.py <transcript> <project> | --activate <project>")
        sys.exit(1)
    tp = Path(args[0])
    if not tp.exists():
        log.error("Transcript not found: %s", tp)
        sys.exit(1)
    update(tp, args[1])
