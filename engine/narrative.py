"""
Cognitive Memory — Cross-Project Progress Narrative

Per-project state says where one project stands now. This reasons across projects
and across time: which goals are advancing, which are stalled (a blocker persisting
over weeks), and how projects depend on each other (e.g. WritersEye depends on HMS
via HMSBridge, so HMS's encryption blocker blocks WritersEye too).

Two outputs:
- stall_alert(project): fast, no-API, for SessionStart — "blocked on X for N days".
- progress(): a model-synthesized cross-project report for `cogmem progress`.

Usage:
  python narrative.py                 # cross-project progress report
  python narrative.py --alert <proj>  # one-line stall alert for a project
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, api_call

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cogmem.narrative")

PROJECTS = VAULT / "projects"
MODEL = "claude-sonnet-4-6"
STALL_DAYS = 10   # a blocker present this long without clearing = stalled


def load_states() -> dict[str, str]:
    states = {}
    if not PROJECTS.exists():
        return states
    for f in sorted(PROJECTS.glob("*.md")):
        states[f.stem] = "\n".join(l for l in f.read_text(errors="replace").splitlines()
                                   if not l.startswith("<!--"))
    return states


def load_history(project: str) -> list[dict]:
    h = PROJECTS / f"{project.lower()}.history.jsonl"
    if not h.exists():
        return []
    out = []
    for line in h.read_text(errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _days_since(ts: str) -> float:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).days
    except (ValueError, TypeError):
        return 0.0


def stall_signal(project: str) -> dict:
    """Mechanical: is a blocker persisting across snapshots, and for how long?"""
    hist = load_history(project)
    if not hist:
        return {}
    latest = hist[-1]
    blockers = (latest.get("blockers") or "").strip()
    if not blockers or blockers.lower() in ("none", "- none"):
        return {}
    # earliest snapshot whose blockers overlap the latest non-trivial blocker lines
    latest_lines = {l.strip("- ").strip().lower()[:60] for l in blockers.splitlines() if l.strip()}
    first_seen = latest.get("ts")
    for snap in hist:
        snap_lines = {l.strip("- ").strip().lower()[:60]
                      for l in (snap.get("blockers") or "").splitlines() if l.strip()}
        if latest_lines & snap_lines:
            first_seen = snap.get("ts")
            break
    return {"blocked_days": _days_since(first_seen), "blockers": blockers}


def stall_alert(project: str) -> str:
    sig = stall_signal(project)
    if not sig or sig["blocked_days"] < STALL_DAYS:
        return ""
    first = sig["blockers"].splitlines()[0].strip("- ").strip()
    return (f"COGMEM progress alert: {project} has been blocked ~{int(sig['blocked_days'])} "
            f"days on: {first[:120]}. Consider unblocking or re-scoping.")


PROMPT = """You are writing a cross-project progress review for a developer. For each
project below you have its current state and computed signals (snapshot count, days
tracked, any persisting blockers). Write a TIGHT report:

For each project: one line on goal, one line on momentum (advancing / stalled / blocked,
and why), and call out anything stalled with how long.
Then a short "Cross-project" section: dependencies between these projects and the
implications (if project A is blocked on X and project B depends on A, say so).

Be specific and grounded. No filler. Output only markdown.

=== PROJECTS ===
{projects}"""


def progress() -> None:
    states = load_states()
    if not states:
        log.info("No project states yet.")
        return
    blocks = []
    names = list(states.keys())
    for name, body in states.items():
        sig = stall_signal(name)
        hist = load_history(name)
        deps = [o for o in names if o != name and o.lower() in body.lower()]
        signal = (f"[snapshots={len(hist)}, "
                  f"blocked_days={int(sig.get('blocked_days', 0))}, "
                  f"mentions={deps or 'none'}]")
        blocks.append(f"### {name} {signal}\n{body}")
    raw = api_call(MODEL, PROMPT.format(projects="\n\n".join(blocks)), max_tokens=1200)
    if raw:
        sys.stdout.write(raw.strip() + "\n")


if __name__ == "__main__":
    if "--alert" in sys.argv:
        rest = [a for a in sys.argv[1:] if a != "--alert"]
        sys.stdout.write(stall_alert(rest[0]) if rest else "")
        sys.exit(0)
    progress()
