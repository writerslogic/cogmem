"""
Cognitive Memory — Guard (mistake interception)

The self-check surfaces failure modes at session start. This catches the
mechanically-detectable ones at the exact moment of action: it matches a proposed
command against the tripwires attached to failure modes and reports any hits, so a
PreToolUse hook can remind ("warn") or block ("block") before the mistake lands.

Usage:
  python guard.py "<command text>"      # prints JSON list of matches
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, read_note

FAILURES = VAULT / "failures"


def load_tripwires() -> list[tuple[str, str, str]]:
    out = []
    if not FAILURES.exists():
        return out
    for f in FAILURES.glob("*.md"):
        meta, body = read_note(f)
        tw = meta.get("tripwire")
        if tw:
            out.append((tw, meta.get("guard", "warn"), body))
    return out


def check(command: str) -> list[dict]:
    hits = []
    for tw, guard, lesson in load_tripwires():
        try:
            matched = re.search(tw, command) is not None
        except re.error:
            matched = tw in command
        if matched:
            hits.append({"guard": guard, "lesson": lesson.replace("\n", " ").strip(),
                         "tripwire": tw})
    return hits


if __name__ == "__main__":
    command = " ".join(sys.argv[1:])
    sys.stdout.write(json.dumps(check(command)))
