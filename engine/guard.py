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
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, read_note

FAILURES = VAULT / "failures"

# Tripwires are model-generated regexes run on every Bash command. A catastrophic-
# backtracking pattern (whether accidental or planted in a poisoned failure note)
# would otherwise hang the PreToolUse hook on every command. Bound the inputs and
# cap total matching time; on timeout, fail open (match nothing) rather than block.
MAX_CMD = 8192          # chars of command considered
MAX_PATTERN = 512       # oversized patterns fall back to literal substring search
MATCH_BUDGET = 0.25     # seconds total across all tripwires


class _MatchTimeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _MatchTimeout


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
    command = command[:MAX_CMD]
    hits = []
    use_alarm = hasattr(signal, "SIGALRM")
    if use_alarm:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, MATCH_BUDGET)
    try:
        for tw, guard, lesson in load_tripwires():
            if len(tw) > MAX_PATTERN:
                matched = tw[:MAX_PATTERN] in command
            else:
                try:
                    matched = re.search(tw, command) is not None
                except re.error:
                    matched = tw in command
            if matched:
                hits.append({"guard": guard, "lesson": lesson.replace("\n", " ").strip(),
                             "tripwire": tw})
    except _MatchTimeout:
        pass
    finally:
        if use_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
    return hits


if __name__ == "__main__":
    command = " ".join(sys.argv[1:])
    sys.stdout.write(json.dumps(check(command)))
