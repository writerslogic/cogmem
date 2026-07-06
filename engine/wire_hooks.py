"""
Cognitive Memory — Claude Code hook wiring

The canonical mapping of Claude Code events to cogmem hook scripts, plus the
idempotent merge into a settings.json. install.sh calls this as a script; it is
importable so the merge logic — the part most likely to corrupt a user's
settings or double-wire a hook — can be unit-tested.

Usage (script, via install.sh):
  COGMEM_HOME=... CLAUDE_DIR=... python wire_hooks.py
"""

import json
import os
import sys
from pathlib import Path

# (event, matcher, hook script) — the working v2 integration.
WIRING = [
    ("SessionStart", "*", "cogmem-activate.sh"),
    ("UserPromptSubmit", "*", "cogmem-recall.sh"),
    ("PreToolUse", "Bash", "cogmem-guard.sh"),
    ("PostToolUse", "Edit|Write", "cogmem-context.sh"),
    ("Stop", "*", "cogmem-capture.sh"),
]


def wire(settings: Path, hooks_dir: Path) -> int:
    """Merge the cogmem hooks into settings.json idempotently. Returns the number
    of hooks newly added (0 when they were all already present). Pre-existing
    settings and unrelated hooks are preserved."""
    data = json.loads(settings.read_text()) if settings.exists() else {}
    hooks = data.setdefault("hooks", {})
    added = 0
    for event, matcher, script in WIRING:
        cmd = str(hooks_dir / script)
        arr = hooks.setdefault(event, [])
        # Idempotent: skip if any entry already runs this cogmem hook.
        if any(h.get("command") == cmd for entry in arr for h in entry.get("hooks", [])):
            continue
        arr.append({"matcher": matcher, "hooks": [{"type": "command", "command": cmd}]})
        added += 1
    if added or not settings.exists():
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text(json.dumps(data, indent=2) + "\n")
    return added


if __name__ == "__main__":
    home = Path(os.environ["COGMEM_HOME"])
    settings_path = Path(os.environ["CLAUDE_DIR"]) / "settings.json"
    added = wire(settings_path, home / "hooks")
    sys.stdout.write(f"   {added} hook(s) added, {len(WIRING) - added} already present\n")
