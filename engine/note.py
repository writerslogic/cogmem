"""
Cognitive Memory — in-the-loop note writer

Records a decision or finding the moment it happens, so memory is written through
a task rather than only reconstructed at session end. Notes are timestamped and
tagged with the working directory; the capture pipeline folds recent notes into
the project-state update for that project.

Usage:  python note.py <text...>
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

NOTES = Path.home() / ".claude" / "cogmem" / "vault" / ".notes.jsonl"


def main() -> int:
    text = " ".join(sys.argv[1:]).strip()
    if not text:
        sys.stderr.write("usage: note.py <text>\n")
        return 1
    NOTES.parent.mkdir(parents=True, exist_ok=True)
    with NOTES.open("a") as fh:
        fh.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "cwd": os.getcwd(),
            "text": text,
        }) + "\n")
    sys.stdout.write("noted\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
