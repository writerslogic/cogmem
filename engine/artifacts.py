"""
Cognitive Memory — Artifact Grounding (git history)

Transcripts are a thin slice of the work. The repo records far more: what was
fixed, what got reverted, the gotchas that show up in commit after commit. This
mines a project's recent git history into candidate rules, so the system learns
from what was actually done, not only what was discussed. Output goes into the
normal candidate pipeline (consolidation dedups against existing knowledge).

Usage:
  python artifacts.py [repo_path]    # default: current directory
"""

import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cogmem.common import VAULT, api_call, parse_json_block, write_note
from cogmem import config
from cogmem.acquire import slugify

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.artifacts")

CANDIDATES = VAULT / "candidates"
MODEL = config.model("artifacts")
MAX_COMMITS = 150


def git_history(repo: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", f"-n{MAX_COMMITS}", "--no-merges",
             "--pretty=format:%h %s%n%b%n---"],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as e:
        log.error("git failed: %s", e)
        return None
    if r.returncode != 0:
        log.info("Not a git repo or no history: %s", repo)
        return None
    return r.stdout[:24000]


PROMPT = """Below are recent git commits (subjects and bodies) from the project "{project}".
Extract durable lessons that should change how a coding assistant works in THIS repo:
recurring bug classes, things that had to be reverted (and why), non-obvious gotchas,
and conventions revealed by fix commits. These are situational (Layer B) rules.

Be strict: only real, recurring or hard-won signal evident in the history, not generic
advice. Return at most 8 of the strongest. If nothing solid, return {{"rules": []}}.

Return ONLY JSON: {{"rules": [{{"rule": "imperative, self-contained", "evidence": "which commits/pattern"}}]}}

=== COMMITS ===
{history}"""


def ingest(repo: Path) -> int:
    history = git_history(repo)
    if not history or len(history) < 200:
        log.info("No usable history to ingest.")
        return 0
    project = repo.name
    raw = api_call(MODEL, PROMPT.format(project=project, history=history), max_tokens=2500)
    if raw is None:
        return 0
    result = parse_json_block(raw)
    if not isinstance(result, dict):
        return 0
    rules = result.get("rules", [])
    now = datetime.now(timezone.utc).isoformat()
    CANDIDATES.mkdir(parents=True, exist_ok=True)
    written = 0
    for item in rules:
        text = (item.get("rule") or "").strip()
        if not text:
            continue
        scope = project.lower()
        slug = f"{scope}-{slugify(text)}"
        meta = {
            "id": slug, "layer": "B", "scope": scope, "status": "candidate",
            "created": now, "source": f"git:{project}",
            "evidence": (item.get("evidence") or "").replace('"', "'"),
        }
        write_note(CANDIDATES / f"{slug}.md", meta, text)
        written += 1
        log.info("  CANDIDATE [%s] %s", scope, slug)
    log.info("Ingested %d candidate rule(s) from %s history.", written, project)
    return written


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    repo = Path(args[0]) if args else Path.cwd()
    ingest(repo)
