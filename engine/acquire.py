"""
Cognitive Memory — Acquisition Engine

Reads a session transcript, detects whether it contains behavior-change signal,
and (only when it does) extracts candidate rules: durable, scope-tagged things
that should change how the assistant acts in future sessions.

Design goal: learn how the user works so the assistant completes their work more
accurately and more autonomously. The unit of value is a behavior-change rule
that can be reliably surfaced when relevant.

Two-step cadence (cost discipline):
  1. detect  — cheap model decides if the session has any signal at all
  2. extract — strong model runs ONLY when signal is present

Output: candidate rule files (markdown + YAML frontmatter) under vault/candidates/.
Candidates are never auto-promoted; consolidation dedups them and queues Layer-A
rules for human approval. The markdown files are the source of truth; nothing is
locked into a database.

Usage:
  python acquire.py <transcript.jsonl>      # explicit path
  cat hook_payload.json | python acquire.py  # Stop-hook mode (reads transcript_path)
  python acquire.py <transcript.jsonl> --dry-run   # print, don't write
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
from common import api_call, parse_json_block

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.acquire")

COGMEM = Path(os.environ.get("COGMEM_HOME", Path.home() / ".claude" / "cogmem"))
CANDIDATES_DIR = COGMEM / "vault" / "candidates"

DETECT_MODEL = config.model("detect")    # cheap: runs every session
EXTRACT_MODEL = config.model("extract")  # strong: runs only on signal

# Cap transcript size sent to the model. Most signal lives in user turns
# (corrections, preferences) and assistant text; we drop thinking/tool noise.
MAX_TRANSCRIPT_CHARS = 60_000


def extract_conversation(transcript_path: Path) -> str:
    """Flatten a Claude Code transcript to role-tagged text, dropping
    thinking blocks and tool noise (low signal, high token cost)."""
    lines = []
    for raw in transcript_path.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("type") not in ("user", "assistant"):
            continue
        msg = obj.get("message") or {}
        role = msg.get("role")
        content = msg.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "\n".join(
                b.get("text", "")
                for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            text = ""
        text = text.strip()
        if text:
            lines.append(f"[{role}] {text}")
    convo = "\n".join(lines)
    if len(convo) > MAX_TRANSCRIPT_CHARS:
        # keep the tail: corrections and conclusions cluster at the end
        convo = convo[-MAX_TRANSCRIPT_CHARS:]
    return convo


DETECT_PROMPT = """You are a signal detector for a coding assistant's memory system.
Decide whether this session contains BEHAVIOR-CHANGE SIGNAL worth learning: a user
correction, a stated preference, a repeated or notable mistake, a non-obvious decision,
or a genuine surprise. Routine sessions with nothing transferable have no signal.

Answer with ONLY one word: YES or NO.

TRANSCRIPT:
{convo}"""

EXTRACT_PROMPT = """You are the acquisition engine for a coding assistant's memory system.
Goal: learn how this user works so the assistant completes their work more accurately and
more autonomously next time.

Extract BEHAVIOR-CHANGE RULES from the session: specific things that should change how the
assistant acts in future sessions. For each rule provide:
- layer: "A" or "B". DEFAULT TO "B". A rule is "A" (always-load) ONLY if forgetting it
  would ship a bug or repeat a costly mistake, AND it must be present from the very start
  of EVERY relevant session because there is no prompt that would reliably recall it in
  time. Facts, situational knowledge, one-off context, anything you would only need "when
  relevant", and anything a recall query could surface in the moment are ALL "B".
- scope: a project name, a language, or "universal"
- rule: the imperative rule itself, self-contained
- evidence: brief paraphrase of what in the session supports it

Be strict. Prefer a few high-value rules over many weak ones. Expect most rules to be "B";
"A" is rare. Layer A is a tiny, precious budget; reserve it for true must-never-miss guardrails.
If the session has nothing worth learning, return {{"signal": false, "rules": []}}.

Return ONLY JSON: {{"signal": true/false, "rules": [...]}}.

TRANSCRIPT:
{convo}"""


def slugify(text: str, maxlen: int = 50) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen].rstrip("-") or "rule"


def write_candidate(rule: dict, session_id: str, now: str) -> Path | None:
    rule_text = (rule.get("rule") or "").strip()
    if not rule_text:
        return None
    layer = rule.get("layer", "B").upper()
    if layer not in ("A", "B"):
        layer = "B"
    scope = (rule.get("scope") or "universal").strip()
    evidence = (rule.get("evidence") or "").replace('"', "'").strip()

    slug = f"{scope}-{slugify(rule_text)}"
    path = CANDIDATES_DIR / f"{slug}.md"
    # avoid clobbering distinct candidates that slugify the same
    n = 2
    while path.exists():
        path = CANDIDATES_DIR / f"{slug}-{n}.md"
        n += 1

    frontmatter = (
        "---\n"
        f"id: {path.stem}\n"
        f"layer: {layer}\n"
        f"scope: {scope}\n"
        "status: candidate\n"
        f"created: {now}\n"
        f"source_session: {session_id}\n"
        f'evidence: "{evidence}"\n'
        "---\n\n"
    )
    path.write_text(frontmatter + rule_text + "\n")
    return path


def acquire(transcript_path: Path, dry_run: bool = False) -> int:
    if not transcript_path.exists():
        log.error("Transcript not found: %s", transcript_path)
        return 0
    convo = extract_conversation(transcript_path)
    if len(convo) < 200:
        log.info("Transcript too short to carry signal; skipping.")
        return 0

    detect = api_call(DETECT_MODEL, DETECT_PROMPT.format(convo=convo), max_tokens=5)
    if detect is None:
        return 0
    if "yes" not in detect.lower():
        log.info("No behavior-change signal detected; skipping extraction.")
        return 0
    log.info("Signal detected; running extraction.")

    raw = api_call(EXTRACT_MODEL, EXTRACT_PROMPT.format(convo=convo), max_tokens=2000)
    if raw is None:
        return 0
    result = parse_json_block(raw)
    if not result or not result.get("signal"):
        log.info("Extractor found no rules.")
        return 0

    session_id = transcript_path.stem
    now = datetime.now(timezone.utc).isoformat()
    rules = result.get("rules", [])

    if dry_run:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        log.info("[dry-run] would write %d candidate(s).", len(rules))
        return len(rules)

    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for rule in rules:
        p = write_candidate(rule, session_id, now)
        if p:
            written += 1
            log.info("  CANDIDATE [%s/%s] %s", rule.get("layer"), rule.get("scope"), p.name)
    log.info("Wrote %d candidate rule(s) to %s", written, CANDIDATES_DIR)
    return written


def resolve_transcript_arg(arg: str) -> Path | None:
    """Accept either a transcript path or a Stop-hook JSON payload on stdin."""
    if arg and arg != "-":
        return Path(arg)
    try:
        payload = json.loads(sys.stdin.read())
        tp = payload.get("transcript_path")
        return Path(tp) if tp else None
    except json.JSONDecodeError:
        return None


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    path = resolve_transcript_arg(args[0] if args else "-")
    if path is None:
        log.error("No transcript path (arg or stdin hook payload required)")
        sys.exit(1)
    acquire(path, dry_run=dry)
