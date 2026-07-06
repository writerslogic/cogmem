"""
Cognitive Memory — User Model

Scattered rules say isolated facts about the user. This synthesizes them into one
compact, evolving model of how David works: his standards, what "done" means to him,
his recurring corrections and priorities. The goal is to let the assistant predict
him, not just retrieve facts about him. Always-loaded, so it is kept short.

Source evidence: episodes, approved (always-load) rules, and the assistant's own
failure modes (which encode what he keeps correcting). Regenerated on demand or
when enough new evidence accrues.

Usage:
  python usermodel.py            # (re)synthesize vault/user-model.md
"""

import logging
from datetime import datetime, timezone

from cogmem.common import VAULT, api_call, read_note
from cogmem import config

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.usermodel")

MODEL_FILE = VAULT / "user-model.md"
MODEL = config.model("usermodel")
MAX_ITEMS = 60  # cap evidence fed to the synthesizer


def gather_evidence() -> str:
    parts = []
    eps = sorted((VAULT / "episodes").glob("*.md"))
    for f in eps[:20]:
        _, body = read_note(f)
        if body:
            parts.append("EPISODE: " + body.replace("\n", " ")[:400])
    for sub in ("learned", "promoted"):
        for f in sorted((VAULT / sub).glob("*.md"))[:25]:
            _, body = read_note(f)
            if body:
                parts.append("RULE: " + body.replace("\n", " ")[:240])
    for f in sorted((VAULT / "failures").glob("*.md"))[:15]:
        _, body = read_note(f)
        if body:
            parts.append("CORRECTS: " + body.replace("\n", " ")[:240])
    return "\n".join(parts[:MAX_ITEMS])


PROMPT = """You are building a compact working model of {name}, the developer this
assistant works with, to help it predict them rather than just recall facts. Synthesize
the evidence below into a SHORT markdown profile (under ~320 words) with these sections:

## Standards (what "done" means to them; their bar for rigor)
## Working style (how they want the assistant to operate)
## Preferences (tools, conventions, things they repeatedly want or reject)
## Recurring corrections (mistakes they keep having to catch)

Capture their GENERAL working principles and meta-standards, the underlying patterns
behind the evidence. Do NOT restate narrow project-specific operational rules verbatim
(those are stored and loaded separately); abstract them to the principle they share.
Be distinctive to {name} and grounded in evidence, no generic advice. Output only the
markdown, and keep it tight.

=== EVIDENCE ===
{evidence}"""


def synthesize() -> bool:
    evidence = gather_evidence()
    if len(evidence) < 200:
        log.info("Not enough evidence yet to synthesize a user model.")
        return False
    name = config.load().get("user_name") or "the user"
    raw = api_call(MODEL, PROMPT.format(name=name, evidence=evidence), max_tokens=900)
    if raw is None:
        return False
    now = datetime.now(timezone.utc).isoformat()
    header = f"<!-- cogmem user-model, synthesized {now} -->\n# User model: {name}\n\n"
    MODEL_FILE.write_text(header + raw.strip() + "\n")
    log.info("Wrote user model (%d chars) -> %s", len(raw), MODEL_FILE.name)
    return True


if __name__ == "__main__":
    synthesize()
