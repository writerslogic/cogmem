"""
Cognitive Memory — Outcome Feedback Loop

Turns storage into learning. For the rules that were recalled during a session
(logged by the recall hook), this judges from the transcript whether each one was
helpful, ignored, or contradicted, and updates the rule's counters. Rules that
prove repeatedly wrong are demoted out of the index; Layer-B rules that prove
repeatedly helpful are surfaced as Layer-A promotion candidates (never
auto-promoted: the always-load gate stays human).

Usage:
  python feedback.py <transcript.jsonl>
  cat hook_payload.json | python feedback.py    # reads session_id + transcript_path
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from cogmem.common import VAULT, api_call, parse_json_block, read_note, write_note
from cogmem import config
from cogmem.acquire import extract_conversation, slugify

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.feedback")

RULES = VAULT / "rules"
PENDING = VAULT / "pending"
REJECTED = VAULT / "rejected"
CANDIDATES = VAULT / "candidates"
RECALL_LOG = VAULT / ".recall-log.jsonl"

JUDGE_MODEL = config.model("judge")
PROMOTE_HELPFUL = 3   # a Layer-B rule helpful this many times -> suggest for Layer A
DEMOTE_CONTRA = 2     # contradicted this many times (and > helpful) -> demote


def recalled_ids(session: str) -> set[str]:
    if not session or not RECALL_LOG.exists():
        return set()
    ids: set[str] = set()
    for line in RECALL_LOG.read_text(errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("session") == session:
            ids.update(entry.get("ids", []))
    return ids


JUDGE_PROMPT = """You are the feedback step of a coding assistant's memory system.
Below is a session transcript, then RULES that were surfaced to the assistant during
that session. For each rule, judge from the transcript how it played out:
- "helpful"      : it was relevant and applying it was correct
- "ignored"      : it was not relevant to what happened (neutral)
- "contradicted" : the session showed it to be wrong, outdated, or misleading

Be conservative: only say "contradicted" with clear evidence, only "helpful" if the
rule plausibly bore on the work. Default to "ignored".

When (and only when) a rule is "contradicted" and the transcript makes a clearly
better version evident, include a "correction": a rewritten, self-contained rule
that captures what is actually true. Otherwise set correction to null. Do not
rewrite rules that were merely ignored or that you are unsure about.

Return ONLY a JSON object mapping rule id to a verdict object:
{{"<id>": {{"verdict": "helpful|ignored|contradicted", "correction": "<text or null>"}}, ...}}

=== TRANSCRIPT ===
{convo}

=== RULES ===
{rules}"""


def judge(convo: str, rules: dict[str, str]) -> dict[str, dict]:
    listing = "\n".join(f"- {rid}: {body}" for rid, body in rules.items())
    raw = api_call(JUDGE_MODEL, JUDGE_PROMPT.format(convo=convo, rules=listing), max_tokens=700)
    if raw is None:
        return {}
    parsed = parse_json_block(raw)
    if not isinstance(parsed, dict):
        return {}
    # Tolerate a bare-string verdict as well as the verdict object.
    return {k: (v if isinstance(v, dict) else {"verdict": str(v), "correction": None})
            for k, v in parsed.items()}


def apply_verdict(path: Path, meta: dict, body: str, vobj: dict, session: str, now: str) -> str:
    verdict = vobj.get("verdict", "ignored")
    correction = vobj.get("correction")
    meta["recalled"] = int(meta.get("recalled", 0)) + 1
    if verdict == "helpful":
        meta["helpful"] = int(meta.get("helpful", 0)) + 1
    elif verdict == "contradicted":
        meta["contradicted"] = int(meta.get("contradicted", 0)) + 1
    meta["last_feedback"] = now

    helpful = int(meta.get("helpful", 0))
    contradicted = int(meta.get("contradicted", 0))

    # Self-refine: a contradiction with a clear correction supersedes the rule.
    # The old one is retired and the correction enters the SAME safe pipeline
    # (candidate -> consolidate -> dedup), never a blind in-place overwrite.
    if verdict == "contradicted" and isinstance(correction, str) and len(correction.strip()) > 15:
        meta["status"] = "refined-superseded"
        write_note(REJECTED / path.name, meta, body)
        path.unlink()
        cmeta = {
            "id": f"{meta.get('scope', 'universal')}-{slugify(correction)}",
            "layer": meta.get("layer", "B"),
            "scope": meta.get("scope", "universal"),
            "status": "candidate",
            "created": now,
            "source_session": session,
            "evidence": f"refined from {path.stem} after contradiction",
        }
        CANDIDATES.mkdir(parents=True, exist_ok=True)
        write_note(CANDIDATES / f"{cmeta['id']}.md", cmeta, correction.strip())
        return "refined"

    # Demote: repeatedly contradicted and net-negative -> out of the index.
    if contradicted >= DEMOTE_CONTRA and contradicted > helpful:
        meta["status"] = "demoted-contradicted"
        write_note(REJECTED / path.name, meta, body)
        path.unlink()
        return "demoted"

    write_note(path, meta, body)

    # Promote suggestion: a Layer-B rule that keeps helping earns a Layer-A review.
    if meta.get("layer", "B").upper() == "B" and helpful >= PROMOTE_HELPFUL:
        pid = f"promoted-{path.stem}"
        ppath = PENDING / f"{pid}.md"
        if not ppath.exists():
            pmeta = dict(meta)
            pmeta["id"] = pid
            pmeta["layer"] = "A"
            pmeta["status"] = "pending-approval"
            pmeta["origin"] = f"promoted-from-B:{path.stem}"
            write_note(ppath, pmeta, body)
            return "helpful+promote-suggested"
    return verdict


def run(transcript: Path, session: str) -> dict:
    ids = recalled_ids(session)
    if not ids:
        log.info("No recalled rules logged for this session; nothing to score.")
        return {}
    present = {}
    for rid in ids:
        f = RULES / f"{rid}.md"
        if f.exists():
            meta, body = read_note(f)
            present[rid] = (f, meta, body)
    if not present:
        log.info("Recalled rules no longer in vault; skipping.")
        return {}

    convo = extract_conversation(transcript)
    verdicts = judge(convo, {rid: v[2] for rid, v in present.items()})
    if not verdicts:
        log.info("Judge returned nothing; leaving rules unchanged.")
        return {}

    now = datetime.now(timezone.utc).isoformat()
    tally: dict[str, int] = {}
    for rid, (f, meta, body) in present.items():
        vobj = verdicts.get(rid, {"verdict": "ignored", "correction": None})
        outcome = apply_verdict(f, meta, body, vobj, session, now)
        tally[outcome] = tally.get(outcome, 0) + 1
        log.info("  %s: %s", rid, outcome)
    log.info("Feedback summary: %s", tally)
    return tally


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        transcript = Path(args[0])
        session = transcript.stem
    else:
        payload = json.loads(sys.stdin.read())
        transcript = Path(payload.get("transcript_path", ""))
        session = payload.get("session_id", transcript.stem)
    if not transcript.exists():
        log.error("Transcript not found: %s", transcript)
        sys.exit(1)
    run(transcript, session)
