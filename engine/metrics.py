"""
Cognitive Memory — Metrics / Observability

The original cogmem failed silently (utility frozen, nobody could see it). This
surfaces the health signals that matter so drift is visible: rule population and
status, the always-loaded budget, feedback outcomes, recall activity, and the
freshness of capture. Read-only; computed on demand from the vault and logs.

Usage:  python metrics.py
"""

import json
import logging
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VAULT, read_note

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cogmem.metrics")

LEARNED = VAULT / "learned"
RECALL_LOG = VAULT / ".recall-log.jsonl"
CAPTURE_LOG = VAULT.parent / "capture.log"
LAYER_A_TOKEN_CAP = 2000  # informational: total always-loaded rules across all scopes
PER_SCOPE_CAP = 900  # enforced: a single scope file (what actually loads with universal)


def scope_tokens(path) -> int:
    """Approx token cost of the bullet rules in one learned file."""
    if not path.exists():
        return 0
    chars = sum(len(l) for l in path.read_text(errors="replace").splitlines() if l.startswith("- "))
    return chars // 4


def _count(p: Path) -> int:
    return len(list(p.glob("*.md"))) if p.exists() else 0


def rule_feedback() -> dict:
    helpful = contradicted = recalled = 0
    top = []
    for f in (VAULT / "rules").glob("*.md"):
        meta, _ = read_note(f)
        h, c, r = (
            int(meta.get("helpful", 0)),
            int(meta.get("contradicted", 0)),
            int(meta.get("recalled", 0)),
        )
        helpful += h
        contradicted += c
        recalled += r
        if r:
            top.append((r, h, c, meta.get("id", f.stem)))
    top.sort(reverse=True)
    return {"helpful": helpful, "contradicted": contradicted, "recalled": recalled, "top": top[:5]}


def layer_a_budget() -> dict:
    chars = 0
    rules = 0
    for f in LEARNED.glob("*.md") if LEARNED.exists() else []:
        for line in f.read_text(errors="replace").splitlines():
            if line.startswith("- "):
                rules += 1
                chars += len(line)
    return {"rules": rules, "tokens_est": chars // 4, "cap": LAYER_A_TOKEN_CAP}


def recall_activity() -> dict:
    if not RECALL_LOG.exists():
        return {"injections": 0, "sessions": 0, "rules_surfaced": 0}
    sessions, rules = set(), set()
    n = 0
    for line in RECALL_LOG.read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        n += 1
        sessions.add(e.get("session"))
        rules.update(e.get("ids", []))
    return {"injections": n, "sessions": len(sessions), "rules_surfaced": len(rules)}


def rejected_breakdown() -> Counter:
    c = Counter()
    rej = VAULT / "rejected"
    for f in rej.glob("*.md") if rej.exists() else []:
        meta, _ = read_note(f)
        c[meta.get("status", "rejected")] += 1
    return c


def last_capture() -> str:
    if not CAPTURE_LOG.exists():
        return "never"
    for line in reversed(CAPTURE_LOG.read_text(errors="replace").splitlines()):
        if line.startswith("--- ") and "capture:" in line:
            return line.strip("- ").split(" capture:")[0]
    return "unknown"


def report() -> None:
    fb = rule_feedback()
    budget = layer_a_budget()
    recall = recall_activity()
    rej = rejected_breakdown()

    log.info("=== cogmem metrics ===")
    log.info("Rules (Layer-B active):   %d", _count(VAULT / "rules"))
    log.info("Pending approval:         %d", _count(VAULT / "pending"))
    log.info("Promoted (Layer-A src):   %d", _count(VAULT / "promoted"))
    log.info("Episodes:                 %d", _count(VAULT / "episodes"))
    log.info("")
    log.info(
        "Layer-A budget:           %d rules, ~%d tok / %d cap%s",
        budget["rules"],
        budget["tokens_est"],
        budget["cap"],
        "  !! OVER" if budget["tokens_est"] > budget["cap"] else "",
    )
    log.info("")
    log.info(
        "Feedback:                 %d recalled, %d helpful, %d contradicted",
        fb["recalled"],
        fb["helpful"],
        fb["contradicted"],
    )
    if rej:
        log.info("Retired:                  %s", dict(rej))
    log.info("")
    log.info(
        "Recall activity:          %d injections, %d sessions, %d distinct rules",
        recall["injections"],
        recall["sessions"],
        recall["rules_surfaced"],
    )
    failures = list((VAULT / "failures").glob("*.md")) if (VAULT / "failures").exists() else []
    recurring = sum(1 for f in failures if int(read_note(f)[0].get("count", 1)) > 1)
    guards = sum(1 for f in failures if read_note(f)[0].get("tripwire"))
    log.info(
        "Self-model:               %d failure modes (%d recurring, %d armed guards)",
        len(failures),
        recurring,
        guards,
    )
    um = VAULT / "user-model.md"
    log.info("User model:               %s", "present" if um.exists() else "not yet synthesized")
    projects = list((VAULT / "projects").glob("*.md")) if (VAULT / "projects").exists() else []
    notes_log = VAULT / ".notes.jsonl"
    n_notes = len(notes_log.read_text(errors="replace").splitlines()) if notes_log.exists() else 0
    log.info(
        "Project states:           %d (%s)",
        len(projects),
        ", ".join(p.stem for p in projects) or "none",
    )
    log.info("In-loop notes recorded:   %d", n_notes)
    import config

    cfg = config.load()
    log.info(
        "Recall thresholds:        floor=%.2f gap=%.1f", cfg["recall_floor"], cfg["recall_gap"]
    )
    log.info("Last capture:             %s", last_capture())
    if fb["top"]:
        log.info("")
        log.info("Most-recalled rules:")
        for r, h, c, rid in fb["top"]:
            log.info("  recalled=%d helpful=%d contra=%d  %s", r, h, c, rid)


def _daemon_status() -> str:
    sock = Path(__file__).resolve().parent / "recall.sock"
    if not sock.exists():
        return "cold (lazy-spawns on next prompt)"
    try:
        import socket as _socket

        c = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        c.settimeout(1.0)
        c.connect(str(sock))
        c.sendall(b'{"cmd":"ping"}\n')
        ok = b"ok" in c.recv(256)
        c.close()
        return "warm" if ok else "socket present but not responding"
    except OSError:
        return "socket present but unreachable"


def doctor() -> None:
    """End-to-end health of the learning loop: every link that can silently break
    (daemon, API key, trust anchor, capture freshness, backlog) in one view."""
    import os

    log.info("=== cogmem doctor ===")
    log.info("Recall daemon:        %s", _daemon_status())
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    log.info(
        "ANTHROPIC_API_KEY:    %s",
        "present" if has_key else "MISSING — capture/feedback/consolidation will no-op",
    )
    try:
        import provenance as pv

        td = pv.trusted_did()
        log.info(
            "Trust anchor:         %s",
            (td[:28] + "…") if td else "NOT established — run `cogmem status` once",
        )
        log.info("Key custody:          %s", pv.key_custody())
        if td and pv.agent_did() != td:
            log.info(
                "  WARNING: current key DID does not match the anchor — "
                "run `cogmem trust --rotate` if the key change was intentional"
            )
    except Exception as e:  # noqa: BLE001 — doctor must never crash
        log.info("Trust anchor:         unavailable (%s)", e)
    log.info("Last capture:         %s", last_capture())
    log.info("Pending candidates:   %d", _count(VAULT / "candidates"))
    log.info("Awaiting approval:    %d", _count(VAULT / "pending"))
    ra = recall_activity()
    fb = rule_feedback()
    log.info("Active rules:         %d", _count(VAULT / "rules"))
    log.info("Recall injections:    %d across %d session(s)", ra["injections"], ra["sessions"])
    log.info(
        "Feedback:             %d recalled, %d helpful, %d contradicted",
        fb["recalled"],
        fb["helpful"],
        fb["contradicted"],
    )
    import config

    log.info("Provenance enforce:   %s", "on" if config.load().get("provenance_enforce") else "off")


if __name__ == "__main__":
    if "doctor" in sys.argv[1:]:
        doctor()
    else:
        report()
