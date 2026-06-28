"""
Cognitive Memory — Recall Client

Thin, fail-open client for the recall daemon. Queries top-k Layer-B rules for a
prompt and prints them. Designed to be called from the UserPromptSubmit hook, so
it must be fast and must never block: a short socket timeout, and on any failure
it exits non-zero with no output (the hook then lazy-spawns the daemon and injects
nothing that turn).

Usage:
  python recall.py "<prompt text>" [--scope rust] [--k 3]
"""

import json
import socket
import sys
from pathlib import Path

SOCK_PATH = Path(__file__).resolve().parent / "recall.sock"
TIMEOUT = 1.0
MAX_MSG = 1 << 20   # 1 MiB ceiling on the daemon response


def filter_results(results: list[dict], min_score: float, gap: float) -> list[dict]:
    """Cosine floor gates relevance; then drop anything the reranker scores far
    below the best survivor (relative gate, robust to the cross-encoder's scale)."""
    kept = [r for r in results if r.get("score", 0) >= min_score]
    if kept:
        top_rr = max(r.get("rerank", 0.0) for r in kept)
        kept = [r for r in kept if top_rr - r.get("rerank", 0.0) <= gap]
    return kept


def recall(query: str, k: int, scope: str | None) -> list[dict]:
    if not SOCK_PATH.exists():
        raise FileNotFoundError("daemon socket absent")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect(str(SOCK_PATH))
    s.sendall((json.dumps({"query": query, "k": k, "scope": scope}) + "\n").encode())
    buf = b""
    while b"\n" not in buf and len(buf) < MAX_MSG:
        chunk = s.recv(8192)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode(errors="replace").strip() or "[]")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        sys.exit(2)
    query = args[0]
    scope = args[args.index("--scope") + 1] if "--scope" in args else None
    k = int(args[args.index("--k") + 1]) if "--k" in args else 3
    import config
    cfg = config.load()
    min_score = float(args[args.index("--min-score") + 1]) if "--min-score" in args else cfg["recall_floor"]
    gap = float(args[args.index("--gap") + 1]) if "--gap" in args else cfg["recall_gap"]
    try:
        results = recall(query, k, scope)
    except Exception:  # noqa: BLE001 — fail open: hook must not break on recall errors
        sys.exit(1)
    results = filter_results(results, min_score, gap)
    if not results:
        sys.exit(0)
    sys.stdout.write(json.dumps(results))
