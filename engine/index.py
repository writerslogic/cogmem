"""
Cognitive Memory — Layer B Index Builder (cold path)

Bootstrap / manual rebuild of the local semantic index from vault/rules. The hot
path reindexes through the warm daemon; this exists for first build and repair.
Updates are incremental (only changed rules are re-embedded). The index is a
derived cache, safe to delete and rebuild.

Usage:
  python index.py          # incremental update from vault/rules
  python index.py --rebuild  # drop and rebuild from scratch
  python index.py --stats
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import indexstore

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.index")

EMBED_MODEL = "BAAI/bge-small-en-v1.5"


def build(rebuild: bool = False) -> dict:
    from fastembed import TextEmbedding

    conn = indexstore.connect()
    if rebuild:
        conn.execute("DELETE FROM rules")
        conn.commit()
    model = TextEmbedding(EMBED_MODEL)
    result = indexstore.incremental_update(conn, model)
    conn.close()
    log.info("Index update: %s", result)
    return result


def stats() -> None:
    if not indexstore.INDEX_DB.exists():
        log.info("No index yet.")
        return
    conn = indexstore.connect()
    rows = conn.execute("SELECT id, scope FROM rules").fetchall()
    conn.close()
    log.info("Index holds %d rule(s):", len(rows))
    for rid, scope in rows:
        log.info("  [%s] %s", scope, rid)


if __name__ == "__main__":
    if "--stats" in sys.argv:
        stats()
    else:
        build(rebuild="--rebuild" in sys.argv)
