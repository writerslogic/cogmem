"""
Cognitive Memory — Recall Daemon

Holds the embedding model and the Layer-B index warm in memory and answers
top-k recall queries over a unix socket in milliseconds, so the per-prompt hook
never pays the model-load cost. Also owns incremental reindexing: the capture
pipeline sends {"cmd":"reindex"} and the warm model embeds only changed rules.

Protocol (one JSON line in, one JSON line out):
  {"query": str, "k": int}      -> [{id, scope, score, text}, ...]
  {"cmd": "reindex"}            -> {"ok": true, "added_or_updated": n, ...}
  {"cmd": "ping"}               -> {"ok": true}

Usage:
  python daemon.py            # foreground (launchd runs it this way)
"""

import json
import logging
import socket
import threading

import numpy as np

from cogmem import config, indexstore
from cogmem.common import SOCK_PATH

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("cogmem.daemon")

EMBED_MODEL = config.embed_model()
RERANK_MODEL = config.rerank_model()
COSINE_PREFILTER = 12  # rerank the top-N cosine candidates
WEIGHT_NUDGE = 0.4  # how much feedback weight tips the rerank ordering


class Recall:
    def __init__(self) -> None:
        from fastembed import TextEmbedding
        from fastembed.rerank.cross_encoder import TextCrossEncoder

        self.model = TextEmbedding(EMBED_MODEL)
        self.reranker = TextCrossEncoder(RERANK_MODEL)
        self._lock = threading.Lock()
        self._mtime = 0.0
        self.ids: list[str] = []
        self.scopes: list[str] = []
        self.texts: list[str] = []
        self.weights: list[float] = []
        self.matrix = np.zeros((0, indexstore.EMBED_DIM), dtype="float32")
        self.reload()

    def reload(self) -> None:
        if not indexstore.INDEX_DB.exists():
            return
        mtime = indexstore.INDEX_DB.stat().st_mtime
        if mtime == self._mtime:
            return
        conn = indexstore.connect()
        ids, scopes, texts, weights, matrix = indexstore.load_matrix(conn)
        conn.close()
        with self._lock:
            self.ids, self.scopes, self.texts = ids, scopes, texts
            self.weights, self.matrix = weights, matrix
            self._mtime = mtime
        log.info("Loaded %d rule(s) from index.", len(ids))

    def reindex(self) -> dict:
        conn = indexstore.connect()
        result = indexstore.incremental_update(conn, self.model)
        conn.close()
        self._mtime = 0.0
        self.reload()
        return result

    def query(self, text: str, k: int = 3) -> list[dict]:
        self.reload()
        with self._lock:
            if not self.ids:
                return []
            matrix, ids = self.matrix, self.ids
            scopes, texts, weights = self.scopes, self.texts, self.weights
        q = next(iter(self.model.embed([text]))).astype("float32")
        q /= np.linalg.norm(q) or 1.0
        norms = np.linalg.norm(matrix, axis=1)
        norms[norms == 0] = 1.0
        sims = (matrix @ q) / norms

        # Cosine is the relevance gate (recall.py applies the floor on `score`);
        # the cross-encoder reorders the survivors, nudged by feedback weight.
        cand = np.argsort(-sims)[:COSINE_PREFILTER]
        rr = list(self.reranker.rerank(text, [texts[i] for i in cand]))
        ranked = sorted(
            zip(cand, rr),
            key=lambda t: t[1] + WEIGHT_NUDGE * float(weights[t[0]]),
            reverse=True,
        )[:k]
        return [
            {
                "id": ids[i],
                "scope": scopes[i],
                "score": round(float(sims[i]), 3),
                "rerank": round(float(r), 3),
                "weight": weights[i],
                "text": texts[i],
            }
            for i, r in ranked
        ]


MAX_MSG = 1 << 20  # 1 MiB ceiling on a single request, so a client that never sends
# a newline can't grow the buffer without bound.


def _recv_line(conn: socket.socket) -> str:
    buf = b""
    while b"\n" not in buf and len(buf) < MAX_MSG:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").strip()


def serve() -> None:
    if SOCK_PATH.exists():
        SOCK_PATH.unlink()
    recall = Recall()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(SOCK_PATH))
    srv.listen(8)
    log.info("Recall daemon listening on %s", SOCK_PATH.name)
    while True:
        conn, _ = srv.accept()
        try:
            line = _recv_line(conn)
            req = json.loads(line) if line else {}
            cmd = req.get("cmd")
            if cmd == "ping":
                conn.sendall(b'{"ok":true}\n')
            elif cmd == "reindex":
                result = recall.reindex()
                conn.sendall((json.dumps({"ok": True, **result}) + "\n").encode())
            else:
                results = recall.query(req.get("query", ""), int(req.get("k", 3)))
                conn.sendall((json.dumps(results) + "\n").encode())
        except Exception as e:  # noqa: BLE001 — one bad request must not kill the daemon
            log.warning("request error: %s", e)
            try:
                conn.sendall(b"[]\n")
            except OSError:
                pass
        finally:
            conn.close()


if __name__ == "__main__":
    serve()
