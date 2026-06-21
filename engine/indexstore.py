"""
Cognitive Memory — shared index store (SQLite + embeddings)

One place for the derived Layer-B index so both the cold bootstrap (index.py) and
the warm daemon (daemon.py) share identical schema and update logic. The index is
a cache built from vault/rules markdown; deleting it loses nothing.

Updates are incremental: only rules whose body changed (by content hash) are
re-embedded, so a per-session reindex embeds one new rule, not the whole vault.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

import numpy as np

ENGINE = Path(__file__).resolve().parent
INDEX_DB = ENGINE / "index.db"
RULES = ENGINE.parent / "vault" / "rules"
EMBED_DIM = 384


def _body_hash(body: str) -> str:
    return hashlib.sha1(body.encode("utf-8")).hexdigest()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(INDEX_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rules "
        "(id TEXT PRIMARY KEY, scope TEXT, text TEXT, hash TEXT, weight REAL, embedding BLOB)"
    )
    return conn


def current_rules() -> list[tuple[str, str, str, str, float]]:
    """(id, scope, body, hash, weight) for every active Layer-B rule on disk.
    weight = helpful - contradicted, the feedback signal used to nudge ranking."""
    # Local import to keep this module importable without the markdown helpers.
    import sys
    sys.path.insert(0, str(ENGINE))
    from common import read_note

    # Poison-resistance gate (opt-in): when enforcing, a rule whose verifiable
    # credential is missing or tampered is excluded from the recall index.
    pv = None
    try:
        import config
        if config.load().get("provenance_enforce", False):
            import provenance as pv
    except Exception:  # noqa: BLE001 — provenance is optional; never block indexing
        pv = None

    out = []
    for f in sorted(RULES.glob("*.md")):
        meta, body = read_note(f)
        if not body:
            continue
        if pv is not None and not _provenance_ok(pv, meta, body, f):
            continue
        weight = float(int(meta.get("helpful", 0)) - int(meta.get("contradicted", 0)))
        out.append((meta.get("id", f.stem), meta.get("scope", "universal"),
                    body, _body_hash(body), weight))
    return out


def _provenance_ok(pv, meta: dict, body: str, f) -> bool:
    cpath = pv.CREDENTIALS / f"{meta.get('id', f.stem)}.jsonld"
    if not cpath.exists():
        return False
    try:
        vc = json.loads(cpath.read_text())
        return pv.verify_credential(vc) and vc["credentialSubject"]["statement"] == body
    except (json.JSONDecodeError, KeyError):
        return False


def incremental_update(conn: sqlite3.Connection, model) -> dict:
    """Embed only new/changed rules; refresh scope/weight on unchanged ones (cheap,
    no re-embed) so feedback weight stays current; drop removed ones. `model` is a
    fastembed TextEmbedding. Returns counts for logging."""
    existing = {row[0]: row[1] for row in conn.execute("SELECT id, hash FROM rules")}
    current = current_rules()
    current_ids = {r[0] for r in current}

    to_embed = [(rid, scope, body, h, w) for rid, scope, body, h, w in current
                if existing.get(rid) != h]
    unchanged = [(rid, scope, body, h, w) for rid, scope, body, h, w in current
                 if existing.get(rid) == h]
    removed = [rid for rid in existing if rid not in current_ids]

    if to_embed:
        vectors = list(model.embed([r[2] for r in to_embed]))
        for (rid, scope, body, h, w), vec in zip(to_embed, vectors):
            conn.execute(
                "INSERT OR REPLACE INTO rules VALUES (?,?,?,?,?,?)",
                (rid, scope, body, h, w, vec.astype("float32").tobytes()),
            )
    for rid, scope, body, h, w in unchanged:
        conn.execute("UPDATE rules SET scope=?, text=?, weight=? WHERE id=?",
                     (scope, body, w, rid))
    for rid in removed:
        conn.execute("DELETE FROM rules WHERE id = ?", (rid,))
    conn.commit()
    return {"added_or_updated": len(to_embed), "removed": len(removed),
            "total": len(current)}


def load_matrix(conn: sqlite3.Connection) -> tuple[list, list, list, list, np.ndarray]:
    """(ids, scopes, texts, weights, matrix) for serving recall queries."""
    rows = conn.execute("SELECT id, scope, text, weight, embedding FROM rules").fetchall()
    ids, scopes, texts, weights, vecs = [], [], [], [], []
    for rid, scope, text, weight, blob in rows:
        ids.append(rid)
        scopes.append(scope)
        texts.append(text)
        weights.append(weight or 0.0)
        vecs.append(np.frombuffer(blob, dtype="float32"))
    matrix = np.vstack(vecs) if vecs else np.zeros((0, EMBED_DIM), dtype="float32")
    return ids, scopes, texts, weights, matrix
