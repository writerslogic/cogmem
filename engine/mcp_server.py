"""
cogmem MCP server — exposes the memory system to any MCP client over stdio.

Speaks newline-delimited JSON-RPC 2.0 (the MCP stdio transport) and implements the
`tools` and `resources` capabilities:

  tools      recall, note, status, verify, receipt, tree_head, progress, review_pending
  resources  the evolving user model and each project's live state, read-only

Provenance operations call the engine directly for structured results; recall and the
CLI-shaped stages run as subprocesses so the warm daemon and tested code paths are
reused. Standard library only.

Run:  cogmem mcp        (or:  python engine/mcp_server.py)
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common                       # noqa: E402
import provenance as pv             # noqa: E402

ENGINE = Path(__file__).resolve().parent
VAULT = common.VAULT
PY = sys.executable
SERVER = {"name": "cogmem", "version": "2.4"}
DEFAULT_PROTOCOL = "2024-11-05"


# --- engine bridges -------------------------------------------------------------

def _engine(script: str, *args: str, parse_json: bool = False, timeout: int = 30):
    out = subprocess.run([PY, str(ENGINE / script), *args],
                         capture_output=True, text=True, timeout=timeout)
    if parse_json:
        text = out.stdout.strip()
        try:
            return json.loads(text) if text else []
        except json.JSONDecodeError:
            return []
    return (out.stdout + out.stderr).strip() or "(no output)"


# --- tools ----------------------------------------------------------------------

def _tool_recall(a: dict) -> dict:
    query = (a.get("query") or "").strip()
    if not query:
        raise ValueError("query is required")
    args = [query, "--k", str(int(a.get("k", 5)))]
    if a.get("scope"):
        args += ["--scope", str(a["scope"])]
    results = _engine("recall.py", *args, parse_json=True)
    return {"count": len(results), "memories": results}


def _tool_note(a: dict) -> dict:
    text = (a.get("text") or "").strip()
    if not text:
        raise ValueError("text is required")
    _engine("note.py", text)
    return {"ok": True, "noted": text}


def _tool_status(a: dict) -> dict:
    log = pv.verify_log()
    return {"agentDid": pv.agent_did(),
            "logEntries": log.get("entries", 0),
            "logIntegrity": "ok" if log["ok"] else log.get("reason", "broken"),
            "merkleRoot": pv.signed_tree_head()["rootHash"]}


def _tool_verify(a: dict) -> dict:
    return pv.verify_vault()


def _tool_receipt(a: dict) -> dict:
    mid = (a.get("memory_id") or "").strip()
    if not mid:
        raise ValueError("memory_id is required")
    receipt = pv.inclusion_receipt(mid)
    if receipt is None:
        raise ValueError(f"no log entry for memory '{mid}'")
    return receipt


def _tool_tree_head(a: dict) -> dict:
    return pv.signed_tree_head()


def _tool_progress(a: dict) -> dict:
    return {"narrative": _engine("narrative.py")}


def _tool_review_pending(a: dict) -> dict:
    return {"pending": _engine("review.py", "list")}


DISPATCH = {
    "recall": _tool_recall, "note": _tool_note, "status": _tool_status,
    "verify": _tool_verify, "receipt": _tool_receipt, "tree_head": _tool_tree_head,
    "progress": _tool_progress, "review_pending": _tool_review_pending,
}

_OBJ = {"type": "object", "properties": {}}
TOOLS = [
    {"name": "recall", "description": "Surface relevant past memories for a query (ranked, with scores).",
     "inputSchema": {"type": "object",
                     "properties": {"query": {"type": "string"},
                                    "k": {"type": "integer", "default": 5},
                                    "scope": {"type": "string", "description": "optional language/scope filter"}},
                     "required": ["query"]}},
    {"name": "note", "description": "Record a decision or finding into memory mid-task.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "status", "description": "Agent DID, transparency-log integrity, and current Merkle root.",
     "inputSchema": _OBJ},
    {"name": "verify", "description": "Verify every memory's credential and the transparency-log chain.",
     "inputSchema": _OBJ},
    {"name": "receipt", "description": "RFC 6962 inclusion receipt proving a memory is committed in the signed log.",
     "inputSchema": {"type": "object", "properties": {"memory_id": {"type": "string"}}, "required": ["memory_id"]}},
    {"name": "tree_head", "description": "Current signed Merkle tree head (the log's signed commitment).",
     "inputSchema": _OBJ},
    {"name": "progress", "description": "Cross-project progress narrative: momentum, stalls, dependencies.",
     "inputSchema": _OBJ},
    {"name": "review_pending", "description": "List always-load rules awaiting human approval.",
     "inputSchema": _OBJ},
]


# --- resources ------------------------------------------------------------------

def _list_resources() -> list:
    res = [{"uri": "cogmem://user-model", "name": "User model",
            "mimeType": "text/markdown",
            "description": "cogmem's evolving model of the user"}]
    pdir = VAULT / "projects"
    if pdir.exists():
        for f in sorted(pdir.glob("*.md")):
            res.append({"uri": f"cogmem://project/{f.stem}",
                        "name": f"Project: {f.stem}", "mimeType": "text/markdown",
                        "description": f"Live project-state for {f.stem}"})
    return res


def _read_resource(uri: str) -> dict:
    if uri == "cogmem://user-model":
        path = VAULT / "user-model.md"
    elif uri.startswith("cogmem://project/"):
        name = uri.split("cogmem://project/", 1)[1]
        if "/" in name or ".." in name:
            raise ValueError("invalid resource uri")
        path = VAULT / "projects" / f"{name}.md"
    else:
        raise ValueError(f"unknown resource: {uri}")
    if not path.exists():
        raise ValueError(f"resource not found: {uri}")
    return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": path.read_text()}]}


# --- JSON-RPC -------------------------------------------------------------------

def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _handle(req):
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
        rid = req.get("id") if isinstance(req, dict) else None
        return _error(rid, -32600, "invalid request")
    method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        return _result(rid, {"protocolVersion": params.get("protocolVersion", DEFAULT_PROTOCOL),
                             "capabilities": {"tools": {}, "resources": {}},
                             "serverInfo": SERVER})
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "tools/call":
        fn = DISPATCH.get(params.get("name"))
        if fn is None:
            return _error(rid, -32602, f"unknown tool: {params.get('name')}")
        try:
            data = fn(params.get("arguments") or {})
            return _result(rid, {"content": [{"type": "text", "text": json.dumps(data, indent=2)}]})
        except Exception as exc:                               # noqa: BLE001 — tool boundary
            return _result(rid, {"content": [{"type": "text", "text": f"error: {exc}"}],
                                 "isError": True})
    if method == "resources/list":
        return _result(rid, {"resources": _list_resources()})
    if method == "resources/read":
        try:
            return _result(rid, _read_resource(params.get("uri", "")))
        except Exception as exc:                               # noqa: BLE001 — request boundary
            return _error(rid, -32602, str(exc))
    if method and method.startswith("notifications/"):
        return None
    if rid is not None:
        return _error(rid, -32601, f"method not found: {method}")
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        if isinstance(msg, list):                              # JSON-RPC batch
            out = [r for r in (_handle(m) for m in msg) if r is not None]
            if out:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()
            continue
        resp = _handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
