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

_NOARG = {"type": "object", "properties": {}, "additionalProperties": False}
# Honest annotations: every tool is local-first (no network/filesystem outside the
# vault), so openWorldHint is always false. Read tools are idempotent reads.
_RO = {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False}

TOOLS = [
    {"name": "recall",
     "title": "Recall Memories",
     "description": (
         "Surface the most relevant past lessons, decisions, and rules for a task, "
         "ranked by semantic similarity.\n"
         "Returns {count, memories:[{id, scope, score, text}]}, where score is rerank "
         "confidence (higher = more relevant).\n"
         "Use at the start of a task or whenever unsure how the user wants something "
         "done, instead of guessing. Read-only — to save a new memory use `note`."),
     "inputSchema": {"type": "object",
                     "properties": {
                         "query": {"type": "string",
                                   "description": "Natural-language description of the task or question to find lessons for, e.g. 'how does the user want commit messages formatted'."},
                         "k": {"type": "integer", "default": 5, "minimum": 1, "maximum": 20,
                               "description": "Maximum number of memories to return (1-20). Defaults to 5."},
                         "scope": {"type": "string",
                                   "description": "Optional domain filter, e.g. 'rust', 'python', 'universal'. Omit to search every scope."}},
                     "required": ["query"], "additionalProperties": False},
     "outputSchema": {"type": "object",
                      "properties": {"count": {"type": "integer"},
                                     "memories": {"type": "array", "items": {
                                         "type": "object",
                                         "properties": {"id": {"type": "string"}, "scope": {"type": "string"},
                                                        "score": {"type": "number"}, "text": {"type": "string"}}}}},
                      "required": ["count", "memories"]},
     "annotations": _RO},

    {"name": "note",
     "title": "Note a Memory",
     "description": (
         "Record a decision, finding, or correction into memory mid-task so it can be "
         "recalled in future sessions.\n"
         "Returns {ok, noted}. The text is captured as a candidate and deduped against "
         "existing knowledge by the background pipeline.\n"
         "Use when the user states a durable preference or you learn something worth "
         "keeping; not for transient chatter. To retrieve memories use `recall`."),
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string",
                                             "description": "The lesson to remember, as one self-contained sentence, e.g. 'The user prefers Conventional Commits with no body.'"}},
                     "required": ["text"], "additionalProperties": False},
     "outputSchema": {"type": "object",
                      "properties": {"ok": {"type": "boolean"}, "noted": {"type": "string"}},
                      "required": ["ok"]},
     "annotations": {"readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": False, "openWorldHint": False}},

    {"name": "status",
     "title": "Memory System Status",
     "description": (
         "Report the health of the verifiable-memory system.\n"
         "Returns {agentDid, logEntries, logIntegrity, merkleRoot} — the agent's "
         "did:key identity, transparency-log size, its integrity ('ok' or a reason), "
         "and the current Merkle root.\n"
         "Use for a fast health/identity check. For a full per-memory credential audit "
         "use `verify`; for the signed log commitment use `tree_head`."),
     "inputSchema": _NOARG,
     "outputSchema": {"type": "object",
                      "properties": {"agentDid": {"type": "string"}, "logEntries": {"type": "integer"},
                                     "logIntegrity": {"type": "string"}, "merkleRoot": {"type": "string"}},
                      "required": ["agentDid", "logIntegrity", "merkleRoot"]},
     "annotations": _RO},

    {"name": "verify",
     "title": "Verify All Memories",
     "description": (
         "Cryptographically verify every stored memory's W3C Verifiable Credential and "
         "the integrity of the hash-chained transparency log.\n"
         "Returns a summary of memories checked, how many are valid, and any failure "
         "reasons.\n"
         "Use to detect tampered or poisoned memories before trusting them. This is the "
         "deep audit; `status` is the lightweight check."),
     "inputSchema": _NOARG,
     "outputSchema": {"type": "object", "additionalProperties": True},
     "annotations": _RO},

    {"name": "receipt",
     "title": "Memory Inclusion Receipt",
     "description": (
         "Produce an RFC 6962-style cryptographic proof that a specific memory is "
         "committed in the signed transparency log.\n"
         "Returns the inclusion receipt (leaf index, audit path, tree size, signed root).\n"
         "Use to prove to a third party that a memory existed and was logged. Requires "
         "the memory's id — get ids from `recall`."),
     "inputSchema": {"type": "object",
                     "properties": {"memory_id": {"type": "string",
                                                  "description": "The id of the memory to prove inclusion for, as returned in a recall result's `id` field."}},
                     "required": ["memory_id"], "additionalProperties": False},
     "outputSchema": {"type": "object", "additionalProperties": True},
     "annotations": _RO},

    {"name": "tree_head",
     "title": "Signed Tree Head",
     "description": (
         "Return the current signed Merkle tree head — the log's tamper-evident "
         "commitment to every memory so far.\n"
         "Returns {rootHash, treeSize, signature, ...}.\n"
         "Use as the anchor a verifier checks inclusion receipts against, or to detect "
         "log forks. Pair with `receipt`."),
     "inputSchema": _NOARG,
     "outputSchema": {"type": "object",
                      "properties": {"rootHash": {"type": "string"}, "treeSize": {"type": "integer"}},
                      "additionalProperties": True},
     "annotations": _RO},

    {"name": "progress",
     "title": "Cross-Project Progress",
     "description": (
         "Summarize momentum, stalls, and dependencies across the user's projects as a "
         "narrative.\n"
         "Returns {narrative}.\n"
         "Use to orient at session start or when the user asks 'where are we'. Read-only "
         "synthesis of project-state memory."),
     "inputSchema": _NOARG,
     "outputSchema": {"type": "object", "properties": {"narrative": {"type": "string"}},
                      "required": ["narrative"]},
     "annotations": _RO},

    {"name": "review_pending",
     "title": "List Pending Approvals",
     "description": (
         "List always-load (Layer-A) rules awaiting human approval before they enter the "
         "always-on context.\n"
         "Returns {pending}.\n"
         "Use to see what the system wants to promote. Approval itself is a human action "
         "via the `cogmem review` CLI, not this tool."),
     "inputSchema": _NOARG,
     "outputSchema": {"type": "object", "properties": {"pending": {"type": "string"}},
                      "required": ["pending"]},
     "annotations": _RO},
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
            return _result(rid, {"content": [{"type": "text", "text": json.dumps(data)}],
                                 "structuredContent": data})
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
