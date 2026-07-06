"""
Cognitive Memory — MCP server tests (stdlib unittest, no API/model needed)

Exercises the JSON-RPC dispatch surface end to end against a throwaway
COGMEM_HOME: the lifecycle methods (initialize/ping), tool and resource listing,
a real-crypto tool call (status), the error contracts (bad request, unknown
method, unknown tool, traversal-guarded resources), and batch handling. The
provenance-backed tools run real Ed25519/Merkle code; recall/note/narrative tools
shell out to the engine and inherit the temp home, so nothing here needs the API.

Run:  python test_mcp.py
"""

import os
import tempfile
import unittest
from pathlib import Path


# A throwaway home MUST be set before importing the server: common/provenance bind
# their vault paths from COGMEM_HOME at import time, and the test must never touch
# the real vault or identity key.
_TMP_HOME = tempfile.mkdtemp(prefix="cogmem-mcp-test-")
os.environ["COGMEM_HOME"] = _TMP_HOME

from cogmem import mcp_server  # noqa: E402


def tearDownModule():
    import shutil

    shutil.rmtree(_TMP_HOME, ignore_errors=True)


def call(method, params=None, rid=1):
    req = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        req["params"] = params
    return mcp_server._handle(req)


class TestLifecycle(unittest.TestCase):
    def test_initialize_echoes_protocol_and_server_info(self):
        r = call("initialize", {"protocolVersion": "2025-06-18"})
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(r["result"]["serverInfo"]["name"], "cogmem")
        self.assertIn("tools", r["result"]["capabilities"])

    def test_initialize_defaults_protocol_when_absent(self):
        r = call("initialize", {})
        self.assertEqual(r["result"]["protocolVersion"], mcp_server.DEFAULT_PROTOCOL)

    def test_ping(self):
        self.assertEqual(call("ping")["result"], {})


class TestListings(unittest.TestCase):
    def test_tools_list_matches_dispatch(self):
        tools = call("tools/list")["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(names, set(mcp_server.DISPATCH))
        for t in tools:
            self.assertIn("inputSchema", t)
            self.assertIn("description", t)

    def test_resources_list_includes_user_model(self):
        res = call("resources/list")["result"]["resources"]
        self.assertIn("cogmem://user-model", {r["uri"] for r in res})


class TestToolCalls(unittest.TestCase):
    def test_status_runs_real_crypto(self):
        r = call("tools/call", {"name": "status", "arguments": {}})
        data = r["result"]["structuredContent"]
        self.assertTrue(data["agentDid"].startswith("did:key:z"))
        self.assertEqual(data["logIntegrity"], "ok")
        self.assertTrue(len(data["merkleRoot"]) == 64)  # sha256 hex

    def test_note_persists_to_temp_vault(self):
        r = call("tools/call", {"name": "note", "arguments": {"text": "prefer tabs over spaces"}})
        self.assertTrue(r["result"]["structuredContent"]["ok"])
        notes = Path(_TMP_HOME) / "vault" / ".notes.jsonl"
        self.assertTrue(notes.exists())
        self.assertIn("prefer tabs over spaces", notes.read_text())

    def test_note_empty_text_is_tool_error(self):
        r = call("tools/call", {"name": "note", "arguments": {"text": "  "}})
        self.assertTrue(r["result"].get("isError"))

    def test_receipt_unknown_memory_is_tool_error(self):
        r = call("tools/call", {"name": "receipt", "arguments": {"memory_id": "nope-xyz"}})
        self.assertTrue(r["result"].get("isError"))


class TestErrorContracts(unittest.TestCase):
    def test_non_jsonrpc_request_rejected(self):
        r = mcp_server._handle({"id": 1, "method": "ping"})  # no jsonrpc field
        self.assertEqual(r["error"]["code"], -32600)

    def test_unknown_method(self):
        self.assertEqual(call("does/not/exist")["error"]["code"], -32601)

    def test_unknown_tool(self):
        r = call("tools/call", {"name": "frobnicate", "arguments": {}})
        self.assertEqual(r["error"]["code"], -32602)

    def test_notifications_return_none(self):
        self.assertIsNone(call("notifications/initialized", rid=None))

    def test_resource_read_unknown_uri_rejected(self):
        r = call("resources/read", {"uri": "cogmem://bogus"})
        self.assertEqual(r["error"]["code"], -32602)

    def test_resource_read_path_traversal_rejected(self):
        r = call("resources/read", {"uri": "cogmem://project/../../etc/passwd"})
        self.assertEqual(r["error"]["code"], -32602)


class TestBatch(unittest.TestCase):
    def test_batch_returns_array_of_responses(self):
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        out = [r for r in (mcp_server._handle(m) for m in batch) if r is not None]
        self.assertEqual(len(out), 2)
        self.assertEqual({r["id"] for r in out}, {1, 2})


if __name__ == "__main__":
    unittest.main(verbosity=2)
