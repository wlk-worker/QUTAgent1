"""MCP JSON-RPC client and solver-loop ``mcp`` action tests.

A local mock MCP server exercises the standard-library client over plain JSON
and SSE transports: initialize/session handling, tools/list, tools/call,
JSON-RPC errors, origin allowlist, redirect refusal, response truncation and the
deadline. The loop tests cover list_tools/call wiring, out-of-scope rejection and
unknown operations without any real MCP server or credentials.
"""
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.contract import Task
from agent.loop import run
from agent.mcp import MCPClient, parse_sse
from labs.common import cleanup_work, workspace_temp

MCP_FLAG = "flag{mock-mcp-flag}"


class MockMCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    lock = threading.Lock()
    hits = []
    session_id = "mock-session-1"

    def log_message(self, *args):
        pass

    def _json(self, status, data, headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def do_GET(self):  # noqa: N802
        self._json(405, {"error": "method not allowed"})

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        with type(self).lock:
            type(self).hits.append({"path": self.path, "method": payload.get("method"),
                                    "session": self.headers.get("Mcp-Session-Id"),
                                    "authorization": self.headers.get("Authorization"),
                                    "api_key": self.headers.get("X-Api-Key")})
        if self.path == "/slow":
            time.sleep(0.5)
            self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{type(self).other_port}/leak")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/error":
            self._json(500, {"jsonrpc": "2.0", "id": payload.get("id"),
                             "error": {"code": -32000, "message": "boom"}})
            return
        method = payload.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "mock-mcp", "version": "0.1"}}
            self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"), "result": result},
                       {"Mcp-Session-Id": type(self).session_id})
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "tools/list":
            if self.path == "/big":
                tools = [{"name": f"tool{index}", "description": "x" * 200}
                         for index in range(60)]
            else:
                tools = [
                    {"name": "echo", "description": "Echo the provided text",
                     "inputSchema": {"type": "object",
                                     "properties": {"text": {"type": "string"}}}},
                    {"name": "flag", "description": "Return the lab flag"},
                ]
            message = {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"tools": tools}}
            if self.path == "/sse":
                body = ("event: message\ndata: " + json.dumps(message) + "\n\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionAbortedError):
                    pass
                return
            self._json(200, message)
            return
        if method == "tools/call":
            params = payload.get("params") or {}
            name = params.get("name")
            if name == "echo":
                text = "echo: " + json.dumps(params.get("arguments") or {}, ensure_ascii=False)
                self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"),
                                 "result": {"content": [{"type": "text", "text": text}]}})
                return
            if name == "flag":
                self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"),
                                 "result": {"content": [{"type": "text", "text": MCP_FLAG}]}})
                return
            self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"),
                             "error": {"code": -32602, "message": "unknown tool"}})
            return
        self._json(200, {"jsonrpc": "2.0", "id": payload.get("id"),
                         "error": {"code": -32601, "message": "method not found"}})


def _start(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02},
                     daemon=True).start()
    return server


class MCPClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockMCPHandler.hits = []
        cls.other = _start(MockMCPHandler)
        MockMCPHandler.other_port = cls.other.server_port
        cls.server = _start(MockMCPHandler)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.other_origin = f"http://127.0.0.1:{cls.other.server_port}"
        MockMCPHandler.hits = []

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.other):
            server.shutdown()
            server.server_close()

    def _client(self, path="/mcp", **kwargs):
        return MCPClient(self.origin + path, allowed_origins=[self.origin], **kwargs)

    def test_initialize_list_tools_and_session_header(self):
        client = self._client()
        init = client.initialize()
        self.assertTrue(init["ok"])
        self.assertEqual(init["server"]["name"], "mock-mcp")
        self.assertTrue(init["session"])
        self.assertEqual(client.session_id, "mock-session-1")
        result = client.list_tools()
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        names = [tool["name"] for tool in result["tools"]]
        self.assertEqual(names, ["echo", "flag"])
        self.assertIn("input_schema", result["tools"][0])
        listed = [hit for hit in MockMCPHandler.hits if hit["method"] == "tools/list"]
        self.assertGreaterEqual(len(listed), 1)
        self.assertEqual(listed[-1]["session"], "mock-session-1")

    def test_allowlisted_auth_headers_are_sent(self):
        client = self._client(headers={"Authorization": "Bearer lab-token",
                                       "X-Api-Key": "lab-key"})
        result = client.list_tools()
        self.assertTrue(result["ok"])
        listed = [hit for hit in MockMCPHandler.hits if hit["method"] == "tools/list"]
        self.assertEqual(listed[-1]["authorization"], "Bearer lab-token")
        self.assertEqual(listed[-1]["api_key"], "lab-key")

    def test_dangerous_or_secret_headers_are_rejected(self):
        with self.assertRaises(ValueError):
            self._client(headers={"Host": "evil"})
        with self.assertRaises(ValueError):
            self._client(headers={"Authorization": "Bearer x\r\nInjected: 1"})
        with self.assertRaises(ValueError):
            self._client(headers={"Authorization": "sk-test-secret"},
                         environ={"LLM_API_KEY": "sk-test-secret"})

    def test_sse_transport_is_parsed(self):
        client = self._client("/sse")
        result = client.list_tools()
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)

    def test_call_tool_success_and_jsonrpc_error(self):
        client = self._client()
        echoed = client.call_tool("echo", {"text": "hi"})
        self.assertTrue(echoed["ok"])
        self.assertIn("hi", echoed["content"][0]["text"])
        flagged = client.call_tool("flag", {})
        self.assertTrue(flagged["ok"])
        self.assertIn(MCP_FLAG, flagged["content"][0]["text"])
        missing = client.call_tool("missing", {})
        self.assertEqual(missing["error"], "jsonrpc_error")
        self.assertEqual(missing["code"], -32602)
        self.assertNotIn("result", missing)

    def test_invalid_arguments_are_rejected_without_a_request(self):
        client = self._client()
        before = len(MockMCPHandler.hits)
        self.assertEqual(client.call_tool("echo", ["not", "a", "dict"])["error"],
                         "invalid_arguments")
        self.assertEqual(client.call_tool("", {})["error"], "invalid_tool_name")
        self.assertEqual(len(MockMCPHandler.hits), before)

    def test_origin_allowlist_is_enforced(self):
        before = len(MockMCPHandler.hits)
        with self.assertRaises(ValueError):
            MCPClient(self.other_origin + "/mcp", allowed_origins=[self.origin])
        with self.assertRaises(ValueError):
            MCPClient("ftp://127.0.0.1/mcp", allowed_origins=[self.origin])
        # The constructor refuses before any network call.
        self.assertEqual(len(MockMCPHandler.hits), before)

    def test_redirect_is_refused_and_not_followed(self):
        before = sum(1 for hit in MockMCPHandler.hits if hit["path"] == "/leak")
        client = self._client("/redirect")
        result = client.initialize()
        self.assertEqual(result["error"], "redirect_refused")
        self.assertEqual(result["phase"], "initialize")
        after = sum(1 for hit in MockMCPHandler.hits if hit["path"] == "/leak")
        self.assertEqual(before, after)

    def test_response_too_large_is_reported(self):
        client = MCPClient(self.origin + "/big", allowed_origins=[self.origin],
                           max_response_bytes=512)
        result = client.list_tools()
        self.assertEqual(result["error"], "response_too_large")

    def test_timeout_is_bounded(self):
        client = MCPClient(self.origin + "/slow", allowed_origins=[self.origin],
                           deadline=time.monotonic() + 0.15)
        start = time.monotonic()
        result = client.initialize()
        self.assertIn(result["error"], {"timeout", "deadline"})
        self.assertLess(time.monotonic() - start, 0.7)

    def test_http_error_body_is_surfaced(self):
        client = self._client("/error")
        result = client.initialize()
        self.assertEqual(result["error"], "jsonrpc_error")
        self.assertEqual(result["phase"], "initialize")
        self.assertEqual(result["detail"], "boom")


class SSEParserTests(unittest.TestCase):
    def test_parse_sse_extracts_json_messages_and_skips_comments(self):
        text = (": keep-alive\n"
                "event: message\n"
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n"
                "\n"
                "data: not-json\n"
                "\n")
        messages = parse_sse(text)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["id"], 1)
        self.assertEqual(parse_sse(""), [])


class _McpPlatform:
    def __init__(self, origin):
        self.origin = origin
        self.submissions = []

    def challenge(self, challenge_id):
        return {"id": challenge_id, "name": "AI assistant with MCP tools",
                "category": "ai", "questions": [{"id": "flag", "prompt": "find the flag"}]}

    def start_instance(self, challenge_id, competition_id):
        return "instance-1"

    def wait_instance(self, instance_id):
        return self.instance(instance_id)

    def instance(self, instance_id):
        return {"id": instance_id,
                "services": [{"service_type": "mcp", "url": self.origin}],
                "questions": [{"id": "flag", "prompt": "find the flag"}]}

    def submit(self, instance_id, question_id, answer):
        self.submissions.append((question_id, answer))
        correct = answer == MCP_FLAG
        return {"correct": correct, "challenge_fully_solved": correct}


class _McpModel:
    input_tokens = 7
    output_tokens = 3
    requests = 0

    def __init__(self, actions):
        self.actions = list(actions)
        self.systems = []

    def complete(self, system, messages, max_tokens=1200):
        self.requests += 1
        self.systems.append(system)
        if not self.actions:
            return json.dumps({"action": "finish", "reason": "script exhausted"})
        return json.dumps(self.actions.pop(0))


class LoopMcpActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockMCPHandler.hits = []
        cls.server = _start(MockMCPHandler)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        MockMCPHandler.hits = []

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.work = workspace_temp("test-mcp-loop-")
        MockMCPHandler.hits = []

    def tearDown(self):
        cleanup_work(self.work)

    def _run(self, model, platform, max_turns=6):
        task = Task(self.work, {"challenge": {"id": "C-1"}}, "", "C-1", "event",
                    "instance", False)
        return run(task, platform, model, max_turns=max_turns,
                   deadline=time.monotonic() + 15, on_update=lambda value: None)

    def _events(self):
        path = self.work / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def test_loop_lists_and_calls_mcp_tools_then_submits(self):
        origin = self.origin
        model = _McpModel([
            {"action": "mcp", "url": origin + "/mcp", "op": "list_tools",
             "headers": {"Authorization": "Bearer loop-token"},
             "why": "enumerate MCP tools with the provided auth header"},
            {"action": "mcp", "url": origin + "/mcp", "op": "call", "tool": "echo",
             "arguments": {"text": "probe"}, "why": "confirm tool call path"},
            {"action": "mcp", "url": origin + "/mcp", "op": "call", "tool": "flag",
             "arguments": {}, "why": "read the flag tool"},
            {"action": "submit", "question_id": "flag", "answer": MCP_FLAG,
             "evidence": "MCP tools/call flag returned it"},
        ])
        platform = _McpPlatform(origin)
        result = self._run(model, platform)
        self.assertEqual(result["category"], "ai")
        self.assertIn("## Playbook: AI / LLM application security", model.systems[0])
        self.assertEqual(result["mcp_calls"], 3)
        self.assertGreaterEqual(result["tool_calls_made"], 3)
        listed = [hit for hit in MockMCPHandler.hits if hit["method"] == "tools/list"]
        self.assertEqual(listed[-1]["authorization"], "Bearer loop-token")
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["stop_reason"], "done")
        self.assertEqual(platform.submissions, [("flag", MCP_FLAG)])
        observations = [entry["data"] for entry in self._events()
                        if entry["event"] == "observation"]
        self.assertTrue(any(item.get("count") == 2 for item in observations))
        self.assertTrue(any(MCP_FLAG in json.dumps(item) for item in observations))
        self.assertTrue(any(item.get("tool") == "echo" and item.get("ok") for item in observations))

    def test_out_of_scope_mcp_url_is_rejected_without_a_request(self):
        model = _McpModel([
            {"action": "mcp", "url": "http://127.0.0.1:9/mcp", "op": "list_tools",
             "why": "out of scope probe"},
            {"action": "finish", "reason": "scope rejected"},
        ])
        result = self._run(model, _McpPlatform(self.origin))
        self.assertEqual(result["mcp_calls"], 1)
        self.assertEqual(result["stop_reason"], "model_finished")
        observations = [entry["data"] for entry in self._events()
                        if entry["event"] == "observation"]
        self.assertTrue(any(item.get("error") == "mcp_url_rejected" for item in observations))
        self.assertEqual(MockMCPHandler.hits, [])

    def test_unknown_mcp_operation_is_an_error_observation(self):
        model = _McpModel([
            {"action": "mcp", "url": self.origin + "/mcp", "op": "delete_everything",
             "why": "invalid op"},
            {"action": "finish", "reason": "op rejected"},
        ])
        result = self._run(model, _McpPlatform(self.origin))
        self.assertEqual(result["mcp_calls"], 1)
        observations = [entry["data"] for entry in self._events()
                        if entry["event"] == "observation"]
        self.assertTrue(any(item.get("error") == "unknown_mcp_op" for item in observations))
        self.assertTrue(all(hit["method"] != "delete_everything" for hit in MockMCPHandler.hits))

    def test_mcp_requires_a_platform_scope(self):
        class NoScopePlatform(_McpPlatform):
            def instance(self, instance_id):
                return {"id": instance_id, "services": [],
                        "questions": [{"id": "flag", "prompt": "find it"}]}

        model = _McpModel([
            {"action": "mcp", "url": self.origin + "/mcp", "op": "list_tools", "why": "no scope"},
            {"action": "finish", "reason": "no scope"},
        ])
        result = self._run(model, NoScopePlatform(self.origin))
        observations = [entry["data"] for entry in self._events()
                        if entry["event"] == "observation"]
        self.assertTrue(any(item.get("error") == "http_scope_empty" for item in observations))
        self.assertEqual(MockMCPHandler.hits, [])


if __name__ == "__main__":
    unittest.main()
