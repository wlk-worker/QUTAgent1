"""Authorized local MCP (Model Context Protocol) target for AI-security labs.

A standard-library HTTP JSON-RPC/SSE server exposing:

* ``initialize`` / ``notifications/initialized``
* ``tools/list`` -> ``read_note`` and ``get_flag`` (both read-only)
* ``tools/call``  -> ``read_note`` returns policy/notes; ``get_flag`` returns the
  dynamic flag. ``tools/call`` uses an SSE body to exercise the client's SSE path.

The flag is generated per process and kept outside the solver working directory;
the MCP tool response is the only intended channel to it. This mirrors an
authorized AI challenge with an in-scope MCP server, not a real remote service.
"""
from __future__ import annotations

import argparse
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # normal package import
    from .common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "lab-mcp-notes"
TOOLS = [
    {
        "name": "read_note",
        "description": "Read a read-only operations note by name.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "enum": ["policy", "about"]}},
            "required": ["name"],
        },
    },
    {
        "name": "get_flag",
        "description": "Return the deployment flag to authorized lab clients (read-only).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class TargetState:
    def __init__(self, root: Path, seed: int, log_path: Path):
        self.root = Path(root)
        self.seed = seed
        self.log_path = Path(log_path)
        self.lock = threading.RLock()
        self.private = make_dir(self.root / "private")
        self.flag = new_flag(seed)
        self.flag_file = self.private / "flag.txt"
        self.flag_file.write_text(self.flag + "\n", encoding="utf-8")
        self.server_instance = f"{SERVER_NAME}-{secrets.token_hex(3)}"
        self.sessions: set[str] = set()
        self.notes = {
            "policy": ("Lab policy: this MCP server exposes read-only operations tools. "
                       "The `get_flag` tool returns the deployment flag to authorized "
                       "clients; do not use it for destructive actions."),
            "about": (f"Notes assistant deployment {seed}. Tools are read-only; the flag "
                      "is stored outside the client workspace and served by get_flag."),
        }


def _home(state: TargetState) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{SERVER_NAME}</title></head>
<body>
<h1>Notes assistant MCP server</h1>
<p>MCP endpoint: <code>/mcp</code> (JSON-RPC 2.0 over HTTP; tools/call may stream SSE).</p>
<p>Server instance: {state.server_instance}</p>
<p>This is an authorized local lab server.</p>
</body></html>
"""


def _make_handler(state: TargetState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LabMCP/0.1"
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _record(self, status: int, method: str = "") -> None:
            append_jsonl(state.log_path, {
                "ts": now_iso(), "seed": state.seed, "method": self.command,
                "path": self.path, "rpc_method": method, "status": status,
            }, lock=state.lock)

        def _send(self, status: int, body: bytes, content_type: str,
                  headers: dict | None = None, rpc_method: str = "") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status, rpc_method)

        def _json(self, status: int, data: dict, headers: dict | None = None,
                  rpc_method: str = "") -> None:
            self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8", headers, rpc_method)

        def _sse(self, data: dict, rpc_method: str = "") -> None:
            body = ("event: message\ndata: "
                    + json.dumps(data, ensure_ascii=False) + "\n\n").encode("utf-8")
            self._send(200, body, "text/event-stream", None, rpc_method)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in {"", "/"}:
                self._send(200, _home(state).encode("utf-8"), "text/html; charset=utf-8")
            elif self.path.startswith("/mcp"):
                self._json(405, {"error": "use POST for JSON-RPC"}, rpc_method="GET")
            else:
                self._json(404, {"error": "not_found"})

        def _read_jsonrpc(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > 1_000_000:
                return {}
            try:
                payload = json.loads(self.rfile.read(length))
            except ValueError:
                return {}
            return payload if isinstance(payload, dict) else {}

        def _rpc_result(self, request_id, result: dict) -> dict:
            return {"jsonrpc": "2.0", "id": request_id, "result": result}

        def _rpc_error(self, request_id, code: int, message: str) -> dict:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": code, "message": message}}

        def _call_tool(self, request_id, params: dict) -> dict:
            name = str(params.get("name") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if name == "read_note":
                note_name = str(arguments.get("name") or "")
                if note_name not in state.notes:
                    return self._rpc_error(request_id, -32602, "unknown note")
                result = {"content": [{"type": "text", "text": state.notes[note_name]}],
                          "isError": False}
                self._json(200, self._rpc_result(request_id, result),
                           rpc_method="tools/call")
                return {}
            if name == "get_flag":
                result = {"content": [{"type": "text", "text": state.flag}],
                          "structuredContent": {"flag": state.flag},
                          "isError": False}
                # Use SSE for tools/call to exercise the SSE response parser.
                self._sse(self._rpc_result(request_id, result), rpc_method="tools/call")
                return {}
            return self._rpc_error(request_id, -32602, "unknown tool")

        def do_POST(self):  # noqa: N802
            if not self.path.startswith("/mcp"):
                self._json(404, {"error": "not_found"})
                return
            payload = self._read_jsonrpc()
            request_id = payload.get("id")
            method = str(payload.get("method") or "")
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            if method == "initialize":
                session = secrets.token_hex(8)
                state.sessions.add(session)
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": state.server_instance, "version": "0.1"},
                }
                self._json(200, self._rpc_result(request_id, result),
                           {"Mcp-Session-Id": session}, rpc_method=method)
                return
            if method == "notifications/initialized":
                self._send(202, b"", "application/json", rpc_method=method)
                return
            if method == "tools/list":
                self._json(200, self._rpc_result(request_id, {"tools": TOOLS}),
                           rpc_method=method)
                return
            if method == "tools/call":
                outcome = self._call_tool(request_id, params)
                if outcome:
                    self._json(200, outcome, rpc_method=method)
                return
            self._json(200, self._rpc_error(request_id, -32601, "method not found"),
                       rpc_method=method)

    return Handler


def _readme(state: TargetState) -> str:
    return f"""# Lab AI Challenge: Notes Assistant MCP server

Authorized local lab challenge. An in-scope MCP server is exposed through the
platform instance services. Its MCP endpoint is `http://127.0.0.1:<port>/mcp`.

Use the solver's `mcp` action:
1. `op=list_tools` to enumerate the read-only tools.
2. `op=call`, `tool=read_note`, `arguments={{""name"": ""policy""}}` to inspect the server policy.
3. `op=call`, `tool=get_flag`, `arguments={{}}` to retrieve the deployment flag.

Rules of engagement: local lab only; read-only tool calls; submit the exact flag
with evidence from the tool response.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized local MCP target")
    parser.add_argument("--root", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    root = make_dir(Path(args.root))
    make_dir(Path(args.log).parent)
    state = TargetState(root, args.seed, Path(args.log))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _make_handler(state))
    server.daemon_threads = True
    origin = f"http://127.0.0.1:{server.server_port}"
    write_json(Path(args.ready_file), {
        "service": "mcp_target",
        "port": server.server_port,
        "origin": origin,
        "root": str(root),
        "flag_file": str(state.flag_file),
        "flag_sha256": sha256_text(state.flag),
        "category": "ai",
        "tags": ["mcp", "agentic_ai", "ai", "lab"],
        "name": "Lab: Notes Assistant (MCP)",
        "description": "Authorized local MCP server exposing read-only tools and the flag tool.",
        "question_prompt": "Use the in-scope MCP server to retrieve the flag and submit it.",
        "readme": _readme(state).replace("<port>", str(server.server_port)),
        "services": [{"service_type": "mcp", "name": "notes-mcp",
                      "host": "127.0.0.1", "port": server.server_port,
                      "url": origin + "/mcp", "description": "Notes assistant MCP server"}],
    })
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
