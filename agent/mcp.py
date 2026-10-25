"""Minimal Model Context Protocol (MCP) JSON-RPC client over HTTP/SSE.

Standard library only: one JSON-RPC POST per call, ``Accept`` covers both
``application/json`` and ``text/event-stream``, and JSON-RPC results are
extracted from either body shape. Used by the solver loop for AI-security
challenges that expose an in-scope MCP server (``mcp`` action:
``list_tools`` / ``call``).

Safety boundaries mirror the structured HTTP tool: the server URL must be in
the platform-provided origin allowlist, redirects are never followed, responses
are size-capped, calls are bounded by the run deadline, and platform/model
credential values are redacted from tool output.

This is a scope and output-hygiene control, not an OS isolation boundary.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from .budget import BudgetExpired, bounded_call, remaining
from .security import redact
from .tools import normalize_origin

MCP_PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "QUTAgent-solver"
CLIENT_VERSION = "0.1"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_RESPONSE_BYTES = 64_000
MAX_CONTENT_CHARS = 12_000
MAX_TOOLS = 200


class MCPError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _header(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def parse_sse(text: str) -> list[dict]:
    """Parse a Server-Sent-Events body into the JSON-RPC messages it carries."""
    messages: list[dict] = []
    data_lines: list[str] = []

    def flush() -> None:
        nonlocal data_lines
        if not data_lines:
            return
        payload = "\n".join(data_lines)
        data_lines = []
        try:
            value = json.loads(payload)
        except ValueError:
            return
        if isinstance(value, dict):
            messages.append(value)
        elif isinstance(value, list):
            messages.extend(item for item in value if isinstance(item, dict))

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            flush()
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if field == "data":
            data_lines.append(value[1:] if value.startswith(" ") else value)
    flush()
    return messages


def _extract_message(text: str, content_type: str, request_id) -> dict | None:
    """Return the JSON-RPC message for ``request_id`` from JSON or SSE text."""
    if not text.strip():
        return None
    candidates: list[dict] = []
    if ("text/event-stream" in (content_type or "").lower()
            or text.lstrip().startswith(("event:", "data:"))):
        candidates = parse_sse(text)
    else:
        try:
            value = json.loads(text)
        except ValueError:
            candidates = parse_sse(text)
        else:
            if isinstance(value, dict):
                return value
            if isinstance(value, list):
                candidates = [item for item in value if isinstance(item, dict)]
    if not candidates:
        return None
    for message in reversed(candidates):
        if (request_id is not None and message.get("id") == request_id
                and ("result" in message or "error" in message)):
            return message
    for message in reversed(candidates):
        if "result" in message or "error" in message:
            return message
    return candidates[-1]


def _redact_value(value, environ):
    """Recursively redact credential-like environment values from a JSON value."""
    if isinstance(value, str):
        return redact(value, environ)
    if isinstance(value, dict):
        return {redact(str(key), environ): _redact_value(item, environ)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, environ) for item in value]
    return value


class MCPClient:
    """One MCP server session: ``initialize`` then ``tools/list`` / ``tools/call``."""

    def __init__(self, url, *, allowed_origins, deadline=None, timeout_s=20,
                 max_response_bytes=MAX_RESPONSE_BYTES, max_content_chars=MAX_CONTENT_CHARS,
                 opener=None, clock=time.monotonic, environ=None):
        self.url = str(url or "").strip()
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("invalid_url")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("invalid_url")
        self.origin = normalize_origin(self.url)
        self.allowed_origins = {normalize_origin(item) for item in allowed_origins}
        if self.origin not in self.allowed_origins:
            raise ValueError("origin_not_allowed")
        self.deadline = deadline
        try:
            self.timeout_s = max(0.1, min(float(timeout_s), 120))
        except (TypeError, ValueError):
            raise ValueError("invalid_timeout")
        try:
            self.max_response_bytes = max(512, min(int(max_response_bytes), 1_000_000))
            self.max_content_chars = max(128, min(int(max_content_chars), 200_000))
        except (TypeError, ValueError):
            raise ValueError("invalid_limits")
        self.opener = opener or urllib.request.build_opener(_NoRedirect)
        self.clock = clock
        self.environ = os.environ if environ is None else environ
        self.session_id: str | None = None
        self.initialized = False
        self.server_info: dict = {}
        self.protocol_version = ""
        self.capabilities: dict = {}
        self.requests = 0
        self._next_id = 0

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "QUTAgent-mcp/1",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _post(self, payload: dict):
        """POST one JSON-RPC payload.

        Returns ``(message, headers, status, error)`` where ``error`` is a short
        machine-readable string. Never raises for network/HTTP/protocol issues.
        """
        try:
            timeout = remaining(self.deadline, self.timeout_s, self.clock)
        except (BudgetExpired, TypeError, ValueError):
            return None, {}, None, "deadline"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.url, data=body, method="POST",
                                          headers=self._headers())
        self.requests += 1

        def fetch():
            with self.opener.open(request, timeout=timeout) as response:
                return (int(response.status), response.read(self.max_response_bytes + 1),
                        dict(response.headers.items()))

        try:
            status, raw, headers = bounded_call(fetch, timeout)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                raw = bounded_call(lambda: exc.read(self.max_response_bytes + 1),
                                   max(0.1, min(timeout, 5)))
            except (BudgetExpired, OSError, ValueError):
                raw = b""
            finally:
                exc.close()
        except BudgetExpired:
            return None, {}, None, "timeout"
        except (urllib.error.URLError, TimeoutError, OSError):
            return None, {}, None, "network_error"
        session_id = _header(headers, "Mcp-Session-Id")
        if session_id:
            self.session_id = session_id
        if status in REDIRECT_STATUSES:
            return None, headers, status, "redirect_refused"
        if len(raw) > self.max_response_bytes:
            return None, headers, status, "response_too_large"
        text = raw.decode("utf-8", errors="replace")
        message = _extract_message(text, _header(headers, "Content-Type"), payload.get("id"))
        if message is None:
            if status in (202, 204, 205) or not text.strip():
                return None, headers, status, None
            return None, headers, status, ("http_%s" % status if status >= 400
                                            else "invalid_response")
        return message, headers, status, None

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        payload = {"jsonrpc": "2.0", "id": self._id(), "method": method,
                   "params": params or {}}
        message, _, status, error = self._post(payload)
        if error:
            return {"error": error, "method": method, "status": status}
        if message is None:
            return {"error": "empty_response", "method": method, "status": status}
        rpc_error = message.get("error")
        if rpc_error is not None:
            detail = rpc_error if isinstance(rpc_error, dict) else {"message": str(rpc_error)}
            return {"error": "jsonrpc_error", "method": method,
                    "code": detail.get("code"),
                    "detail": str(detail.get("message") or "")[:300]}
        result = message.get("result")
        if not isinstance(result, dict):
            return {"error": "invalid_result", "method": method}
        return result

    def _notify(self, method: str, params: dict | None = None) -> None:
        try:
            self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})
        except Exception:  # notifications are best-effort
            pass

    def initialize(self) -> dict:
        """Perform the MCP handshake; idempotent for a session."""
        result = self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        })
        if "error" in result:
            return {"error": result["error"], "phase": "initialize",
                    "status": result.get("status"),
                    "detail": result.get("detail") or result.get("code")}
        self.server_info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        self.protocol_version = str(result.get("protocolVersion") or "")
        self.capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
        self.initialized = True
        self._notify("notifications/initialized")
        return {"ok": True, "server": _redact_value(self.server_info, self.environ),
                "protocol_version": self.protocol_version,
                "capabilities": sorted(self.capabilities)[:20],
                "session": bool(self.session_id),
                "requests": self.requests}

    def _ensure_initialized(self) -> dict | None:
        if self.initialized:
            return None
        outcome = self.initialize()
        if "error" in outcome:
            return {"error": outcome["error"], "phase": "initialize",
                    "detail": outcome.get("detail"), "status": outcome.get("status")}
        return None

    def _clip(self, text: str) -> str:
        text = redact(str(text), self.environ)
        if len(text) <= self.max_content_chars:
            return text
        return text[: self.max_content_chars] + (
            f"... [truncated; {len(text)} chars total]")

    def list_tools(self) -> dict:
        """Return a bounded summary of the server's tools."""
        failure = self._ensure_initialized()
        if failure:
            return failure
        result = self._rpc("tools/list", {})
        if "error" in result:
            return {"error": result["error"], "method": "tools/list",
                    "status": result.get("status"), "detail": result.get("detail"),
                    "code": result.get("code")}
        tools = result.get("tools")
        if not isinstance(tools, list):
            return {"error": "invalid_tools", "method": "tools/list"}
        selected: list[dict] = []
        used = 0
        truncated = False
        for tool in tools[:MAX_TOOLS]:
            if not isinstance(tool, dict):
                continue
            item: dict = {"name": str(tool.get("name") or "")[:128],
                          "description": self._clip(str(tool.get("description") or ""))[:1000]}
            schema = tool.get("inputSchema")
            if isinstance(schema, dict):
                encoded = json.dumps(schema, ensure_ascii=False)
                if len(encoded) <= 2_000:
                    item["input_schema"] = _redact_value(schema, self.environ)
                else:
                    item["input_schema_truncated"] = sorted(schema)[:20]
            encoded = json.dumps(item, ensure_ascii=False)
            if used + len(encoded) > self.max_content_chars:
                truncated = True
                break
            selected.append(item)
            used += len(encoded)
        if len(selected) < min(len(tools), MAX_TOOLS):
            truncated = True
        return {"ok": True, "count": len(tools), "tools": selected,
                "truncated": truncated,
                "server": _redact_value(self.server_info, self.environ),
                "session": bool(self.session_id)}

    def call_tool(self, tool: str, arguments: dict | None = None) -> dict:
        """Call one tool with model-supplied JSON arguments; bounded result."""
        name = str(tool or "").strip()
        if not name or len(name) > 128:
            return {"error": "invalid_tool_name"}
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return {"error": "invalid_arguments"}
        try:
            encoded = json.dumps(arguments, ensure_ascii=False)
        except (TypeError, ValueError):
            return {"error": "invalid_arguments"}
        if len(encoded) > 16_000:
            return {"error": "arguments_too_large"}
        failure = self._ensure_initialized()
        if failure:
            return failure
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if "error" in result:
            return {"error": result["error"], "tool": name, "status": result.get("status"),
                    "code": result.get("code"), "detail": result.get("detail")}
        observation = {
            "ok": not bool(result.get("isError")),
            "tool": name,
            "is_error": bool(result.get("isError")),
            "content": self._render_content(result.get("content")),
            "session": bool(self.session_id),
        }
        structured = result.get("structuredContent")
        if isinstance(structured, (dict, list)):
            raw = json.dumps(structured, ensure_ascii=False)
            observation["structured_content"] = (
                _redact_value(structured, self.environ) if len(raw) <= self.max_content_chars
                else {"truncated": True, "preview": self._clip(raw)})
        return _redact_value(observation, self.environ)

    def _render_content(self, content) -> list[dict]:
        if content is None:
            return []
        if isinstance(content, str):
            return [{"type": "text", "text": self._clip(content)}]
        if not isinstance(content, list):
            return [{"type": "text", "text": self._clip(str(content))}]
        rendered: list[dict] = []
        for item in content[:64]:
            if not isinstance(item, dict):
                rendered.append({"type": "text", "text": self._clip(str(item))})
                continue
            kind = str(item.get("type") or "text")[:32]
            if isinstance(item.get("text"), str):
                rendered.append({"type": kind, "text": self._clip(item["text"])})
            elif item.get("data") is not None:
                rendered.append({"type": kind,
                                 "data_preview": str(item.get("data"))[:512]})
            else:
                rendered.append({"type": kind,
                                 "raw": self._clip(json.dumps(item, ensure_ascii=False))})
        return rendered
