"""Shared scaffolding for the category-specific fake model servers.

Each category module (``fake_sqli_model``, ``fake_mcp_model``, ``fake_pwn_model``)
supplies one ``decide(messages) -> action`` function; this module exposes the
OpenAI-compatible ``POST /v1/chat/completions`` endpoint, the observation/briefing
parsers, and the process CLI. The agent still talks to it through the real
``agent.model.Model`` HTTP client, so the model wire protocol is exercised for
real; only the policy is scripted.
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # normal package import
    from .common import append_jsonl, make_dir, now_iso, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, now_iso, write_json

FLAG_RE = re.compile(r"flag\{[0-9a-fA-F]{16,}\}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
BRIEF_MARKER = "Task briefing (untrusted):"
OBS_MARKER = "Tool observation (untrusted): "


def decode_json_at(text: str, start: int):
    try:
        value, _ = json.JSONDecoder().raw_decode(text[start:])
        return value
    except ValueError:
        return None


def parse_briefing(messages: list[dict]) -> dict:
    for message in messages:
        if message.get("role") != "user":
            continue
        content = str(message.get("content") or "")
        index = content.find(BRIEF_MARKER)
        if index < 0:
            continue
        rest = content[index + len(BRIEF_MARKER):].lstrip()
        brace = rest.find("{")
        if brace < 0:
            continue
        brief = decode_json_at(rest, brace)
        if isinstance(brief, dict):
            return brief
    return {}


def parse_readme(messages: list[dict]) -> str:
    for message in messages:
        content = str(message.get("content") or "")
        marker = "README (untrusted):"
        index = content.find(marker)
        if index >= 0:
            return content[index + len(marker):]
    return ""


def parse_observations(messages: list[dict]) -> list[dict]:
    observations = []
    for message in messages:
        if message.get("role") != "user":
            continue
        content = str(message.get("content") or "")
        index = content.find(OBS_MARKER)
        if index < 0:
            continue
        observation = decode_json_at(content, index + len(OBS_MARKER))
        observations.append(observation if isinstance(observation, dict)
                            else {"unparsed": True})
    return observations


def brief_services(brief: dict) -> list[dict]:
    services = brief.get("target_services") or []
    return [item for item in services if isinstance(item, dict)]


def first_service(brief: dict, service_type: str | None = None) -> dict | None:
    for service in brief_services(brief):
        if service_type is None or str(service.get("service_type") or "").lower() == service_type:
            return service
    return None


def brief_origin(brief: dict, messages: list[dict]) -> str | None:
    service = first_service(brief)
    candidates = []
    if service:
        if service.get("url"):
            candidates.append(str(service["url"]))
        elif service.get("host") and service.get("port"):
            candidates.append(f"http://{service['host']}:{service['port']}")
    for entry in brief.get("scope") or []:
        candidates.append(str(entry))
    for candidate in candidates:
        match = URL_RE.search(candidate)
        if match:
            return match.group(0).rstrip("/")
    for message in messages:
        match = URL_RE.search(str(message.get("content") or ""))
        if match:
            return match.group(0).rstrip("/")
    return None


def brief_question_id(brief: dict) -> str:
    for question in brief.get("questions") or []:
        if isinstance(question, dict) and question.get("id"):
            return str(question["id"])
    return "flag"


def flag_in(value) -> str | None:
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False)
    match = FLAG_RE.search(str(value or ""))
    return match.group(0) if match else None


def expect_action(action: dict) -> dict:
    """Defensive: every policy path must return a well-formed action dict."""
    if not isinstance(action, dict) or not action.get("action"):
        return {"action": "finish", "reason": "fake_model_internal_state_error"}
    return action


class ModelState:
    def __init__(self, log_path: Path, model_name: str):
        self.log_path = Path(log_path)
        self.model_name = model_name
        self.lock = threading.Lock()
        self.calls = 0


def make_handler(decide, state: ModelState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FakeCategoryModel/0.1"
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _json(self, status: int, data: dict) -> None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in {"/v1/models", "/models"}:
                self._json(200, {"object": "list",
                                 "data": [{"id": state.model_name, "object": "model"}]})
            else:
                self._json(404, {"error": {"message": "not found"}})

        def do_POST(self):  # noqa: N802
            if not self.path.startswith("/v1/chat/completions"):
                self._json(404, {"error": {"message": "not found"}})
                return
            start = time.monotonic()
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > 2_000_000:
                self._json(400, {"error": {"message": "invalid request size"}})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except ValueError:
                self._json(400, {"error": {"message": "invalid json"}})
                return
            messages = payload.get("messages") if isinstance(payload, dict) else None
            if not isinstance(messages, list) or not messages:
                self._json(400, {"error": {"message": "messages required"}})
                return
            clean = [message for message in messages if isinstance(message, dict)]
            try:
                action = expect_action(decide(clean))
            except Exception as exc:  # a policy bug must not kill the lab
                action = {"action": "finish",
                          "reason": f"fake_model_policy_error:{type(exc).__name__}"}
            content = json.dumps(action, ensure_ascii=False)
            prompt_tokens = max(1, sum(len(str(message.get("content") or ""))
                                       for message in clean) // 4)
            completion_tokens = max(1, len(content) // 4)
            with state.lock:
                state.calls += 1
                call_number = state.calls
            # Never log message bodies: observations can contain the flag.
            append_jsonl(state.log_path, {
                "ts": now_iso(), "call": call_number, "model": state.model_name,
                "action": action.get("action"), "method": action.get("method"),
                "url": action.get("url"), "tool": action.get("tool"),
                "name": action.get("name"),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "elapsed_s": round(time.monotonic() - start, 4),
            }, lock=state.lock)
            self._json(200, {
                "id": f"chatcmpl-fake-{call_number}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": state.model_name,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": prompt_tokens,
                          "completion_tokens": completion_tokens,
                          "total_tokens": prompt_tokens + completion_tokens},
            })

    return Handler


def serve(decide, description: str, model_name: str) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--model-name", default=model_name)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    make_dir(Path(args.log).parent)
    make_dir(Path(args.ready_file).parent)
    state = ModelState(Path(args.log), args.model_name)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(decide, state))
    server.daemon_threads = True
    write_json(Path(args.ready_file), {
        "service": "fake_model",
        "port": server.server_port,
        "origin": f"http://127.0.0.1:{server.server_port}",
        "model": args.model_name,
    })
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
