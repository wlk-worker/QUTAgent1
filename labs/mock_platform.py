"""Category-aware mock CTFy-compatible REST stand-in that really checks flags.

Endpoints (matching the shapes used by ``agent/platform.py``):
- ``GET  /api/v1/challenges/{id}``            (category/tags/name/questions)
- ``POST /api/v1/instances``
- ``GET  /api/v1/instances/{id}/status``
- ``GET  /api/v1/instances/{id}``             (services + attachments + questions)
- ``GET  /api/v1/instances/{id}/attachments/{name}``
- ``GET  /api/v1/challenges/{id}/attachments/{name}``
- ``POST /api/v1/submissions``

The platform is the grader: it reads the dynamic flag from the target's private
flag file; the solver never sees that path. Submission logs keep only the answer
SHA-256, never the flag value. Services (HTTP/MCP/TCP) and attachments are
supplied by the runner from the target's readiness handshake, so the same mock
platform works for the traversal, SQLi, MCP and Pwn labs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:  # normal package import
    from .common import append_jsonl, make_dir, now_iso, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, now_iso, write_json

MAX_ATTEMPTS = 3
MAX_ATTACHMENT_BYTES = 50_000_000


def _attachment_list(directory: Path | None) -> list[dict]:
    if directory is None:
        return []
    root = Path(directory)
    if not root.is_dir():
        return []
    items = []
    for path in sorted(root.iterdir()):
        if path.is_file():
            items.append({"name": path.name, "size": path.stat().st_size})
    return items


class PlatformState:
    def __init__(self, challenge_id: str, services: list[dict], flag: str, token: str,
                 log_path: Path, submissions_path: Path, *, category: str = "web",
                 tags: list[str] | None = None, name: str = "Lab challenge",
                 description: str = "Authorized local lab challenge.",
                 question_prompt: str = "Find the flag and submit the exact string.",
                 attachments_dir: Path | None = None):
        self.challenge_id = challenge_id
        self.services = [item for item in services if isinstance(item, dict)]
        self.flag = flag
        self.token = token
        self.log_path = Path(log_path)
        self.submissions_path = Path(submissions_path)
        self.category = category
        self.tags = list(tags or [])
        self.name = name
        self.description = description
        self.question_prompt = question_prompt
        self.attachments_dir = Path(attachments_dir) if attachments_dir else None
        self.attachments = _attachment_list(self.attachments_dir)
        self.lock = threading.RLock()
        self.instances: dict[str, dict] = {}
        self.solved = False
        self.attempts_remaining = MAX_ATTEMPTS
        self.submission_count = 0

    def questions(self) -> list[dict]:
        return [{
            "id": "flag",
            "prompt": self.question_prompt,
            "type": "text",
            "unlocked": True,
            "answered_correctly": self.solved,
            "attempts_remaining": self.attempts_remaining,
        }]

    def challenge(self) -> dict:
        return {
            "id": self.challenge_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "tags": self.tags,
            "questions": self.questions(),
            "gated_questions": 0,
            "attempts_per_question": MAX_ATTEMPTS,
            "challenge_fully_solved": self.solved,
        }

    def instance_info(self, instance_id: str) -> dict:
        return {
            "id": instance_id,
            "status": "ready",
            "challenge_id": self.challenge_id,
            "services": self.services,
            "attachments": self.attachments,
            "questions": self.questions(),
            "gated_questions": 0,
            "challenge_fully_solved": self.solved,
        }

    def attachment_path(self, name: str) -> Path | None:
        if self.attachments_dir is None or not name:
            return None
        parts = name.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return None
        candidate = self.attachments_dir / name
        try:
            resolved = candidate.resolve()
            root = self.attachments_dir.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(root) or not resolved.is_file():
            return None
        if resolved.stat().st_size > MAX_ATTACHMENT_BYTES:
            return None
        return resolved

    def submit(self, instance_id: str, question_id: str, answer) -> dict:
        with self.lock:
            if instance_id not in self.instances:
                return {"status": 404, "body": {"code": "unknown_instance"}}
            if question_id != "flag":
                return {"status": 404, "body": {"code": "unknown_question"}}
            self.submission_count += 1
            submitted = answer if isinstance(answer, str) else json.dumps(answer, ensure_ascii=False)
            correct = self.solved or submitted.strip() == self.flag
            if correct:
                self.solved = True
            else:
                self.attempts_remaining = max(0, self.attempts_remaining - 1)
            append_jsonl(self.submissions_path, {
                "ts": now_iso(),
                "instance_id": instance_id,
                "question_id": question_id,
                "answer_sha256": hashlib.sha256(submitted.encode("utf-8")).hexdigest(),
                "answer_length": len(submitted),
                "correct": bool(correct),
                "attempts_remaining": self.attempts_remaining,
                "challenge_fully_solved": self.solved,
            }, lock=self.lock)
            return {"status": 200, "body": {
                "id": f"submission-{self.submission_count}",
                "correct": bool(correct),
                "challenge_fully_solved": self.solved,
                "attempts_remaining": self.attempts_remaining,
            }}


def _make_handler(state: PlatformState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MockCTFy/0.2"
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _record(self, status: int) -> None:
            append_jsonl(state.log_path, {
                "ts": now_iso(), "method": self.command, "path": self.path,
                "status": status,
            }, lock=state.lock)

        def _json(self, status: int, data: dict) -> None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status)

        def _bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status)

        def _authorized(self) -> bool:
            expected = "Bearer " + state.token
            return self.headers.get("Authorization") == expected

        def _read_json(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if length <= 0 or length > 1_000_000:
                return None
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw)
            except ValueError:
                return None
            return data if isinstance(data, dict) else None

        def _attachment(self, rest: str) -> None:
            # rest is like "instances/<id>/attachments/<name>" or
            # "challenges/<id>/attachments/<name>".
            pieces = rest.split("/")
            # "<instances|challenges>/<id>/attachments/<name>"
            if len(pieces) < 4 or pieces[2] != "attachments":
                self._json(404, {"code": "not_found"})
                return
            owner_kind = pieces[0]
            owner_id = unquote(pieces[1])
            name = "/".join(unquote(piece) for piece in pieces[3:])
            if owner_kind == "instances" and owner_id not in state.instances:
                self._json(404, {"code": "unknown_instance"})
                return
            if owner_kind == "challenges" and owner_id != state.challenge_id:
                self._json(404, {"code": "unknown_challenge"})
                return
            path = state.attachment_path(name)
            if path is None:
                self._json(404, {"code": "unknown_attachment"})
                return
            self._bytes(200, path.read_bytes(), "application/octet-stream")

        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path).path
            prefix = "/api/v1/"
            if not path.startswith(prefix):
                self._json(404, {"code": "not_found"})
                return
            if not self._authorized():
                self._json(401, {"code": "unauthorized", "message": "missing or invalid token"})
                return
            rest = path[len(prefix):]
            if rest.startswith("challenges/"):
                tail = rest[len("challenges/"):]
                if "/attachments/" in tail:
                    self._attachment(rest)
                    return
                challenge_id = unquote(tail)
                if challenge_id != state.challenge_id:
                    self._json(404, {"code": "unknown_challenge"})
                else:
                    self._json(200, state.challenge())
                return
            if rest.startswith("instances/"):
                tail = rest[len("instances/"):]
                if "/attachments/" in tail:
                    self._attachment(rest)
                    return
                if tail.endswith("/status"):
                    self._status(unquote(tail[:-len("/status")]))
                    return
                instance_id = unquote(tail)
                if instance_id in state.instances:
                    self._json(200, state.instance_info(instance_id))
                else:
                    self._json(404, {"code": "unknown_instance"})
                return
            if rest == "health":
                self._json(200, {"status": "ok"})
                return
            self._json(404, {"code": "not_found"})

        def _status(self, instance_id: str) -> None:
            with state.lock:
                instance = state.instances.get(instance_id)
                if instance is None:
                    self._json(404, {"code": "unknown_instance"})
                    return
                if instance["status_polls"] == 0:
                    instance["status_polls"] += 1
                    self._json(200, {"id": instance_id, "status": "starting",
                                     "poll_after_s": 0.05})
                    return
                self._json(200, {"id": instance_id, "status": "ready"})

        def _create_instance(self) -> None:
            payload = self._read_json()
            if payload is None:
                self._json(400, {"code": "invalid_json"})
                return
            if payload.get("challenge_id") != state.challenge_id:
                self._json(404, {"code": "unknown_challenge"})
                return
            with state.lock:
                index = len(state.instances) + 1
                instance_id = f"instance-{index}"
                state.instances[instance_id] = {
                    "status_polls": 0,
                    "competition_id": payload.get("competition_id"),
                }
            self._json(200, {"id": instance_id, "status": "starting", "poll_after_s": 0.05})

        def _submit(self) -> None:
            payload = self._read_json()
            if payload is None:
                self._json(400, {"code": "invalid_json"})
                return
            result = state.submit(str(payload.get("instance_id") or ""),
                                  str(payload.get("question_id") or ""),
                                  payload.get("answer"))
            self._json(result["status"], result["body"])

        def do_POST(self):  # noqa: N802
            path = urlsplit(self.path).path
            if not path.startswith("/api/v1/"):
                self._json(404, {"code": "not_found"})
                return
            if not self._authorized():
                self._json(401, {"code": "unauthorized", "message": "missing or invalid token"})
                return
            if path == "/api/v1/instances":
                self._create_instance()
            elif path == "/api/v1/submissions":
                self._submit()
            else:
                self._json(404, {"code": "not_found"})

    return Handler


def _parse_services(args) -> list[dict]:
    if args.services_json:
        try:
            services = json.loads(args.services_json)
        except ValueError as exc:
            raise SystemExit(f"invalid --services-json: {exc}")
        if not isinstance(services, list):
            raise SystemExit("--services-json must be a JSON list")
        return [item for item in services if isinstance(item, dict)]
    if args.target_origin and args.target_port:
        return [{"service_type": "http", "name": "file-shelf",
                 "host": "127.0.0.1", "port": args.target_port,
                 "url": args.target_origin, "description": "Acme File Shelf"}]
    raise SystemExit("provide --services-json or --target-origin/--target-port")


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock CTFy platform for the local lab")
    parser.add_argument("--services-json", default="")
    parser.add_argument("--target-origin", default="")
    parser.add_argument("--target-port", type=int, default=0)
    parser.add_argument("--flag-file", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--challenge-id", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--submissions-log", required=True)
    parser.add_argument("--attachments-dir", default="")
    parser.add_argument("--category", default="web")
    parser.add_argument("--tags", default="", help="comma-separated tags")
    parser.add_argument("--name", default="Lab challenge")
    parser.add_argument("--description", default="Authorized local lab challenge.")
    parser.add_argument("--question-prompt",
                       default="Find the flag served by the challenge target and submit the exact string.")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    flag = Path(args.flag_file).read_text(encoding="utf-8").strip()
    if not flag:
        raise SystemExit("flag file is empty")
    for path in (args.log, args.submissions_log):
        make_dir(Path(path).parent)
    tags = [item.strip() for item in args.tags.split(",") if item.strip()]
    state = PlatformState(
        args.challenge_id, _parse_services(args), flag, args.token,
        Path(args.log), Path(args.submissions_log),
        category=args.category, tags=tags, name=args.name,
        description=args.description, question_prompt=args.question_prompt,
        attachments_dir=Path(args.attachments_dir) if args.attachments_dir else None)
    make_dir(Path(args.ready_file).parent)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _make_handler(state))
    server.daemon_threads = True
    write_json(Path(args.ready_file), {
        "service": "mock_platform",
        "port": server.server_port,
        "origin": f"http://127.0.0.1:{server.server_port}",
        "challenge_id": args.challenge_id,
        "attachments": [item["name"] for item in state.attachments],
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
