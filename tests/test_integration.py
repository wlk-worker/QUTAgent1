"""Exercise the real entrypoint against local HTTP stand-ins, not CTFy."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    solved = False
    model_calls = 0
    submissions = []
    delay_model = 0

    def log_message(self, *args):
        pass

    def reply(self, data):
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionAbortedError):
            # Expected when the short-budget client abandons a slow response.
            pass

    def do_GET(self):
        if self.path == "/api/v1/challenges/C-1":
            self.reply({"id": "C-1", "name": "Local fixture", "questions": [{"id": "flag", "prompt": "Find the token"}]})
        elif self.path == "/api/v1/instances/I-1/status":
            self.reply({"id": "I-1", "status": "ready"})
        elif self.path == "/api/v1/instances/I-1":
            self.reply({"id": "I-1", "services": [{"service_type": "http", "host": "127.0.0.1", "port": 1}],
                        "questions": [{"id": "flag", "prompt": "Find the token", "answered_correctly": type(self).solved}]})
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if self.path == "/api/v1/instances":
            self.reply({"id": "I-1", "status": "starting"})
        elif self.path == "/api/v1/submissions":
            type(self).submissions.append(body)
            type(self).solved = body.get("answer") == "ctfy{mock}"
            self.reply({"id": "S-1", "correct": type(self).solved, "challenge_fully_solved": type(self).solved})
        elif self.path == "/v1/chat/completions":
            if type(self).delay_model:
                time.sleep(type(self).delay_model)
            type(self).model_calls += 1
            action = ({"action": "shell", "command": "printf 'ctfy{mock}'", "why": "local fixture"}
                      if type(self).model_calls == 1 else
                      {"action": "submit", "question_id": "flag", "answer": "ctfy{mock}", "evidence": "shell output"})
            self.reply({"choices": [{"message": {"content": json.dumps(action)}}],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2}})
        else:
            self.send_error(404)


class IntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "command tool requires Linux; run full suite in WSL/container")
    def test_entrypoint_model_tool_platform_result(self):
        Handler.solved = False
        Handler.model_calls = 0
        Handler.submissions = []
        Handler.delay_model = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "task.json").write_text(json.dumps({
                    "schema_version": 2, "run_mode": "instance", "challenge": {"id": "C-1"},
                    "competition_id": "event", "questions": [{"id": "flag", "prompt": "Find the token"}],
                    "max_turns": 3,
                }))
                address = f"http://127.0.0.1:{server.server_port}"
                env = {**os.environ, "CTFY_WORK_DIR": temp, "CTFY_PLATFORM_URL": address,
                       "CTFY_TOKEN": "fixture-platform-key", "LLM_FLAVOR": "openai",
                       "LLM_API_KEY": "fixture-model-key", "LLM_MODEL": "fixture",
                       "LLM_BASE_URL": address + "/v1"}
                run = subprocess.run([sys.executable, str(ROOT / "agent" / "main.py")],
                                     env=env, cwd=temp, capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                result = json.loads((root / "result.json").read_text())
                self.assertEqual(result["solved"], ["flag"])
                self.assertTrue(result["fully_solved"])
                self.assertEqual(result["stop_reason"], "done")
                self.assertEqual(result["answers"], {})
                self.assertEqual(len(Handler.submissions), 1)
                self.assertEqual(Handler.submissions[0]["instance_id"], "I-1")
                self.assertNotIn("fixture-platform-key", run.stdout + run.stderr + json.dumps(result))
                self.assertNotIn("fixture-model-key", run.stdout + run.stderr + json.dumps(result))
        finally:
            server.shutdown()
            server.server_close()

    def test_short_budget_writes_result(self):
        Handler.solved = False
        Handler.model_calls = 0
        Handler.delay_model = .35
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "task.json").write_text(json.dumps({
                    "schema_version": 2, "run_mode": "qa", "challenge": {"id": "C-1"},
                    "competition_id": "event", "max_turns": 3,
                }))
                address = f"http://127.0.0.1:{server.server_port}"
                env = {**os.environ, "CTFY_WORK_DIR": temp, "CTFY_PLATFORM_URL": address,
                       "CTFY_TOKEN": "fixture-platform-key", "LLM_FLAVOR": "openai",
                       "LLM_API_KEY": "fixture-model-key", "LLM_MODEL": "fixture",
                       "LLM_BASE_URL": address + "/v1", "QUT_RUN_TIMEOUT_S": ".12"}
                start = time.monotonic()
                run = subprocess.run([sys.executable, str(ROOT / "agent" / "main.py")],
                                     env=env, cwd=temp, capture_output=True, text=True, timeout=3)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertLess(time.monotonic() - start, .8)
                result = json.loads((root / "result.json").read_text())
                self.assertEqual(result["stop_reason"], "deadline")
                self.assertFalse(result["fully_solved"])
        finally:
            Handler.delay_model = 0
            server.shutdown()
            server.server_close()
