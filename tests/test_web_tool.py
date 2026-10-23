"""Structured HTTP tool tests: origin scope, redirects, truncation, timeout, loop wiring."""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.contract import Task
from agent.loop import run
from agent.tools import http_request, normalize_origin
from labs.common import cleanup_work, workspace_temp


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    lock = threading.Lock()
    hits = {}
    other_port = 0

    def log_message(self, *args):
        pass

    def _record(self):
        with type(self).lock:
            type(self).hits[self.path] = type(self).hits.get(self.path, 0) + 1

    def _reply(self, status, body=b"", headers=None):
        self._record()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            self._reply(200, b'{"hello":"world"}', {"Content-Type": "application/json",
                                                    "X-Fixture": "yes"})
        elif self.path == "/big":
            self._reply(200, b"A" * 5000, {"Content-Type": "text/plain"})
        elif self.path == "/redirect":
            self._reply(302, b"", {"Location": f"http://127.0.0.1:{type(self).other_port}/leak"})
        elif self.path == "/slow":
            time.sleep(0.6)
            self._reply(200, b"late")
        elif self.path == "/leak":
            self._reply(200, b"should-not-be-reached")
        else:
            self._reply(404, b"nope")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/echo":
            payload = json.dumps({"echo": body.decode("utf-8", "replace"),
                                  "content_type": self.headers.get("Content-Type")}).encode()
            self._reply(200, payload, {"Content-Type": "application/json"})
        else:
            self._reply(404, b"nope")


def _start(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02},
                              daemon=True)
    thread.start()
    return server


class HttpToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FixtureHandler.hits = {}
        cls.other = _start(FixtureHandler)
        FixtureHandler.other_port = cls.other.server_port
        cls.server = _start(FixtureHandler)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.other_origin = f"http://127.0.0.1:{cls.other.server_port}"
        FixtureHandler.hits = {}

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.other):
            server.shutdown()
            server.server_close()

    def test_allowed_origin_get_returns_structured_observation(self):
        result = http_request("GET", self.origin + "/ok", allowed_origins=[self.origin])
        self.assertEqual(result["status"], 200)
        self.assertTrue(result["ok"])
        self.assertIn("hello", result["body_preview"])
        self.assertIn("content-type", {key.lower() for key in result["headers"]})
        self.assertFalse(result["truncated"])
        self.assertFalse(result["redirect_blocked"])
        self.assertEqual(result["origin"], self.origin)

    def test_disallowed_origin_is_rejected_without_sending_request(self):
        before = FixtureHandler.hits.get("/leak", 0)
        result = http_request("GET", self.other_origin + "/leak",
                              allowed_origins=[self.origin])
        self.assertEqual(result["error"], "origin_not_allowed")
        self.assertEqual(result["origin"], self.other_origin)
        self.assertEqual(FixtureHandler.hits.get("/leak", 0), before)

    def test_origin_normalization_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_origin("http://user:pass@127.0.0.1:1")
        with self.assertRaises(ValueError):
            normalize_origin("ftp://127.0.0.1:1")
        self.assertEqual(normalize_origin("HTTP://127.0.0.1:80"), "http://127.0.0.1")

    def test_response_body_is_truncated_at_limit(self):
        result = http_request("GET", self.origin + "/big", allowed_origins=[self.origin],
                              max_response_bytes=1000)
        self.assertEqual(result["status"], 200)
        self.assertTrue(result["truncated"])
        self.assertGreaterEqual(result["body_bytes"], 1000)
        self.assertLessEqual(len(result["body_preview"]), 1000)

    def test_redirect_is_refused_and_not_followed(self):
        before = FixtureHandler.hits.get("/leak", 0)
        result = http_request("GET", self.origin + "/redirect", allowed_origins=[self.origin])
        self.assertEqual(result["status"], 302)
        self.assertTrue(result["redirect_blocked"])
        self.assertIn("location", result)
        self.assertEqual(FixtureHandler.hits.get("/leak", 0), before)

    def test_post_json_body_is_forwarded(self):
        result = http_request("POST", self.origin + "/echo", allowed_origins=[self.origin],
                              body={"answer": 42})
        self.assertEqual(result["status"], 200)
        self.assertIn("answer", result["body_preview"])
        self.assertIn("application/json", result["body_preview"])

    def test_get_with_body_and_bad_urls_are_rejected(self):
        result = http_request("GET", self.origin + "/ok", allowed_origins=[self.origin],
                              body={"x": 1})
        self.assertEqual(result["error"], "body_not_allowed_for_get")
        self.assertEqual(http_request("GET", "http://user:pass@127.0.0.1:1/",
                                      allowed_origins=[self.origin])["error"], "invalid_url")
        self.assertEqual(http_request("GET", "ftp://127.0.0.1/x",
                                      allowed_origins=[self.origin])["error"], "invalid_url")
        self.assertEqual(http_request("DELETE", self.origin + "/ok",
                                      allowed_origins=[self.origin])["error"], "method_not_allowed")

    def test_timeout_is_bounded(self):
        start = time.monotonic()
        result = http_request("GET", self.origin + "/slow", allowed_origins=[self.origin],
                              timeout_s=0.15)
        self.assertEqual(result["error"], "timeout")
        self.assertLess(time.monotonic() - start, 0.5)


class _FakePlatform:
    def __init__(self, origin):
        self.origin = origin
        self.submissions = []

    def challenge(self, challenge_id):
        return {"id": challenge_id, "questions": [{"id": "flag", "prompt": "find it"}]}

    def start_instance(self, challenge_id, competition_id):
        return "instance-1"

    def wait_instance(self, instance_id):
        return self.instance(instance_id)

    def instance(self, instance_id):
        return {"id": instance_id,
                "services": [{"service_type": "http", "host": "127.0.0.1",
                              "port": int(self.origin.rsplit(":", 1)[1]), "url": self.origin}],
                "questions": [{"id": "flag", "prompt": "find it"}]}

    def submit(self, instance_id, question_id, answer):
        self.submissions.append((question_id, answer))
        return {"correct": True, "challenge_fully_solved": True}


class _HttpModel:
    input_tokens = 11
    output_tokens = 4

    def __init__(self, origin):
        self.origin = origin
        self.actions = [
            {"action": "http", "method": "GET", "url": origin + "/ok", "why": "probe"},
            {"action": "submit", "question_id": "flag", "answer": "flag{from-observation}",
             "evidence": "GET /ok"},
        ]

    def complete(self, system, messages, max_tokens=1200):
        return json.dumps(self.actions.pop(0))


class LoopHttpWiringTests(unittest.TestCase):
    def setUp(self):
        FixtureHandler.hits = {}
        self.server = _start(FixtureHandler)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.work = workspace_temp("test-web-tool-")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        cleanup_work(self.work)

    def _run(self, model, platform):
        task = Task(self.work, {"challenge": {"id": "C-1"}}, "", "C-1", "event", "instance", False)
        return run(task, platform, model, max_turns=4, deadline=time.monotonic() + 10,
                   on_update=lambda value: None)

    def test_loop_http_action_uses_platform_service_scope(self):
        result = self._run(_HttpModel(self.origin), _FakePlatform(self.origin))
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["http_calls"], 1)
        self.assertEqual(result["tool_calls_made"], 1)
        events = [json.loads(line) for line in
                  (self.work / "events.jsonl").read_text().splitlines() if line.strip()]
        observations = [entry["data"] for entry in events if entry["event"] == "observation"]
        self.assertTrue(any(item.get("status") == 200 for item in observations))
        self.assertTrue(any(item.get("verdict", {}).get("correct") for item in observations))

    def test_web_only_disables_shell_before_execution(self):
        calls = []

        def command_tool(command, cwd):
            calls.append(command)
            return {"exit_code": 0, "stdout": "should not run"}

        class ShellModel:
            input_tokens = output_tokens = 0
            actions = [{"action": "shell", "command": "whoami", "why": "should be disabled"},
                       {"action": "finish", "reason": "shell unavailable"}]

            def complete(self, *args):
                return json.dumps(self.actions.pop(0))

        with patch.dict(os.environ, {"QUT_WEB_ONLY": "1"}):
            result = run(Task(self.work, {"challenge": {"id": "C-1"}}, "", "C-1", "event",
                              "instance", False),
                         _FakePlatform(self.origin), ShellModel(), max_turns=2,
                         deadline=time.monotonic() + 10, on_update=lambda value: None,
                         command_tool=command_tool)
        self.assertEqual(calls, [])
        self.assertEqual(result["tool_calls_made"], 0)
        events = [json.loads(line) for line in (self.work / "events.jsonl").read_text().splitlines()
                  if line.strip()]
        self.assertTrue(any(entry["data"].get("error") == "shell_disabled_web_only"
                            for entry in events if entry["event"] == "observation"))


if __name__ == "__main__":
    unittest.main()
