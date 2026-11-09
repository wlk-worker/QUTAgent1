import http.client
import json
import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.contract import Task, write_result
from agent.loop import run
from agent.main import _working_time
from agent.model import Model, ModelError
from agent.platform import Platform, PlatformError, Paused, _retry_seconds
from author.generate import generate


class FakeModel:
    input_tokens = 9
    output_tokens = 3

    def __init__(self, actions):
        self.actions = iter(actions)

    def complete(self, system, messages, max_tokens=1200):
        return json.dumps(next(self.actions))


class FakePlatform:
    def __init__(self):
        self.started = 0
        self.submissions = []
        self.unlocked = False

    def challenge(self, challenge_id):
        return {"id": challenge_id, "questions": [{"id": "flag", "prompt": "First"}]}

    def start_instance(self, challenge_id, competition_id):
        self.started += 1
        return "instance-1"

    def wait_instance(self, instance_id):
        return self.instance(instance_id)

    def instance(self, instance_id):
        questions = [{"id": "flag", "prompt": "First", "answered_correctly": self.unlocked}]
        if self.unlocked:
            questions.append({"id": "second", "prompt": "Unlocked", "answered_correctly": False})
        return {"id": instance_id, "questions": questions, "services": [{"host": "example.test", "port": 443}]}

    def submit(self, instance_id, qid, answer):
        self.submissions.append((qid, answer))
        if qid == "flag" and answer == "ctfy{ok}":
            self.unlocked = True
            return {"correct": True, "challenge_fully_solved": False}
        return {"correct": False, "attempts_remaining": 0}


class ContractTests(unittest.TestCase):
    def test_short_task_budget_is_not_extended(self):
        self.assertGreater(_working_time(10), 0)
        self.assertLess(_working_time(10), 10)

    def test_instance_status_honors_poll_hint(self):
        class PollingPlatform(Platform):
            def __init__(self):
                self.responses = iter([
                    type("R", (), {"data": {"status": "starting", "poll_after_s": 3}, "headers": {}})(),
                    type("R", (), {"data": {"status": "ready"}, "headers": {}})(),
                    type("R", (), {"data": {"id": "I-1"}, "headers": {}})(),
                ])
                self.waits = []
                self.sleep = self.waits.append
                self.deadline = None
                import time
                self.clock = time.monotonic

            def request(self, method, path, payload=None):
                return next(self.responses)

        platform = PollingPlatform()
        self.assertEqual(platform.wait_instance("I-1")["id"], "I-1")
        self.assertEqual(platform.waits, [3])

    def test_generated_rotator_has_unix_shebang(self):
        with tempfile.TemporaryDirectory() as temp:
            output = generate(Path(temp) / "web", 42)
            script = (output / "services/flag-rotator/rotate.sh").read_bytes()
            self.assertTrue(script.startswith(b"#!/bin/sh\n"))
            self.assertNotIn(b"\r\n", script)

    def test_dry_run_and_atomic_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "task.json").write_text('{"dry_run":true,"run_mode":"instance"}')
            task = Task.load({"CTFY_WORK_DIR": str(root), "CTFY_EVAL_DRY_RUN": "1"})
            self.assertTrue(task.dry_run)
            write_result(root, {"stop_reason": "dry_run"})
            self.assertEqual(json.loads((root / "result.json").read_text())["schema_version"], 2)
            self.assertEqual(list(root.glob(".result-*.json")), [])

    def test_missing_model_key_fails_closed(self):
        with self.assertRaises(ModelError):
            Model("openai", "test", "https://model.test/v1", "")

    def test_internal_http_gateway_is_allowed(self):
        # CTFY's evaluation network injects http://ctfy-llm-relay:8081.
        model = Model("openai", "m", "http://ctfy-llm-relay:8081", "gateway-handle")
        self.assertEqual(model.base_url, "http://ctfy-llm-relay:8081")

    def test_public_http_gateway_is_rejected(self):
        for url in ("http://model.example/v1", "http://8.8.8.8/v1"):
            with self.assertRaises(ModelError):
                Model("openai", "m", url, "gateway-handle")

    def test_model_uses_injected_gateway_and_key(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size=-1):
                return b'{"choices":[{"message":{"content":"{\\"action\\":\\"finish\\",\\"reason\\":\\"done\\"}"}}],"usage":{"prompt_tokens":5,"completion_tokens":7}}'

        class Opener:
            request = None

            def open(self, request, timeout):
                self.request = request
                return Response()

        opener = Opener()
        model = Model("openai", "injected-model", "https://model.test/v1", "injected-key", opener=opener)
        self.assertIn("finish", model.complete("rules", [{"role": "user", "content": "task"}]))
        self.assertEqual(opener.request.full_url, "https://model.test/v1/chat/completions")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer injected-key")
        self.assertEqual((model.input_tokens, model.output_tokens), (5, 7))

    def test_platform_poll_hint_precedence(self):
        self.assertEqual(_retry_seconds({"Retry-After": "7"}, {"poll_after_s": 2}, 0), 7)
        self.assertEqual(_retry_seconds({}, {"poll_after_s": 4}, 0), 4)

    def test_get_retries_429_using_header(self):
        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"id":"C-1"}'

        class Opener:
            calls = 0

            def open(self, request, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise urllib.error.HTTPError(request.full_url, 429, "limited", {"Retry-After": "2"},
                                                 io.BytesIO(b'{"code":"rate_limited"}'))
                return Response()

        opener = Opener()
        waits = []
        platform = Platform("https://platform.test", "test-token", opener=opener, sleep=waits.append)
        self.assertEqual(platform.challenge("C-1")["id"], "C-1")
        self.assertEqual(opener.calls, 2)
        self.assertEqual(waits, [2])

    def test_get_retries_remote_disconnected(self):
        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"id":"C-1"}'

        class Opener:
            calls = 0

            def open(self, request, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise http.client.RemoteDisconnected("remote closed")
                return Response()

        opener = Opener()
        waits = []
        platform = Platform("https://platform.test", "test-token", opener=opener, sleep=waits.append)
        self.assertEqual(platform.challenge("C-1")["id"], "C-1")
        self.assertEqual(opener.calls, 2)
        self.assertEqual(waits, [1])

    def test_rejected_capacity_post_can_retry(self):
        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"id":"I-1"}'

        class Opener:
            calls = 0

            def open(self, request, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise urllib.error.HTTPError(request.full_url, 503, "capacity", {},
                                                 io.BytesIO(b'{"code":"capacity_exceeded","retry_after_s":4}'))
                return Response()

        opener = Opener()
        waits = []
        platform = Platform("https://platform.test", "test-token", opener=opener, sleep=waits.append)
        self.assertEqual(platform.start_instance("C-1", "event"), "I-1")
        self.assertEqual(opener.calls, 2)
        self.assertEqual(waits, [4])

    def test_uncertain_post_is_not_retried(self):
        class Opener:
            calls = 0

            def open(self, request, timeout):
                self.calls += 1
                raise urllib.error.URLError("lost response")

        opener = Opener()
        platform = Platform("https://platform.test", "test-token", opener=opener, sleep=lambda n: None)
        with self.assertRaises(PlatformError):
            platform.submit("i", "flag", "candidate")
        self.assertEqual(opener.calls, 1)

    def test_pause_beyond_deadline_is_reported(self):
        class Opener:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 403, "paused", {},
                                             io.BytesIO(b'{"code":"competition_paused","retry_after_s":600}'))

        platform = Platform("https://platform.test", "test-token", deadline=100,
                            opener=Opener(), clock=lambda: 0, sleep=lambda n: self.fail("should not wait"))
        with self.assertRaises(Paused):
            platform.challenge("C-1")

    def test_instance_submission_unlocks_next_question(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = Task(root, {"challenge": {"id": "C-1"}, "questions": [{"id": "flag"}]}, "",
                        "C-1", "event", "instance", False)
            platform = FakePlatform()
            model = FakeModel([
                {"action": "shell", "command": "probe", "why": "observe"},
                {"action": "submit", "question_id": "flag", "answer": "ctfy{ok}", "evidence": "probe output"},
                {"action": "finish", "reason": "next question needs separate work"},
            ])
            snapshots = []
            result = run(task, platform, model, max_turns=3, deadline=10**12,
                         on_update=lambda value: snapshots.append(json.loads(json.dumps(value))),
                         command_tool=lambda command, cwd: {"exit_code": 0, "stdout": "ctfy{ok}"})
            self.assertEqual(platform.started, 1)
            self.assertEqual(platform.submissions, [("flag", "ctfy{ok}")])
            self.assertEqual(result["solved"], ["flag"])
            self.assertEqual(result["answers"], {})
            self.assertTrue(any(s.get("solved") == ["flag"] for s in snapshots))

    def test_qa_submits_without_starting_instance(self):
        class QaPlatform(FakePlatform):
            def challenge(self, challenge_id):
                return {"id": challenge_id, "questions": [{"id": "answer", "prompt": "Pick A", "choices": ["A", "B"]}]}

            def submit_qa(self, challenge_id, competition_id, qid, answer):
                self.submissions.append((qid, answer))
                return {"correct": True, "challenge_fully_solved": True}

        with tempfile.TemporaryDirectory() as temp:
            task = Task(Path(temp), {"challenge": {"id": "Q-1"}}, "", "Q-1", "event", "qa", False)
            platform = QaPlatform()
            model = FakeModel([{"action": "submit", "question_id": "answer", "answer": "A", "evidence": "choice reasoning"},
                               {"action": "finish", "reason": "done"}])
            result = run(task, platform, model, max_turns=2, deadline=10**12, on_update=lambda value: None)
            self.assertEqual(platform.started, 0)
            self.assertEqual(platform.submissions, [("answer", "A")])
            self.assertTrue(result["fully_solved"])


if __name__ == "__main__":
    unittest.main()
