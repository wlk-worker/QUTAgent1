import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.budget import BudgetExpired
from agent.contract import Task, write_result
from agent.loop import run
from agent.model import Model, ModelError
from agent.platform import Platform, PlatformError
from agent.security import command_environment
from agent.state import assess
from agent.tools import shell


class ReliabilityTests(unittest.TestCase):
    def test_exhausted_locked_and_unknown_are_not_complete(self):
        for question in ({"id": "f", "attempts_remaining": 0}, {"id": "f", "unlocked": False}):
            result = assess({}, {}, {"questions": [question]}, [])
            self.assertFalse(result["fully_solved"])
        self.assertFalse(assess({}, {}, {}, [])["fully_solved"])

    def test_hidden_questions_and_verified_completion(self):
        info = {"questions": [{"id": "f", "answered_correctly": True}]}
        self.assertFalse(assess({"gated_questions": 1}, {}, info, [])["fully_solved"])
        self.assertTrue(assess({"gated_questions": 0}, {}, info, [])["fully_solved"])
        self.assertTrue(assess({}, {}, {}, ["f"], True)["fully_solved"])
        self.assertEqual(assess({}, {}, {"questions": [{"id": "f", "answered_correctly": False}]}, ["f"])["solved"], ["f"])

    def test_model_finish_and_qa_state(self):
        class P:
            def challenge(self, _, **kwargs): return {"questions": [{"id": "a", "prompt": "A"}]}
        class M:
            input_tokens = output_tokens = 0
            def complete(self, *args): return '{"action":"finish"}'
        with tempfile.TemporaryDirectory() as d:
            task = Task(Path(d), {}, "", "q", "c", "qa", False)
            result = run(task, P(), M(), max_turns=1, deadline=time.monotonic()+1, on_update=lambda _: None)
        self.assertEqual(result["stop_reason"], "model_finished")
        self.assertFalse(result["fully_solved"])

    def test_qa_requires_platform_confirmation(self):
        class P:
            correct = False
            def challenge(self, _, **kwargs):
                return {"questions": [{"id": "a", "prompt": "A", "answered_correctly": self.correct}]}
            def submit_qa(self, *args):
                self.correct = True
                return {"correct": True, "challenge_fully_solved": True}
        class M:
            input_tokens = output_tokens = 0
            def complete(self, *args):
                return '{"action":"submit","question_id":"a","answer":"A","evidence":"fixture"}'
        with tempfile.TemporaryDirectory() as d:
            task = Task(Path(d), {}, "", "q", "c", "qa", False)
            result = run(task, P(), M(), max_turns=2, deadline=time.monotonic()+2, on_update=lambda _: None)
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["stop_reason"], "done")

    def test_allowlist_and_saved_output_redaction(self):
        values = {name: "fictional-value-"+str(i) for i, name in enumerate(
            ["CTFY_TOKEN", "LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OTHER_PASSWORD"])}
        with patch.dict(os.environ, {**values, "PATH": os.environ.get("PATH", "")}), tempfile.TemporaryDirectory() as d:
            self.assertFalse(set(values) & set(command_environment()))
            write_result(Path(d), {"error": " ".join(values.values())})
            saved = (Path(d)/"result.json").read_text()
            self.assertFalse(any(v in saved for v in values.values()))

    def test_slow_model_and_platform_include_body_in_deadline(self):
        class Response:
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self, n=-1):
                time.sleep(.25)
                return b'{}'
        class Opener:
            def open(self, req, timeout): return Response()
        for kind in ("model", "platform", "attachment"):
            start = time.monotonic()
            deadline = start+.06
            with self.assertRaises(BudgetExpired):
                if kind == "model":
                    Model("openai", "test", "http://localhost", "fake", opener=Opener(), deadline=deadline).complete("s", [])
                elif kind == "platform":
                    Platform("http://localhost", "fake", opener=Opener(), deadline=deadline).challenge("c")
                else:
                    Platform("http://localhost", "fake", opener=Opener(), deadline=deadline).download_attachment("c", "a")
            self.assertLess(time.monotonic()-start, .2)

    def test_model_retry_and_request_cap(self):
        class Opener:
            def open(self, req, timeout):
                raise urllib.error.HTTPError(req.full_url, 429, "rate", {}, io.BytesIO())
        with self.assertRaises(BudgetExpired):
            Model("openai", "test", "http://localhost", "fake", opener=Opener(), deadline=time.monotonic()+.05).complete("s", [])
        # ``max_requests`` caps logical completions; the same completion may use
        # a bounded number of HTTP retries without consuming another turn.
        model = Model("openai", "test", "http://localhost", "fake", opener=Opener(),
                      max_requests=1, sleep=lambda _:None)
        with self.assertRaises(ModelError):
            model.complete("s", [])
        self.assertEqual(model.logical_requests, 1)
        self.assertLessEqual(model.requests, 4)

    def test_uncertain_mutation_is_reported_once(self):
        class Opener:
            calls = 0
            def open(self, req, timeout):
                self.calls += 1
                time.sleep(.2)
                return None
        opener = Opener()
        platform = Platform("http://localhost", "fake", opener=opener, deadline=time.monotonic()+.03)
        with self.assertRaises(PlatformError) as raised:
            platform.submit("i", "f", "candidate")
        self.assertEqual(raised.exception.code, "mutation_outcome_unknown")
        self.assertEqual(opener.calls, 1)

    @unittest.skipUnless(os.name == "posix", "Linux process groups")
    def test_shell_limits_environment_and_process_group(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"ANTHROPIC_AUTH_TOKEN":"fictional-sensitive-value"}):
            good = shell("printf ok; printf err >&2", Path(d))
            self.assertEqual((good["exit_code"], good["stdout"], good["stderr"]), (0, "ok", "err"))
            env = shell("env", Path(d))
            self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env["stdout"])
            large = shell("python3 -c 'import sys; sys.stdout.write(\"x\"*2000000)'", Path(d), output_limit=1024)
            self.assertTrue(large["truncated"])
            self.assertLessEqual(large["captured_bytes"], 2048)
            failed = shell("exit 7", Path(d))
            self.assertEqual(failed["exit_code"], 7)
            timed = shell("sleep 60 & echo $! > child.pid; wait", Path(d), timeout_s=.15)
            self.assertEqual(timed["error"], "timeout")
            self.assertTrue(timed["timed_out"])
            pid = int((Path(d)/"child.pid").read_text())
            status = Path(f"/proc/{pid}/stat")
            self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z")
            self.assertLess(timed["elapsed_s"], 1.5)
