"""End-to-end tests for the process-isolated Web lab: fake model closure, budgets,
blocked real-model path, dynamic per-run flags and process-level target behavior.
"""
import hashlib
import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from labs.common import (
    cleanup_work, spawn_module, stop_process, wait_ready, workspace_temp,
)
from labs.runner import (
    EXPERIMENTS, _agent_environment, _credentials, run_experiment,
)

RAW_FLAG = re.compile(r"flag\{[0-9a-fA-F]{16,}\}")

CLEAN_ENV = {key: value for key, value in os.environ.items()
             if not key.upper().startswith(("LLM_", "CTFY_", "OPENAI_", "ANTHROPIC_"))}


class LabChainTests(unittest.TestCase):
    def setUp(self):
        self.out = workspace_temp("test-lab-")

    def tearDown(self):
        cleanup_work(self.out)

    def test_fake_model_full_chain_and_evidence(self):
        experiment, code = run_experiment(
            "fake", "dev", out_dir=self.out, seeds=[101], environ=CLEAN_ENV)
        self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
        self.assertEqual(experiment["status"], "completed")
        self.assertEqual(experiment["summary"]["succeeded"], 1)
        self.assertEqual(experiment["summary"]["total"], 1)
        case = experiment["cases"][0]
        self.assertTrue(case["success"])
        self.assertTrue(case["platform_accepted_flag"])
        self.assertEqual(case["stop_reason"], "done")
        self.assertTrue(case["fully_solved"])
        self.assertGreaterEqual(case["submission_count"], 1)
        self.assertGreaterEqual(case["correct_submission_count"], 1)
        self.assertEqual(len(case["flag_sha256"]), 64)
        self.assertGreater(case["tokens"]["input"], 0)
        self.assertGreater(case["tokens"]["output"], 0)
        self.assertGreater(case["http_calls"], 0)

        for key in ("task_json", "result_json", "events_jsonl", "submissions_jsonl",
                    "target_requests", "model_calls"):
            relative = case["evidence"].get(key)
            self.assertTrue(relative, f"missing evidence {key}")
            self.assertTrue((ROOT / relative).exists(), f"evidence file missing: {relative}")

        # The accepted submission log records only a hash of the answer.
        submissions = [json.loads(line) for line in
                       (ROOT / case["evidence"]["submissions_jsonl"]).read_text().splitlines()]
        self.assertEqual(len(submissions), 1)
        self.assertTrue(submissions[0]["correct"])
        self.assertNotIn("answer", submissions[0])
        self.assertEqual(submissions[0]["answer_sha256"], case["flag_sha256"])

        # Events show the HTTP path and never contain the raw flag.
        events = [json.loads(line) for line in
                  (ROOT / case["evidence"]["events_jsonl"]).read_text().splitlines()
                  if line.strip()]
        actions = [entry["data"] for entry in events if entry["event"] == "action"]
        self.assertGreaterEqual(sum(1 for action in actions if action.get("action") == "http"), 2)
        self.assertFalse(any(action.get("action") == "shell" for action in actions))
        for path in (ROOT / case["evidence"]["result_json"]).parent.glob("*"):
            if path.is_file():
                self.assertIsNone(RAW_FLAG.search(path.read_text(encoding="utf-8", errors="replace")),
                                  f"raw flag leaked into {path}")

        # experiment.json is directly inspectable evidence.
        experiment_json = self.out / "experiment.json"
        self.assertTrue(experiment_json.exists())
        saved = json.loads(experiment_json.read_text(encoding="utf-8"))
        self.assertEqual(saved["summary"]["succeeded"], 1)
        self.assertFalse(saved["evidence"]["flag_values_stored"])

    def test_turn_budget_stops_case_without_fabricating_success(self):
        experiment, code = run_experiment(
            "fake", "dev", out_dir=self.out, seeds=[102], max_turns=1, environ=CLEAN_ENV)
        self.assertEqual(code, 1)
        case = experiment["cases"][0]
        self.assertFalse(case["success"])
        self.assertFalse(case["platform_accepted_flag"])
        self.assertEqual(case["submission_count"], 0)
        self.assertEqual(case["stop_reason"], "turn_limit")
        self.assertLess(case["wall_seconds"], EXPERIMENTS["dev"]["timeout_s"] + 30)

    def test_real_model_without_credentials_is_blocked_not_failed(self):
        experiment, code = run_experiment(
            "real", "validation", out_dir=self.out, seeds=[201], environ={})
        self.assertEqual(code, 2)
        self.assertEqual(experiment["status"], "blocked")
        self.assertEqual(experiment["cases"], [])
        blocked = experiment["blocked"]
        self.assertEqual(blocked["reason"], "missing_credentials")
        self.assertIn("LLM_API_KEY", blocked["missing"])
        self.assertEqual(experiment["summary"]["succeeded"], 0)
        self.assertIn("--model real", blocked["rerun"])
        saved = json.loads((self.out / "experiment.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "blocked")

    def test_real_model_flavor_is_forwarded_not_hardcoded(self):
        # Regression: --model real with LLM_FLAVOR=anthropic must reach
        # agent.model.Model as anthropic, not the fake-openai default.
        budget = {"timeout_s": 5, "max_turns": 3, "max_requests": 4}
        for flavor in ("openai", "anthropic"):
            env = _agent_environment(
                Path("."), "http://127.0.0.1:9", "fixture-token",
                model_mode="real", model_flavor=flavor,
                model_base_url="https://gateway.example/v1",
                model_name="fixture-model", model_key="fixture-model-key", budget=budget)
            self.assertEqual(env["LLM_FLAVOR"], flavor)
            self.assertEqual(env["LLM_BASE_URL"], "https://gateway.example/v1")
            self.assertEqual(env["LLM_API_KEY"], "fixture-model-key")
            self.assertEqual(env["QUT_WEB_ONLY"], "1")
        fake_env = _agent_environment(
            Path("."), "http://127.0.0.1:9", "fixture-token",
            model_mode="fake", model_flavor="openai", model_base_url="http://127.0.0.1:9/v1",
            model_name="fake-lab-model", model_key="fake-model-key", budget=budget)
        self.assertEqual(fake_env["LLM_FLAVOR"], "openai")

    def test_credentials_validate_flavor_and_report_missing_fields(self):
        values, missing, issue = _credentials({
            "LLM_FLAVOR": "anthropic", "LLM_MODEL": "m", "LLM_API_KEY": "k"})
        self.assertEqual((missing, issue), ([], None))
        self.assertEqual(values["LLM_FLAVOR"], "anthropic")
        _, missing, issue = _credentials({})
        self.assertEqual(issue, "missing_credentials")
        self.assertEqual(missing, ["LLM_FLAVOR", "LLM_MODEL", "LLM_API_KEY"])
        _, _, issue = _credentials({
            "LLM_FLAVOR": "bogus", "LLM_MODEL": "m", "LLM_API_KEY": "k"})
        self.assertEqual(issue, "unsupported_llm_flavor")


class TargetProcessTests(unittest.TestCase):
    def _start_target(self, work: Path, seed: int = 701):
        ready = work / f"target-{seed}.json"
        process, handle = spawn_module(
            "labs.target",
            ["--root", str(work / f"root-{seed}"), "--ready-file", str(ready),
             "--log", str(work / f"target-{seed}.jsonl"), "--seed", str(seed)],
            stderr_path=work / f"target-{seed}.stderr")
        info = wait_ready(ready, timeout_s=20, process=process)
        return process, handle, info

    def test_flags_differ_per_process_and_traversal_needs_encoding(self):
        work = workspace_temp("test-target-")
        processes = []
        try:
            infos = []
            for seed in (701, 702):
                process, handle, info = self._start_target(work, seed)
                processes.append((process, handle))
                infos.append(info)
            self.assertNotEqual(infos[0]["flag_sha256"], infos[1]["flag_sha256"])

            first = infos[0]
            origin = first["origin"]
            # Literal traversal is blocked by the naive prefix check.
            with self.assertRaises(urllib.error.HTTPError) as blocked:
                urllib.request.urlopen(origin + "/download?name=..%2fprivate%2fflag.txt", timeout=5)
            self.assertEqual(blocked.exception.code, 403)
            blocked.exception.close()
            # Encoded traversal reaches the private flag outside the public root.
            body = urllib.request.urlopen(
                origin + "/download?name=%2e%2e/private/flag.txt", timeout=5).read().decode()
            flag = body.strip()
            self.assertIsNotNone(RAW_FLAG.fullmatch(flag))
            self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(), first["flag_sha256"])
            # The literal public-file route cannot traverse.
            with self.assertRaises(urllib.error.HTTPError) as literal:
                urllib.request.urlopen(origin + "/files/%2e%2e%2fprivate%2fflag.txt", timeout=5)
            literal.exception.close()
        finally:
            for process, handle in reversed(processes):
                stop_process(process)
                handle.close()
            cleanup_work(work)

    def test_target_home_page_documents_the_legacy_download_endpoint(self):
        # Discovery evidence is HTTP-only: no shell, WSL or Docker is needed.
        work = workspace_temp("test-target-shell-")
        try:
            process, handle, info = self._start_target(work, 703)
            try:
                page = urllib.request.urlopen(info["origin"] + "/", timeout=5).read().decode()
                self.assertIn("download", page)
                self.assertIn("private", page)
            finally:
                stop_process(process)
                handle.close()
        finally:
            cleanup_work(work)


if __name__ == "__main__":
    unittest.main()
