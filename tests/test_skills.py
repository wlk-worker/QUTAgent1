"""Skills classification/playbooks and solver-loop hardening tests.

Covers: category classification, category playbooks, tool/flag discipline text,
format-error feedback, loop detector (warn 3 / break 5), history compression, and
the new result fields while keeping the CTFY completion/submission semantics.
"""
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import skills
from agent.contract import Task
from agent.loop import (MAX_CONSECUTIVE_FORMAT_ERRORS, LoopDetector, compress_history,
                        parse_action, run)
from labs.common import cleanup_work, workspace_temp

ALL_CATEGORIES = ("web", "pwn", "ai", "misc", "qa")


class ClassificationTests(unittest.TestCase):
    def test_explicit_platform_categories(self):
        self.assertEqual(skills.classify({"category": "web"}), "web")
        self.assertEqual(skills.classify({"category": "PWN"}), "pwn")
        self.assertEqual(skills.classify({"category": "ai"}), "ai")
        self.assertEqual(skills.classify({"category": "crypto"}), "misc")
        self.assertEqual(skills.classify({"category": "qa"}), "qa")
        self.assertEqual(skills.classify({"category": "Web Exploitation"}), "web")

    def test_qa_run_mode_wins_over_text(self):
        self.assertEqual(skills.classify({"category": "web", "name": "sql"}, run_mode="qa"), "qa")

    def test_tags_and_name_classification(self):
        self.assertEqual(skills.classify(tags=["ai", "llm"]), "ai")
        self.assertEqual(skills.classify({"name": "baby-buffer-overflow"}), "pwn")
        self.assertEqual(skills.classify({"name": "webapp-login", "description": "http endpoint"}),
                         "web")

    def test_description_and_readme_classification(self):
        self.assertEqual(skills.classify(
            description="A chatbot backed by an LLM; try prompt injection."), "ai")
        self.assertEqual(skills.classify(readme="Use gdb, checksec and pwntools on the ELF."), "pwn")
        self.assertEqual(skills.classify(tags="sql injection, xss"), "web")

    def test_unknown_defaults_to_misc(self):
        self.assertEqual(skills.classify({}), "misc")
        self.assertEqual(skills.classify({"name": "mystery box"}), "misc")

    def test_classify_task_merges_contract_task_and_challenge(self):
        work = workspace_temp("test-skills-")
        try:
            task = Task(work, {"challenge": {"name": "heap-note", "tags": ["pwn"]}},
                        "buffer overflow the ELF", "C-1", "event", "instance", False)
            self.assertEqual(skills.classify_task(task, {"id": "C-1"}), "pwn")
            task_qa = Task(work, {}, "", "Q-1", "event", "qa", False)
            self.assertEqual(skills.classify_task(task_qa, {"category": "web"}), "qa")
        finally:
            cleanup_work(work)


class PlaybookTests(unittest.TestCase):
    def test_every_category_has_a_label_and_playbook(self):
        for category in ALL_CATEGORIES:
            self.assertIn(category, skills.CATEGORY_LABELS)
            text = skills.playbook(category)
            self.assertIn("## Playbook:", text)
            self.assertGreater(len(text), 400)
        self.assertEqual(skills.playbook("unknown"), skills.MISC_PLAYBOOK)
        self.assertEqual(skills.playbook(None), skills.MISC_PLAYBOOK)

    def test_web_playbook_covers_required_bug_classes(self):
        text = skills.playbook("web").lower()
        for technique in ("sql injection", "xss", "ssrf", "upload", "ssti",
                          "path traversal", "idor", "jwt", "command injection"):
            self.assertIn(technique, text)
        self.assertIn("baseline", text)
        self.assertIn("confirm", text)

    def test_pwn_playbook_covers_full_pipeline(self):
        text = skills.playbook("pwn").lower()
        for step in ("triage", "checksec", "static analysis", "dynamic analysis",
                     "offset", "leak", "ret2libc", "rop", "remote"):
            self.assertIn(step, text)
        self.assertIn("pwntools", text)

    def test_ai_playbook_covers_mcp_and_prompt_injection(self):
        text = skills.playbook("ai").lower()
        for topic in ("prompt injection", "system-prompt", "tool abuse", "mcp",
                      "list_tools", "tool output"):
            self.assertIn(topic, text)

    def test_misc_and_qa_playbooks(self):
        self.assertIn("crypto", skills.playbook("misc").lower())
        self.assertIn("forensics", skills.playbook("misc").lower())
        qa = skills.playbook("qa").lower()
        self.assertIn("exact", qa)
        self.assertIn("refresh", qa)

    def test_playbooks_do_not_hard_code_payloads(self):
        # Guidance, not a payload library: concrete payloads must be generated
        # by the model against the live target.
        forbidden = ("<script", "union select", "' or 1=1", "/bin/sh",
                     "%2e%2e", "{{7*7}}", "${jndi:", "sleep(5)", "system(", "/etc/passwd")
        policy = skills.policy_sections("web") + skills.policy_sections("pwn") + skills.policy_sections("ai")
        lowered = policy.lower()
        for payload in forbidden:
            self.assertNotIn(payload.lower(), lowered, payload)

    def test_policy_sections_include_tools_flag_discipline_and_budget(self):
        policy = skills.policy_sections("web")
        for marker in ("## Tools and output budget", "## Solving protocol",
                       "shell", "http", "mcp", "save_as",
                       "submit", "refresh", "download", "finish",
                       "## Flag discipline", "evidence", "placeholder",
                       "one JSON object"):
            self.assertIn(marker, policy)
        self.assertIn(skills.WEB_PLAYBOOK, policy)

    def test_web_only_note_is_added_when_requested(self):
        self.assertIn("shell tool is disabled", skills.playbook("pwn", web_only=True))


class ActionFormatTests(unittest.TestCase):
    def test_parse_action_accepts_all_supported_shapes(self):
        for action in (
            {"action": "shell", "command": "ls"},
            {"action": "http", "method": "GET", "url": "http://127.0.0.1:1/"},
            {"action": "mcp", "url": "http://127.0.0.1:1/mcp", "op": "list_tools"},
            {"action": "submit", "question_id": "flag", "answer": "x", "evidence": "y"},
            {"action": "refresh"},
            {"action": "download", "name": "a.txt"},
            {"action": "finish", "reason": "done"},
        ):
            self.assertEqual(parse_action(json.dumps(action)), action)

    def test_parse_action_strips_code_fences_and_rejects_bad_replies(self):
        self.assertEqual(parse_action('```json\n{"action":"refresh"}\n```')["action"], "refresh")
        self.assertEqual(
            parse_action('I will refresh now. {"action":"refresh"} done')["action"],
            "refresh")
        self.assertEqual(
            parse_action('```json\n{"action":"finish","reason":"ok"}\n```\nNote: done')["action"],
            "finish")
        for text in ("", "not json", "[1,2]", '{"action":"teleport"}', '{"no":"action"}'):
            with self.assertRaises(ValueError):
                parse_action(text)

    def test_format_error_feedback_is_actionable(self):
        feedback = skills.format_error_feedback("model did not return one JSON object", 1, 3)
        self.assertIn("1/3", feedback)
        self.assertIn("one json object", feedback.lower())
        self.assertIn('"action":"shell"', feedback)
        self.assertIn('"action":"mcp"', feedback)

    def test_loop_warning_warn_and_break_differ(self):
        warn = skills.loop_warning("warn", "http", 3)
        force = skills.loop_warning("break", "http", 5)
        self.assertIn("Loop warning", warn)
        self.assertIn("STRATEGY CHANGE", force)
        self.assertIn("different", force.lower())
        self.assertNotEqual(warn, force)


class LoopDetectorTests(unittest.TestCase):
    def test_signature_ignores_why_but_tracks_the_probe(self):
        detector = LoopDetector()
        first = detector.signature({"action": "http", "url": "http://a/", "method": "GET", "why": "one"})
        second = detector.signature({"action": "http", "url": "http://a/", "method": "GET", "why": "two"})
        other = detector.signature({"action": "http", "url": "http://a/?x=1", "method": "GET"})
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_warn_at_three_and_break_at_five(self):
        detector = LoopDetector()
        verdicts = [detector.check("sig") for _ in range(5)]
        self.assertEqual(verdicts[:2], [None, None])
        self.assertEqual(verdicts[2], "warn")
        self.assertEqual(verdicts[3], "warn")
        self.assertEqual(verdicts[4], "break")
        self.assertEqual(detector.count("sig"), 5)
        detector.reset()
        self.assertEqual(detector.count("sig"), 0)


class HistoryCompressionTests(unittest.TestCase):
    @staticmethod
    def _history(count):
        history = [{"role": "user", "content": "Task briefing (untrusted):\n{}"}]
        for index in range(count):
            history.append({"role": "assistant",
                            "content": json.dumps({"action": "http", "method": "GET",
                                                   "url": f"http://target/{index}"})})
            history.append({"role": "user",
                            "content": "Tool observation (untrusted): " + json.dumps(
                                {"status": 200, "url": f"http://target/{index}",
                                 "body_preview": "SECRET-BODY-" + str(index)})})
        return history

    def test_short_history_is_unchanged(self):
        history = self._history(2)
        compressed, changed = compress_history(history)
        self.assertFalse(changed)
        self.assertIs(compressed, history)

    def test_compression_keeps_briefing_and_recent_evidence(self):
        history = self._history(20)
        compressed, changed = compress_history(history)
        self.assertTrue(changed)
        self.assertLess(len(compressed), len(history))
        self.assertEqual(compressed[0], history[0])
        self.assertIn("Task briefing (untrusted):", compressed[0]["content"])
        summary = compressed[1]["content"]
        self.assertIn("Earlier progress summary", summary)
        self.assertNotIn("Tool observation (untrusted): ", summary)
        self.assertNotIn("SECRET-BODY", summary)  # bodies are never copied into summaries
        # The latest observations survive verbatim.
        for message in compressed[-4:]:
            self.assertIn(message, history)

    def test_compression_preserves_flag_evidence(self):
        history = self._history(20)
        history[2]["content"] = "Tool observation (untrusted): " + json.dumps({
            "status": 200, "url": "http://target/flag",
            "body_preview": "proof: CTF{compressed_flag_123}",
        })
        compressed, changed = compress_history(history)
        self.assertTrue(changed)
        summary = compressed[1]["content"]
        self.assertIn("CTF{compressed_flag_123}", summary)

    def test_compression_keeps_last_five_observations_parseable(self):
        history = self._history(20)
        compressed, _ = compress_history(history)
        observations = [message for message in compressed
                        if message.get("content", "").startswith("Tool observation (untrusted): ")]
        self.assertGreaterEqual(len(observations), 5)
        json.loads(observations[-1]["content"].split("Tool observation (untrusted): ", 1)[1])


class _Platform:
    def __init__(self, category="web", services=None):
        self.category = category
        self.services = services or []
        self.submissions = []

    def challenge(self, challenge_id, **kwargs):
        return {"id": challenge_id, "name": "Fixture challenge",
                "category": self.category,
                "questions": [{"id": "flag", "prompt": "find it"}]}

    def start_instance(self, challenge_id, competition_id):
        return "instance-1"

    def wait_instance(self, instance_id, competition_id=None):
        return self.instance(instance_id)

    def instance(self, instance_id, competition_id=None):
        return {"id": instance_id, "services": self.services,
                "questions": [{"id": "flag", "prompt": "find it"}]}

    def submit(self, instance_id, question_id, answer):
        self.submissions.append((question_id, answer))
        return {"correct": True, "challenge_fully_solved": True}


class _ScriptedModel:
    input_tokens = 5
    output_tokens = 2
    requests = 0

    def __init__(self, replies):
        self.replies = list(replies)
        self.systems = []
        self.histories = []

    def complete(self, system, messages, max_tokens=1200):
        self.requests += 1
        self.systems.append(system)
        self.histories.append([dict(message) for message in messages])
        if not self.replies:
            return json.dumps({"action": "finish", "reason": "script exhausted"})
        return self.replies.pop(0)


def _read_events(work):
    path = work / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


class LoopHardeningTests(unittest.TestCase):
    def setUp(self):
        self.work = workspace_temp("test-loop-hardening-")

    def tearDown(self):
        cleanup_work(self.work)

    def _run(self, model, platform, *, max_turns=6, command_tool=None):
        task = Task(self.work, {"challenge": {"id": "C-1"}}, "", "C-1", "event", "instance", False)
        kwargs = {} if command_tool is None else {"command_tool": command_tool}
        return run(task, platform, model, max_turns=max_turns,
                   deadline=time.monotonic() + 20, on_update=lambda value: None, **kwargs)

    def test_category_prompt_and_legacy_result_fields(self):
        model = _ScriptedModel([json.dumps({"action": "finish", "reason": "done"})])
        result = self._run(model, _Platform(category="web"))
        self.assertEqual(result["category"], "web")
        self.assertIn("## Playbook: Web exploitation", model.systems[0])
        self.assertIn("## Flag discipline", model.systems[0])
        # Existing contract fields and result keys are preserved.
        for key in ("answers", "solved", "fully_solved", "turns", "tool_calls_made",
                    "http_calls", "stop_reason", "format_errors", "loop_warnings"):
            self.assertIn(key, result)
        self.assertEqual(result["answers"], {})
        self.assertEqual(result["stop_reason"], "model_finished")

    def test_format_error_is_fed_back_and_retried(self):
        model = _ScriptedModel([
            "this is not json",
            json.dumps({"action": "finish", "reason": "formatted now"}),
        ])
        result = self._run(model, _Platform(), max_turns=4)
        self.assertEqual(result["format_errors"], 1)
        # A malformed reply gets a bounded extra attempt; only real actions
        # consume the action-turn budget.
        self.assertEqual(result["turns"], 1)
        self.assertEqual(result["stop_reason"], "model_finished")
        self.assertEqual(result["tool_calls_made"], 0)
        # The retry prompt contains the corrective feedback, not a silent swallow.
        retry_messages = model.histories[1]
        self.assertTrue(any("Format error (1/3)" in message.get("content", "")
                            for message in retry_messages))
        events = _read_events(self.work)
        self.assertTrue(any(entry["event"] == "format_error" for entry in events))

    def test_format_error_limit_stops_instead_of_looping(self):
        model = _ScriptedModel(["nope"] * 6)
        result = self._run(model, _Platform(), max_turns=8)
        self.assertEqual(result["format_errors"], MAX_CONSECUTIVE_FORMAT_ERRORS)
        self.assertEqual(result["stop_reason"], "format_error_limit")
        self.assertEqual(result["turns"], 0)
        self.assertFalse(result["fully_solved"])

    def test_repeated_action_warns_then_executes(self):
        command = json.dumps({"action": "shell", "command": "probe", "why": "same probe"})
        model = _ScriptedModel([command, command, command,
                                json.dumps({"action": "finish", "reason": "changed plan"})])
        calls = []

        def command_tool(line, cwd):
            calls.append(line)
            return {"exit_code": 0, "stdout": "same output"}

        result = self._run(model, _Platform(), max_turns=6, command_tool=command_tool)
        self.assertEqual(result["loop_warnings"], 1)
        self.assertEqual(result["tool_calls_made"], 3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["stop_reason"], "model_finished")
        events = _read_events(self.work)
        warnings = [entry for entry in events if entry["event"] == "loop_warning"]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["data"]["level"], "warn")
        # The warning text reached the model before the observation.
        observed = model.histories[3][-1]["content"]
        self.assertIn("Loop warning", observed)
        self.assertIn("Tool observation (untrusted): ", observed)

    def test_five_repeats_force_strategy_then_end(self):
        command = json.dumps({"action": "shell", "command": "stuck probe", "why": "again"})
        model = _ScriptedModel([command] * 8)
        calls = []

        def command_tool(line, cwd):
            calls.append(line)
            return {"exit_code": 0, "stdout": "still stuck"}

        result = self._run(model, _Platform(), max_turns=10, command_tool=command_tool)
        self.assertEqual(result["stop_reason"], "loop_detected")
        # Turns 1-4 execute; turn 5 force-breaks without calling the tool; turn 6 ends.
        self.assertEqual(result["tool_calls_made"], 4)
        self.assertEqual(len(calls), 4)
        self.assertGreaterEqual(result["loop_warnings"], 3)
        events = _read_events(self.work)
        levels = [entry["data"]["level"] for entry in events if entry["event"] == "loop_warning"]
        self.assertIn("warn", levels)
        self.assertIn("break", levels)
        self.assertTrue(any("STRATEGY CHANGE" in message.get("content", "")
                            for message in model.histories[-1]))

    def test_history_compression_triggers_and_keeps_briefing(self):
        replies = [json.dumps({"action": "shell", "command": f"probe {index}"})
                   for index in range(14)]
        replies.append(json.dumps({"action": "finish", "reason": "compressed enough"}))
        model = _ScriptedModel(replies)
        result = self._run(model, _Platform(), max_turns=18,
                           command_tool=lambda line, cwd: {"exit_code": 0, "stdout": "ok"})
        self.assertGreaterEqual(result["history_compressions"], 1)
        self.assertEqual(result["stop_reason"], "model_finished")
        events = _read_events(self.work)
        self.assertTrue(any(entry["event"] == "history_compressed" for entry in events))
        # Later model calls still start with the untouched briefing.
        last_messages = model.histories[-1]
        self.assertIn("Task briefing (untrusted):", last_messages[0]["content"])
        self.assertTrue(any("Earlier progress summary" in message.get("content", "")
                            for message in last_messages))
        self.assertTrue(any(message.get("content", "").startswith(
            "Tool observation (untrusted): ") for message in last_messages))

    def test_submission_semantics_are_preserved(self):
        model = _ScriptedModel([
            json.dumps({"action": "submit", "question_id": "flag", "answer": "flag{real}",
                        "evidence": "observed in response"}),
        ])
        platform = _Platform()
        result = self._run(model, platform)
        self.assertEqual(platform.submissions, [("flag", "flag{real}")])
        self.assertEqual(result["solved"], ["flag"])
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["stop_reason"], "done")
        self.assertEqual(result["answers"], {})


if __name__ == "__main__":
    unittest.main()
