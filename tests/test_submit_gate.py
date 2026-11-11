"""Submit/finish gate regressions: MMLU-CS-0011, SECQA-0132, SECQA-0148.

The three incidents behind these gates are replayed against stub platforms, so
the tests fail if a future change lets a malformed answer consume an attempt, a
fabricated success claim end a run, or a confirmed success be relabelled.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import gate  # noqa: E402
from agent.contract import Task  # noqa: E402
from agent.loop import _brief, run  # noqa: E402
from agent.platform import Platform, PlatformError  # noqa: E402

# The MMLU-CS-0011 payload: choices are letters, the option sentences live in
# the description.  Submitting a sentence is the mistake that cost an attempt.
MMLU_DESCRIPTION = (
    "An integer overflow occurs when\n\n"
    "A) an integer expression's result \"wraps around\"; instead of creating a very large number, "
    "a very small (or negative) number ends up getting created\n"
    "B) an integer is used as if it was a pointer\n"
    "C) an integer is used to access a buffer outside of the buffer's bounds\n"
    "D) there is no more space to hold integers in the program\n"
)
MMLU_QUESTION = {
    "id": "answer",
    "prompt": "Select the correct option (letter A/B/C/D).",
    "mode": "single_select",
    "choices": ["A", "B", "C", "D"],
    "requires": [],
}
OPTION_A_SENTENCE = (
    "an integer expression's result \"wraps around\"; instead of creating a very large number, "
    "a very small (or negative) number ends up getting created"
)


def mmlu_task(root: Path, run_mode: str = "qa") -> Task:
    raw = {
        "run_mode": run_mode,
        "competition_id": "event",
        "challenge": {"id": "MMLU-CS-0011", "description": MMLU_DESCRIPTION},
        "questions": [MMLU_QUESTION],
    }
    return Task(root, raw, "", "MMLU-CS-0011", "event", run_mode, False)


class ScriptedModel:
    """Replays a fixed action list; every action is a real JSON reply."""

    input_tokens = 11
    output_tokens = 7

    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = 0

    def complete(self, system, messages, max_tokens=1200):
        action = self.actions[min(self.calls, len(self.actions) - 1)]
        self.calls += 1
        return json.dumps(action)


class QaPlatform:
    """Stub CTFy QA endpoint: grades against a fixed key, caps attempts."""

    def __init__(self, key="C", attempts=3, fully_solved=True, refresh_error=None,
                 verdict_extra=None, extra_questions=(), forget=False):
        self.key = key
        self.attempts = attempts
        self.fully_solved = fully_solved
        self.refresh_error = refresh_error
        self.verdict_extra = verdict_extra or {}
        self.extra_questions = list(extra_questions)
        self.forget = forget
        self.submissions = []
        self.solved = False
        self.challenge_calls = 0

    def _questions(self):
        rows = [{
            **MMLU_QUESTION,
            "answered_correctly": self.solved and not self.forget,
            "attempts_remaining": self.attempts,
        }]
        for qid in self.extra_questions:
            rows.append({"id": qid, "prompt": "next question", "mode": "single_select",
                         "choices": ["A", "B"], "unlocked": True,
                         "answered_correctly": False, "attempts_remaining": 2})
        return rows

    def challenge(self, challenge_id, **kwargs):
        self.challenge_calls += 1
        if self.refresh_error is not None and self.challenge_calls > 1:
            raise self.refresh_error
        return {
            "id": challenge_id,
            "description": MMLU_DESCRIPTION,
            "questions": self._questions(),
            "challenge_fully_solved": self.solved and not self.forget,
            "gated_questions": 0,
        }

    def submit_qa(self, challenge_id, competition_id, question_id, answer):
        self.submissions.append(answer)
        if question_id != "answer":
            return {"correct": False, "attempts_remaining": 2}
        correct = str(answer) == self.key
        if correct:
            self.solved = True
        else:
            self.attempts = max(0, self.attempts - 1)
        return {"correct": correct, "challenge_fully_solved": self.solved and self.fully_solved,
                "attempts_remaining": self.attempts, **self.verdict_extra}


def run_task(task, platform, actions, max_turns):
    model = ScriptedModel(actions)
    snapshots = []
    result = run(task, platform, model, max_turns=max_turns, deadline=10 ** 12,
                 on_update=lambda value: snapshots.append(json.loads(json.dumps(value))))
    return result, snapshots


class SubmissionGateTests(unittest.TestCase):
    """Pure gate rules; no server, no clock."""

    def test_single_select_accepts_only_declared_values(self):
        ok = gate.check_submission(MMLU_QUESTION, "a", "quoted option reasoning")
        self.assertTrue(ok.ok)
        self.assertEqual(ok.value, "A")  # normalized, not paraphrased
        self.assertEqual(gate.check_submission(MMLU_QUESTION, "option C", "ev").value, "C")
        self.assertEqual(gate.check_submission(MMLU_QUESTION, "(D)", "ev").value, "D")
        for bad in ("E", "the integer wraps around", "", None):
            decision = gate.check_submission(MMLU_QUESTION, bad, "ev")
            self.assertFalse(decision.ok, bad)
            self.assertEqual(decision.code, "answer_not_in_choices")
            self.assertIn("no attempt was consumed", decision.instruction)

    def test_option_sentence_maps_to_its_letter(self):
        # MMLU-CS-0011 submitted this sentence; it is the same choice as "A",
        # so it must be recognized (and then caught as a duplicate), not sent.
        options = gate.option_map(MMLU_DESCRIPTION)
        decision = gate.check_submission(MMLU_QUESTION, OPTION_A_SENTENCE, "ev", options=options)
        self.assertTrue(decision.ok)
        self.assertEqual(decision.value, "A")
        self.assertEqual(gate.resolve_choice("B) an integer is used as if it was a pointer",
                                            gate.choice_pairs(MMLU_QUESTION), options), "B")

    def test_single_select_rejects_a_list(self):
        decision = gate.check_submission(MMLU_QUESTION, ["A", "B"], "ev")
        self.assertFalse(decision.ok)
        self.assertEqual(decision.code, "answer_not_single")

    def test_multi_select_is_canonicalised(self):
        question = {"id": "answer", "mode": "multi_select", "choices": ["A", "B", "C", "D"]}
        decision = gate.check_submission(question, ["c", "a"], "quoted reasoning")
        self.assertTrue(decision.ok)
        self.assertEqual(decision.value, ["A", "C"])
        self.assertFalse(gate.check_submission(question, ["A", "E"], "ev").ok)

    def test_text_answer_rejects_placeholders(self):
        question = {"id": "flag", "prompt": "Find the flag", "mode": "text"}
        self.assertTrue(gate.check_submission(question, "ctfy{real}", "GET /x -> ctfy{real}").ok)
        for bad in ("flag{...}", "TODO", "n/a"):
            decision = gate.check_submission(question, bad, "observed")
            self.assertFalse(decision.ok, bad)
            self.assertEqual(decision.code, "answer_placeholder")

    def test_evidence_must_add_information(self):
        question = {"id": "flag", "prompt": "Find the flag"}
        self.assertFalse(gate.check_submission(question, "ctfy{x}", "").ok)
        self.assertEqual(gate.check_submission(question, "ctfy{x}", "  ").code, "evidence_missing")
        self.assertEqual(gate.check_submission(question, "ctfy{x}", "n/a").code, "evidence_generic")
        self.assertEqual(gate.check_submission(question, "ctfy{x}", "ctfy{x}").code, "evidence_is_answer")
        self.assertEqual(gate.check_submission(question, "x" * 5000, "ev").code, "answer_too_long")

    def test_answer_format_is_declared_in_the_briefing(self):
        with tempfile.TemporaryDirectory() as temp:
            task = mmlu_task(Path(temp))
        brief = json.loads(_brief(task, None, {"description": MMLU_DESCRIPTION}))
        question = brief["questions"][0]
        self.assertEqual(question["mode"], "single_select")
        self.assertEqual(question["choices"], ["A", "B", "C", "D"])
        self.assertIn("exactly one choice value", question["answer_format"])
        self.assertIn("never the option sentence", question["answer_format"])

    def test_verdict_requires_an_explicit_boolean_true(self):
        self.assertTrue(gate.validate_verdict({"correct": True}, "answer").correct)
        self.assertFalse(gate.validate_verdict({"correct": False}, "answer").correct)
        for payload, problem in (({"correct": "false"}, "verdict_correct_not_boolean"),
                                 ({"correct": 1}, "verdict_correct_not_boolean"),
                                 ({}, "verdict_missing_correct"),
                                 (["correct"], "verdict_not_an_object")):
            verdict = gate.validate_verdict(payload, "answer")
            self.assertFalse(verdict.correct, payload)
            self.assertIn(problem, verdict.problems)
        mismatch = gate.validate_verdict({"correct": True, "question_id": "other"}, "answer")
        self.assertFalse(mismatch.correct)
        self.assertIn("verdict_question_mismatch", mismatch.problems)
        reconciled = gate.validate_verdict({"correct": True}, "answer", reconciled=True)
        self.assertEqual(reconciled.basis, "reconciled_get")
        self.assertEqual(gate.validate_verdict({"correct": False, "attempts_remaining": "2"},
                                              "answer").attempts_remaining, None)

    def test_success_claim_detection_matches_the_incident_wording(self):
        self.assertTrue(gate.claims_success(
            "SECQA-0132 solved: answer C (Malware Injection) was accepted with challenge_fully_solved=true."))
        self.assertTrue(gate.claims_success("flag accepted by the platform"))
        self.assertTrue(gate.claims_success("task complete; the flag was correct"))
        self.assertFalse(gate.claims_success("next question needs separate work"))
        self.assertFalse(gate.claims_success("all traversal encodings rejected"))
        self.assertFalse(gate.claims_success("target unreachable after retries"))
        # Failure reports must not be treated as claims, or an honest finish
        # would be pushed back and then mislabelled.
        self.assertFalse(gate.claims_success("could not solve the challenge"))
        self.assertFalse(gate.claims_success("unable to solve; no checker mode available"))
        self.assertFalse(gate.claims_success("the platform rejected my answer; not solved"))
        self.assertFalse(gate.claims_success(""))
        self.assertFalse(gate.claims_success(None))


class MmluRegressionTests(unittest.TestCase):
    """MMLU-CS-0011: an option sentence must not consume an attempt."""

    def test_option_sentence_is_rejected_locally_as_a_duplicate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C")
            actions = [
                {"action": "submit", "question_id": "answer", "answer": "A",
                 "evidence": "option A is the wrap-around definition"},
                # The incident's second submission: the same option as a sentence.
                {"action": "submit", "question_id": "answer", "answer": OPTION_A_SENTENCE,
                 "evidence": "quoted MMLU key text"},
                {"action": "submit", "question_id": "answer", "answer": "C",
                 "evidence": "buffer-bound access is the memory-safety wording"},
            ]
            result, snapshots = run_task(task, platform, actions, max_turns=4)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]

        # The sentence never reached the platform: only A and C were graded.
        self.assertEqual(platform.submissions, ["A", "C"])
        self.assertEqual(result["submit_rejections"], 1)
        self.assertEqual(result["rejection_codes"]["duplicate_submission"], 1)
        self.assertTrue(result["solved"] == ["answer"])
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["stop_reason"], "done")
        self.assertTrue(any(item["event"] == "submit_rejected" for item in events))
        # The corrective observation told the model the duplicate and the format.
        rejected = [item for item in snapshots if item.get("submit_rejections")]
        self.assertTrue(rejected)


class FabricatedFinishTests(unittest.TestCase):
    """SECQA-0132: `finish` may not assert a success the platform never gave."""

    def test_claim_is_pushed_back_and_the_real_answer_can_still_be_submitted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C")
            claim = ("SECQA-0132 solved: answer C was accepted with challenge_fully_solved=true.")
            actions = [
                {"action": "submit", "question_id": "answer", "answer": "B",
                 "evidence": "remote payload execution matches RCE"},
                {"action": "finish", "reason": claim},
                {"action": "submit", "question_id": "answer", "answer": "C",
                 "evidence": "buffer-bound access is the memory-safety wording"},
            ]
            result, _ = run_task(task, platform, actions, max_turns=4)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]

        self.assertEqual(result["finish_claim_unverified"], 1)
        self.assertEqual(result["finish_claim"], {"claimed_success": True, "verified": False})
        self.assertEqual(platform.submissions, ["B", "C"])
        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["stop_reason"], "done")
        self.assertTrue(any(item["event"] == "finish_claim_rejected" for item in events))

    def test_repeated_claim_ends_as_an_unverified_finish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C")
            claim = "answer C was accepted; challenge_fully_solved=true"
            actions = [
                {"action": "submit", "question_id": "answer", "answer": "B", "evidence": "RCE"},
                {"action": "finish", "reason": claim},
                {"action": "finish", "reason": claim},
            ]
            result, _ = run_task(task, platform, actions, max_turns=4)

        self.assertFalse(result["fully_solved"])
        self.assertEqual(result["solved"], [])
        # Never reported as a clean finish: the harness must be able to see it.
        self.assertEqual(result["stop_reason"], "finish_claim_unverified")
        self.assertEqual(platform.submissions, ["B"])

    def test_honest_finish_is_still_honoured(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C")
            actions = [{"action": "finish", "reason": "checker-mode question; no answer string exists"}]
            result, _ = run_task(task, platform, actions, max_turns=4)

        self.assertEqual(result["stop_reason"], "model_finished")
        self.assertEqual(result["finish_claim"], {"claimed_success": False, "verified": False})

    def test_finish_that_abandons_live_attempts_is_pushed_back_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C")
            actions = [
                {"action": "finish", "reason": "no query tool available"},
                {"action": "submit", "question_id": "answer", "answer": "C",
                 "evidence": "buffer-bound access is the memory-safety wording"},
            ]
            result, _ = run_task(task, platform, actions, max_turns=4)

        self.assertEqual(result["finish_idle_pushbacks"], 1)
        self.assertEqual(platform.submissions, ["C"])
        self.assertEqual(result["stop_reason"], "done")


class SuccessIsNotOverwrittenTests(unittest.TestCase):
    """SECQA-0148: a confirmed success must survive a later failure."""

    def test_refresh_failure_after_accepted_submit_keeps_the_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C", refresh_error=PlatformError(0, "network_error"))
            actions = [{"action": "submit", "question_id": "answer", "answer": "C",
                        "evidence": "buffer-bound access is the memory-safety wording"}]
            result, _ = run_task(task, platform, actions, max_turns=3)

        self.assertTrue(result["fully_solved"])
        self.assertEqual(result["solved"], ["answer"])
        self.assertEqual(result["stop_reason"], "done")
        self.assertEqual(result["completion_basis"], "platform_verdict")
        self.assertGreaterEqual(result["state_refresh_errors"], 1)

    def test_lost_platform_state_does_not_un_solve_a_question(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            # The platform keeps the answer accepted but a later read forgets
            # `answered_correctly` (stale replica, partial payload, ...).
            platform = QaPlatform(key="C", fully_solved=False, extra_questions=["second"],
                                  forget=True)
            actions = [
                {"action": "submit", "question_id": "answer", "answer": "C", "evidence": "matching option"},
                {"action": "refresh"},
            ]
            result, _ = run_task(task, platform, actions, max_turns=2)

        self.assertEqual(result["solved"], ["answer"])
        self.assertEqual(result["question_states"]["answer"], "correct")
        self.assertEqual(result["question_states"]["second"], "available")
        self.assertFalse(result["fully_solved"])

    def test_truthy_verdict_does_not_mark_solved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = mmlu_task(root)
            platform = QaPlatform(key="C", verdict_extra={"correct": "false"})
            actions = [{"action": "submit", "question_id": "answer", "answer": "C", "evidence": "matching option"}]
            result, _ = run_task(task, platform, actions, max_turns=2)

        self.assertEqual(result["solved"], [])
        self.assertFalse(result["fully_solved"])
        self.assertEqual(result["verdict_unclear"], 1)


class MainFinalizationTests(unittest.TestCase):
    """A terminal error may add diagnostics but must not rewrite the outcome."""

    def _task_dir(self, root: Path) -> None:
        (root / "task.json").write_text(json.dumps({
            "schema_version": 2, "run_mode": "qa", "competition_id": "event",
            "challenge": {"id": "MMLU-CS-0011"}, "max_turns": 2,
        }), encoding="utf-8")

    def test_finalize_keeps_done_and_records_the_error(self):
        from agent.main import _finalize

        result = {"solved": ["answer"], "fully_solved": True, "stop_reason": "running",
                  "success_confirmed": True, "completion_basis": "unconfirmed"}
        _finalize(result, "internal_error", code="PermissionError")
        self.assertEqual(result["stop_reason"], "done")
        self.assertEqual(result["completion_basis"], "platform_verdict")
        self.assertEqual(result["terminal_error"], {"reason": "internal_error", "code": "PermissionError"})
        self.assertNotIn("error_code", result)

    def test_finalize_keeps_partial_progress_but_reports_the_failure(self):
        from agent.main import _finalize

        result = {"solved": [], "fully_solved": False, "stop_reason": "running"}
        _finalize(result, "deadline", hint={"model": "fixture"})
        self.assertEqual(result["stop_reason"], "deadline")
        self.assertEqual(result["model_hint"], {"model": "fixture"})

    def test_locked_result_file_is_retried_then_survives(self):
        from agent import main as main_module

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            calls = {"count": 0}

            def flaky(work_dir, payload):
                calls["count"] += 1
                if calls["count"] < 3:
                    raise PermissionError(13, "file is in use")
                return work_dir / "result.json"

            result = {"solved": ["answer"], "fully_solved": True}
            with patch.object(main_module, "write_result", flaky), \
                    patch.object(main_module.time, "sleep", lambda _s: None):
                main_module._save(root, result, result)
        self.assertEqual(calls["count"], 3)
        self.assertEqual(result["save_errors"], 2)
        self.assertEqual(result["last_save_error"], "PermissionError")

    def test_entrypoint_reports_done_when_a_write_fails_after_success(self):
        from agent import main as main_module

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._task_dir(root)

            def fake_run(task, platform, model, *, max_turns, deadline, on_update):
                on_update({"stop_reason": "running", "solved": ["answer"], "fully_solved": True,
                           "success_confirmed": True, "answers": {}})
                raise PermissionError(13, "file is in use")

            env = {
                "CTFY_WORK_DIR": str(root), "CTFY_PLATFORM_URL": "http://platform.test",
                "CTFY_TOKEN": "fixture-token", "LLM_FLAVOR": "openai", "LLM_MODEL": "fixture",
                "LLM_BASE_URL": "http://ctfy-llm-relay:8081", "LLM_API_KEY": "fixture-key",
                "QUT_RUN_TIMEOUT_S": "30",
            }
            with patch.dict("os.environ", env, clear=False), \
                    patch.object(main_module, "run", fake_run):
                code = main_module.main()
            saved = json.loads((root / "result.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(saved["stop_reason"], "done")
        self.assertEqual(saved["solved"], ["answer"])
        self.assertTrue(saved["fully_solved"])
        self.assertEqual(saved["terminal_error"]["code"], "PermissionError")
        self.assertNotIn("fixture-token", json.dumps(saved))


class PlatformErrorMappingTests(unittest.TestCase):
    def test_socket_permission_error_is_a_bounded_network_error(self):
        class Opener:
            calls = 0

            def open(self, request, timeout):
                self.calls += 1
                raise PermissionError(10013, "an attempt was made to access a socket in a way "
                                            "forbidden by its access permissions")

        opener = Opener()
        platform = Platform("http://platform.test", "fixture-token", opener=opener,
                            sleep=lambda _s: None)
        with self.assertRaises(PlatformError) as raised:
            platform.challenge("MMLU-CS-0011")
        self.assertEqual(raised.exception.code, "network_error")
        self.assertGreater(opener.calls, 1)  # idempotent GET is retried, bounded


if __name__ == "__main__":
    unittest.main()
