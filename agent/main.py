"""Absolute-path entrypoint used by the CTFy evaluator."""
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.contract import Task, write_result
from agent.loop import run
from agent.model import Model, ModelError
from urllib.parse import urlsplit
from agent.platform import Paused, Platform, PlatformError
from agent.budget import BudgetExpired


def _time_budget(raw: dict) -> float:
    limits = raw.get("limits") or {}
    choices = [raw.get("timeout_s"), limits.get("timeout_s"), limits.get("wall_time_s"),
               os.environ.get("QUT_RUN_TIMEOUT_S")]
    valid = []
    for value in choices:
        try:
            if float(value) > 0:
                valid.append(float(value))
        except (TypeError, ValueError):
            pass
    return min([10_800.0, *valid])


def _turn_budget(raw: dict) -> int:
    value = os.environ.get("CTFY_EVAL_MAX_TURNS") or raw.get("max_turns")
    try:
        return max(1, min(int(value), 500)) if value is not None else 96
    except (TypeError, ValueError):
        return 96


def _working_time(budget: float) -> float:
    """Leave room for a final atomic result without exceeding a short task."""
    reserve = min(30.0, budget * 0.1)
    return max(0.001, budget - reserve)


def _model_hint() -> dict:
    """Diagnostic metadata without the key: flavor/model and gateway host."""
    raw = os.environ.get("LLM_BASE_URL", "")
    try:
        parsed = urlsplit(raw)
        base = f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else ""
    except ValueError:
        base = ""
    return {
        "flavor": os.environ.get("LLM_FLAVOR", "")[:40],
        "model": os.environ.get("LLM_MODEL", "")[:100],
        "base": base,
    }


def main() -> int:
    try:
        task = Task.load()
    except Exception as exc:
        work_dir = Path(os.environ.get("CTFY_WORK_DIR") or "/ctfy/work")
        write_result(work_dir, {"stop_reason": "invalid_task", "error": type(exc).__name__})
        return 0
    result: dict = {"stop_reason": "starting", "answers": {}, "solved": [], "fully_solved": False}

    def save(value: dict) -> None:
        nonlocal result
        result = value.copy()
        write_result(task.work_dir, result)

    save(result)
    if task.dry_run:
        write_result(task.work_dir, {"stop_reason": "dry_run", "solved": [], "fully_solved": False})
        return 0
    if not task.challenge_id or task.run_mode not in {"instance", "qa"}:
        write_result(task.work_dir, {**result, "stop_reason": "unsupported_or_missing_task"})
        return 0
    budget = _time_budget(task.raw)
    deadline = time.monotonic() + _working_time(budget)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        model = Model(os.environ.get("LLM_FLAVOR", ""), os.environ.get("LLM_MODEL", ""),
                      os.environ.get("LLM_BASE_URL", ""), os.environ.get("LLM_API_KEY", ""),
                      deadline=deadline, max_requests=max(1, min(500, int(os.environ.get("QUT_MODEL_MAX_REQUESTS", "64")))))
        platform = Platform(os.environ.get("CTFY_PLATFORM_URL", ""), os.environ.get("CTFY_TOKEN", ""), deadline=deadline)
        result = run(task, platform, model, max_turns=_turn_budget(task.raw), deadline=deadline,
                     on_update=save)
    except BudgetExpired:
        result["stop_reason"] = "deadline"
        result["model_hint"] = _model_hint()
    except KeyboardInterrupt:
        result["stop_reason"] = "interrupted"
    except Paused:
        result["stop_reason"] = "competition_paused"
    except PlatformError as exc:
        result["stop_reason"] = "platform_error"
        result["error_code"] = exc.code
    except ModelError as exc:
        result["stop_reason"] = "model_error"
        result["error_code"] = str(exc)[:100]
        result["model_hint"] = _model_hint()
    except Exception as exc:
        # Failure class is useful for diagnosis; request bodies and secrets are not.
        result["stop_reason"] = "internal_error"
        result["error_code"] = type(exc).__name__
    write_result(task.work_dir, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
