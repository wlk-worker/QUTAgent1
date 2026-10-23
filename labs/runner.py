"""Process-isolated Web-lab experiment runner.

For each fixed seed the runner starts three independent child processes
(``labs.target``, ``labs.mock_platform``, and for fake experiments
``labs.fake_model``), each on an ephemeral 127.0.0.1 port, then runs the real
``agent/main.py`` entrypoint in a child process with a fixed time/turn/request
budget. Evidence is copied into ``artifacts/lab/runs/<experiment>/`` with the
dynamic flag replaced by ``flag{[REDACTED]}``; only its SHA-256 is recorded.

Isolation level: separate processes, ephemeral ports and scratch directories on
the same Windows host and user. This is NOT Docker/VM/container isolation.
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:  # normal package import
    from .common import (
        ARTIFACTS, ROOT, child_environment, cleanup_work, make_dir, now_iso,
        read_json, read_jsonl, relative_to_workspace, sanitize_copy,
        sanitize_text, sha256_text, spawn_module, stop_process, timestamp,
        wait_ready, workspace_temp, write_json, write_text,
    )
except ImportError:  # direct script execution
    from common import (
        ARTIFACTS, ROOT, child_environment, cleanup_work, make_dir, now_iso,
        read_json, read_jsonl, relative_to_workspace, sanitize_copy,
        sanitize_text, sha256_text, spawn_module, stop_process, timestamp,
        wait_ready, workspace_temp, write_json, write_text,
    )

EXPERIMENTS = {
    "dev": {
        "seeds": (101, 102, 103),
        "timeout_s": 60,
        "max_turns": 8,
        "max_requests": 8,
        "description": "Development set: fixed seeds used while iterating on the lab.",
    },
    "validation": {
        "seeds": (201, 202, 203),
        "timeout_s": 60,
        "max_turns": 8,
        "max_requests": 8,
        "description": "Validation set: fixed seeds reserved for final measurements.",
    },
}

REAL_CREDENTIAL_FIELDS = ("LLM_FLAVOR", "LLM_MODEL", "LLM_API_KEY")
REAL_OPTIONAL_FIELDS = ("LLM_BASE_URL",)

ISOLATION_LIMITS = [
    "separate OS processes, ephemeral 127.0.0.1 ports and separate scratch directories",
    "same Windows host and same user account as the runner; no container, VM or PID/FS namespace",
    "the solver gets only task.json/README.md, target origin, platform endpoint and model endpoint",
    "the target flag file lives outside the solver working directory and is never passed to it",
    "QUT_WEB_ONLY=1 disables the shell tool and the http tool is origin-restricted",
    "process-level isolation is a lab boundary, not a security boundary against a malicious solver",
]


def _credentials(environ) -> tuple[dict, list[str], str | None]:
    values = {key: str(environ.get(key) or "").strip() for key in REAL_CREDENTIAL_FIELDS + REAL_OPTIONAL_FIELDS}
    missing = [key for key in REAL_CREDENTIAL_FIELDS if not values[key]]
    if missing:
        return values, missing, "missing_credentials"
    if values["LLM_FLAVOR"] not in {"openai", "anthropic"}:
        return values, [], "unsupported_llm_flavor"
    base = values.get("LLM_BASE_URL") or ""
    if base and not (base.startswith("http://localhost") or base.startswith("http://127.0.0.1")
                     or base.startswith("https://")):
        return values, [], "invalid_llm_base_url"
    return values, [], None


def _solver_readme(origin: str) -> str:
    return f"""# Lab Web Challenge: Acme File Shelf

This is an authorized, locally hosted lab challenge. The target service is:

    {origin}

Player-visible endpoints:

- `GET /` home page
- `GET /files/` public shelf listing
- `GET /files/<name>` public file reader
- `GET /download?name=<url-encoded name>` legacy single-file download endpoint

The flag is stored in the deployment's private area, outside the public web
root. Find it by interacting with the target over HTTP and submit the exact flag
string to the platform question `flag`.

Rules of engagement: use only the supplied target origin and the platform/model
endpoints; do not attempt to use credentials or access unrelated hosts.
"""


def _task_payload(challenge_id: str, origin: str, budget: dict) -> dict:
    question = {"id": "flag", "prompt": "Find the flag served by the challenge target."}
    return {
        "schema_version": 2,
        "run_mode": "instance",
        "competition_id": "qutagent-local-lab",
        "challenge": {"id": challenge_id, "name": "Lab: Acme File Shelf",
                      "questions": [question]},
        "questions": [question],
        "gated_questions": 0,
        "scope": [origin],
        "target_services": [{"service_type": "http", "url": origin}],
        "rules_of_engagement": [
            "Authorized local lab only; the target origin is the only allowed HTTP scope.",
            "Do not attempt to read the target's private files directly from the filesystem.",
            "Submit only evidence-backed answers.",
        ],
        "max_turns": budget["max_turns"],
        "limits": {"timeout_s": budget["timeout_s"]},
    }


def _agent_environment(work_dir: Path, platform_origin: str, token: str, *,
                       model_mode: str, model_flavor: str, model_base_url: str,
                       model_name: str, model_key: str, budget: dict) -> dict:
    env = child_environment({
        "CTFY_WORK_DIR": str(work_dir),
        "CTFY_PLATFORM_URL": platform_origin,
        "CTFY_TOKEN": token,
        # fake experiments use the OpenAI wire protocol; real experiments must
        # forward the configured provider flavor (openai or anthropic) verbatim.
        "LLM_FLAVOR": model_flavor,
        "LLM_MODEL": model_name,
        "LLM_API_KEY": model_key,
        "QUT_WEB_ONLY": "1",
        "QUT_RUN_TIMEOUT_S": str(budget["timeout_s"]),
        "QUT_MODEL_MAX_REQUESTS": str(budget["max_requests"]),
        "CTFY_EVAL_MAX_TURNS": str(budget["max_turns"]),
        "PYTHONPATH": str(ROOT),
        "PYTHONUTF8": "1",
    })
    if model_base_url:
        env["LLM_BASE_URL"] = model_base_url
    return env


def _run_agent(work_dir: Path, env: dict, timeout_s: float) -> dict:
    started = time.monotonic()
    process = subprocess.Popen(
        [sys.executable, "-X", "utf8", str(ROOT / "agent" / "main.py")],
        cwd=str(work_dir), env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=max(10.0, timeout_s + 20.0))
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "stdout": stdout or "",
        "stderr": stderr or "",
        "elapsed_s": round(time.monotonic() - started, 3),
    }


def _start_server(module: str, arguments: list[str], *, work: Path, case_dir: Path,
                  label: str, processes: list):
    ready_path = work / f"{label}.ready.json"
    stderr_path = case_dir / f"{label}.stderr.log"
    process, handle = spawn_module(module, [*arguments, "--ready-file", str(ready_path)],
                                   stderr_path=stderr_path)
    processes.append((process, handle))
    ready = wait_ready(ready_path, timeout_s=20.0, process=process)
    return ready


def run_case(set_name: str, seed: int, model: str, budget: dict, run_dir: Path,
             *, credentials: dict | None = None, verbose: bool = False) -> dict:
    case_id = f"{model}-{set_name}-{seed}"
    case_dir = make_dir(run_dir / "cases" / f"{set_name}-{seed}")
    work = workspace_temp(prefix=f"{set_name}-{seed}-")
    started = time.monotonic()
    case: dict = {
        "case_id": case_id,
        "set": set_name,
        "seed": seed,
        "model": model,
        "status": "error",
        "success": False,
        "stop_reason": None,
        "fully_solved": False,
        "platform_accepted_flag": False,
        "submission_count": 0,
        "correct_submission_count": 0,
        "turns": None,
        "tool_calls_made": None,
        "http_calls": None,
        "model_requests": None,
        "tokens": {"input": 0, "output": 0},
        "wall_seconds": 0.0,
        "agent_elapsed_s": None,
        "agent_returncode": None,
        "agent_timed_out": False,
        "flag_sha256": None,
        "evidence": {},
        "error": None,
    }
    processes: list = []
    flag: str | None = None
    try:
        target = _start_server(
            "labs.target",
            ["--root", str(work / "target"), "--log", str(case_dir / "target_requests.jsonl"),
             "--seed", str(seed)],
            work=work, case_dir=case_dir, label="target", processes=processes)
        challenge_id = f"lab-web-traversal-{set_name}-{seed}"
        platform_token = secrets.token_urlsafe(18)
        platform = _start_server(
            "labs.mock_platform",
            ["--target-origin", target["origin"], "--target-port", str(target["port"]),
             "--flag-file", target["flag_file"], "--token", platform_token,
             "--challenge-id", challenge_id,
             "--log", str(case_dir / "platform_requests.jsonl"),
             "--submissions-log", str(case_dir / "submissions.jsonl")],
            work=work, case_dir=case_dir, label="platform", processes=processes)
        flag = Path(target["flag_file"]).read_text(encoding="utf-8").strip()
        case["flag_sha256"] = target["flag_sha256"]

        if model == "fake":
            fake_model = _start_server(
                "labs.fake_model",
                ["--log", str(case_dir / "model_calls.jsonl")],
                work=work, case_dir=case_dir, label="model", processes=processes)
            model_base_url = fake_model["origin"] + "/v1"
            model_name = fake_model["model"]
            model_key = "fake-model-key"
            model_flavor = "openai"
        else:
            credentials = credentials or {}
            model_base_url = credentials.get("LLM_BASE_URL") or ""
            model_name = credentials.get("LLM_MODEL") or ""
            model_key = credentials.get("LLM_API_KEY") or ""
            model_flavor = credentials.get("LLM_FLAVOR") or ""

        solver_work = make_dir(work / "solver_work")
        write_text(solver_work / "task.json",
                   _json_dumps(_task_payload(challenge_id, target["origin"], budget)))
        write_text(solver_work / "README.md", _solver_readme(target["origin"]))
        agent_env = _agent_environment(
            solver_work, platform["origin"], platform_token,
            model_mode=model, model_flavor=model_flavor, model_base_url=model_base_url,
            model_name=model_name, model_key=model_key, budget=budget)
        agent = _run_agent(solver_work, agent_env, budget["timeout_s"])
        case["agent_returncode"] = agent["returncode"]
        case["agent_timed_out"] = agent["timed_out"]
        case["agent_elapsed_s"] = agent["elapsed_s"]

        result = read_json(solver_work / "result.json", {}) or {}
        sanitize_copy(solver_work / "result.json", case_dir / "result.json", flag)
        sanitize_copy(solver_work / "events.jsonl", case_dir / "events.jsonl", flag)
        sanitize_copy(solver_work / "task.json", case_dir / "task.json", flag)
        write_text(case_dir / "agent_stdout.txt", sanitize_text(agent["stdout"], flag))
        write_text(case_dir / "agent_stderr.txt", sanitize_text(agent["stderr"], flag))

        submissions = read_jsonl(case_dir / "submissions.jsonl")
        accepted = any(bool(item.get("correct")) for item in submissions)
        correct_count = sum(1 for item in submissions if item.get("correct"))
        model_calls = read_jsonl(case_dir / "model_calls.jsonl")
        input_tokens = int(result.get("input_tokens") or 0)
        output_tokens = int(result.get("output_tokens") or 0)
        if not input_tokens and not output_tokens and model_calls:
            input_tokens = sum(int(item.get("prompt_tokens") or 0) for item in model_calls)
            output_tokens = sum(int(item.get("completion_tokens") or 0) for item in model_calls)
        case.update({
            "stop_reason": result.get("stop_reason"),
            "fully_solved": result.get("fully_solved") is True,
            "solved_questions": result.get("solved") or [],
            "platform_accepted_flag": accepted,
            "submission_count": len(submissions),
            "correct_submission_count": correct_count,
            "turns": result.get("turns"),
            "tool_calls_made": result.get("tool_calls_made"),
            "http_calls": result.get("http_calls"),
            "model_requests": result.get("model_requests") if result.get("model_requests") is not None else len(model_calls),
            "tokens": {"input": input_tokens, "output": output_tokens},
            "question_states": result.get("question_states"),
            "completion_basis": result.get("completion_basis"),
        })
        success = bool(accepted and result.get("fully_solved") is True
                       and result.get("stop_reason") == "done" and not agent["timed_out"])
        case["success"] = success
        case["status"] = "success" if success else "failed"
        if not success and result.get("stop_reason") is None and not result:
            case["error"] = "agent produced no result.json"
        case["evidence"] = {
            "task_json": relative_to_workspace(case_dir / "task.json"),
            "result_json": relative_to_workspace(case_dir / "result.json"),
            "events_jsonl": relative_to_workspace(case_dir / "events.jsonl"),
            "submissions_jsonl": relative_to_workspace(case_dir / "submissions.jsonl"),
            "platform_requests": relative_to_workspace(case_dir / "platform_requests.jsonl"),
            "target_requests": relative_to_workspace(case_dir / "target_requests.jsonl"),
            "model_calls": relative_to_workspace(case_dir / "model_calls.jsonl")
            if (case_dir / "model_calls.jsonl").exists() else None,
            "agent_stdout": relative_to_workspace(case_dir / "agent_stdout.txt"),
            "agent_stderr": relative_to_workspace(case_dir / "agent_stderr.txt"),
        }
    except Exception as exc:  # one broken case must not abort the whole set
        case["error"] = f"{type(exc).__name__}: {exc}"[:500]
        case["status"] = "error"
        case["success"] = False
    finally:
        for process, handle in reversed(processes):
            stop_process(process)
            try:
                handle.close()
            except OSError:
                pass
        case["wall_seconds"] = round(time.monotonic() - started, 3)
        cleanup_work(work)
        write_json(case_dir / "case.json", case)
        if verbose:
            outcome = "success" if case["success"] else case["status"]
            print(f"[lab] {case_id}: {outcome} "
                  f"(stop={case['stop_reason']}, {case['wall_seconds']}s)",
                  file=sys.stderr)
    return case


def _json_dumps(data) -> str:
    import json
    return json.dumps(data, ensure_ascii=False, indent=2)


def _summarize(cases: list[dict], wall_seconds: float) -> dict:
    succeeded = sum(1 for case in cases if case.get("success"))
    return {
        "total": len(cases),
        "succeeded": succeeded,
        "failed": len(cases) - succeeded,
        "success_rate": round(succeeded / len(cases), 4) if cases else 0.0,
        "wall_seconds_total": round(wall_seconds, 3),
        "platform_accepted_flags": sum(1 for case in cases if case.get("platform_accepted_flag")),
        "tokens": {
            "input": sum(int((case.get("tokens") or {}).get("input") or 0) for case in cases),
            "output": sum(int((case.get("tokens") or {}).get("output") or 0) for case in cases),
        },
        "model_requests_total": sum(int(case.get("model_requests") or 0) for case in cases),
    }


def _base_experiment(experiment_id: str, model: str, set_name: str, seeds: list[int],
                     budget: dict) -> dict:
    return {
        "schema_version": 1,
        "experiment_id": experiment_id,
        "generated_at": now_iso(),
        "status": "running",
        "model": model,
        "set": set_name,
        "seeds": seeds,
        "budget": budget,
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "isolation": "process/port/tempdir (same host; no Docker/WSL/container)",
        },
        "isolation_limits": ISOLATION_LIMITS,
        "cases": [],
        "summary": _summarize([], 0.0),
        "evidence": {
            "flag_values_stored": False,
            "flag_sha256_recorded": True,
            "submission_answers_logged_as_sha256": True,
        },
        "blocked": None,
    }


def run_experiment(model: str, set_name: str, *, out_dir: Path | str | None = None,
                   seeds=None, timeout_s: float | None = None, max_turns: int | None = None,
                   max_requests: int | None = None, environ=None, verbose: bool = False,
                   ) -> tuple[dict, int]:
    """Run one fixed experiment set. Returns ``(experiment, exit_code)``.

    Exit codes: 0 all cases succeeded; 1 ran but at least one case failed;
    2 blocked (for example missing LLM_* credentials for --model real).
    """
    if model not in {"fake", "real"}:
        raise ValueError("model must be 'fake' or 'real'")
    if set_name not in EXPERIMENTS:
        raise ValueError(f"unknown set {set_name!r}; choose from {sorted(EXPERIMENTS)}")
    base = EXPERIMENTS[set_name]
    budget = {
        "timeout_s": float(timeout_s if timeout_s is not None else base["timeout_s"]),
        "max_turns": int(max_turns if max_turns is not None else base["max_turns"]),
        "max_requests": int(max_requests if max_requests is not None else base["max_requests"]),
    }
    seeds = list(seeds if seeds is not None else base["seeds"])
    env = environ if environ is not None else os.environ
    out_root = make_dir(Path(out_dir) if out_dir is not None else ARTIFACTS)
    experiment_id = f"{model}-{set_name}-{timestamp()}-{uuid.uuid4().hex[:6]}"
    run_dir = make_dir(out_root / "runs" / experiment_id)
    started = time.monotonic()
    experiment = _base_experiment(experiment_id, model, set_name, seeds, budget)

    credentials: dict | None = None
    if model == "real":
        credentials, missing, issue = _credentials(env)
        if issue:
            experiment.update({
                "status": "blocked",
                "blocked": {
                    "reason": issue,
                    "missing": missing,
                    "note": "No real-model result was produced. Set LLM_FLAVOR, LLM_MODEL and "
                            "LLM_API_KEY (optional LLM_BASE_URL) to run; no private key fallback is used.",
                    "rerun": f"python -X utf8 scripts/run_lab.py --model real --set {set_name}",
                },
                "cases": [],
                "summary": _summarize([], time.monotonic() - started),
            })
            experiment["evidence"].update({
                "run_dir": relative_to_workspace(run_dir),
                "experiment_json": relative_to_workspace(run_dir / "experiment.json"),
            })
            write_json(run_dir / "experiment.json", experiment)
            write_json(out_root / "experiment.json", experiment)
            write_json(out_root / f"blocked-{model}-{set_name}.json", experiment)
            return experiment, 2

    try:
        for index, seed in enumerate(seeds, start=1):
            if verbose:
                print(f"[lab] case {index}/{len(seeds)}: {model} {set_name} seed={seed}", file=sys.stderr)
            case = run_case(set_name, seed, model, budget, run_dir,
                            credentials=credentials, verbose=verbose)
            experiment["cases"].append(case)
            experiment["summary"] = _summarize(experiment["cases"], time.monotonic() - started)
            experiment["evidence"].update({
                "run_dir": relative_to_workspace(run_dir),
                "experiment_json": relative_to_workspace(run_dir / "experiment.json"),
                "real_model_used": model == "real",
            })
            write_json(run_dir / "experiment.json", experiment)
            write_json(out_root / "experiment.json", experiment)
        experiment["status"] = "completed"
        experiment["summary"] = _summarize(experiment["cases"], time.monotonic() - started)
        exit_code = 0 if experiment["cases"] and all(case.get("success") for case in experiment["cases"]) else 1
    except Exception as exc:  # keep a machine-readable record even on runner errors
        experiment["status"] = "error"
        experiment["error"] = f"{type(exc).__name__}: {exc}"[:500]
        experiment["summary"] = _summarize(experiment["cases"], time.monotonic() - started)
        exit_code = 1
    experiment["generated_at"] = now_iso()
    write_json(run_dir / "experiment.json", experiment)
    write_json(out_root / "experiment.json", experiment)
    return experiment, exit_code
