"""Official TPCTF 2026 solve runner.

This is deliberately separate from the CTFY-0001 image entrypoint in
``agent.main``.  The official contest exposes a REST solve API
(``/api/v1/competitions`` ... ``/api/v1/submissions``) and expects the agent
to run on the player's own machine/VPS with a scoped ``agent_play`` token.
The image entrypoint remains unchanged for local image evaluation.

Usage::

    python -m agent.official --list
    python -m agent.official --env-file artifacts/official.env --list
    python -m agent.official --env-file artifacts/official.env \
        --competition-id c0d8b4e3dd3b42c095d63d7dfa66431f

Environment:
    CTFY_PLATFORM_URL       default https://ctfy.tsinghua.edu.cn
    CTFY_TOKEN              official agent_play token (or CTFY_USER_TOKEN for practice)
    CTFY_COMPETITION_ID     default c0d8b4e3dd3b42c095d63d7dfa66431f (Agent Track)
    LLM_FLAVOR              openai or anthropic
    LLM_MODEL               model id required by the gateway
    LLM_BASE_URL            gateway/direct base URL (optional)
    LLM_API_KEY             gateway/direct key (optional)

For an official platform gateway session, leave ``LLM_BASE_URL`` and
``LLM_API_KEY`` unset and export the injected ``OPENAI_*`` / ``ANTHROPIC_*``
variables instead.  Never put a vendor key in the repository or an image.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .budget import BudgetExpired
from .contract import Task, write_result
from .loop import run
from .model import Model, ModelError
from .platform import Platform, PlatformError
from .security import scrub

DEFAULT_COMPETITION_ID = "c0d8b4e3dd3b42c095d63d7dfa66431f"
DEFAULT_MAX_TURNS = 60
DEFAULT_TIME_BUDGET = 3600


def load_env_file(path: Path | str) -> None:
    """Load a small KEY=VALUE file without overriding the caller's env."""
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"env file not found: {source}")
    for raw in source.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def build_platform() -> Platform:
    base = _env("CTFY_PLATFORM_URL", "CTFY_BASE_URL", default="https://ctfy.tsinghua.edu.cn")
    token = _env("CTFY_TOKEN", "CTFY_AGENT_TOKEN", "CTFY_USER_TOKEN")
    if not token:
        raise SystemExit("missing CTFY_TOKEN (or CTFY_USER_TOKEN for practice)")
    return Platform(base, token)


def build_model(model_override: str | None = None, flavor_override: str | None = None) -> Model:
    flavor = (flavor_override or _env("LLM_FLAVOR") or
              ("anthropic" if _env("ANTHROPIC_BASE_URL") and not _env("OPENAI_BASE_URL") else "openai"))
    if flavor not in {"openai", "anthropic"}:
        raise SystemExit("LLM_FLAVOR must be openai or anthropic")
    native_base = _env("ANTHROPIC_BASE_URL" if flavor == "anthropic" else "OPENAI_BASE_URL")
    native_key = _env("ANTHROPIC_API_KEY" if flavor == "anthropic" else "OPENAI_API_KEY")
    native_model = _env("ANTHROPIC_MODEL" if flavor == "anthropic" else "OPENAI_MODEL")
    base = _env("LLM_BASE_URL") or native_base
    key = _env("LLM_API_KEY") or native_key
    model = model_override or _env("LLM_MODEL") or native_model
    if not model and "api.deepseek.com" in base:
        # Direct DeepSeek practice key.  Official gateway runs must set LLM_MODEL.
        model = "deepseek-flash"
    if not model:
        raise SystemExit("missing LLM_MODEL/OPENAI_MODEL/ANTHROPIC_MODEL")
    if not key:
        raise SystemExit("missing LLM_API_KEY (or OPENAI_API_KEY/ANTHROPIC_API_KEY)")
    return Model(flavor, model, base, key)


def _render_readme(challenge: dict[str, Any]) -> str:
    lines = [
        f"# {challenge.get('name') or challenge.get('id', 'challenge')}",
        "",
        str(challenge.get("description") or ""),
        "",
        f"Category: {challenge.get('category', '')}",
        f"Scoring: {challenge.get('scoring', '')}",
    ]
    questions = challenge.get("questions") or []
    if questions:
        lines.extend(["", "## Questions"])
        for question in questions:
            if not isinstance(question, dict):
                continue
            lines.append(f"- `{question.get('id', '')}`: {question.get('prompt', '')}")
            choices = question.get("choices") or []
            if choices:
                lines.append("  choices: " + ", ".join(str(c) for c in choices))
            if question.get("requires"):
                lines.append("  requires: " + ", ".join(map(str, question["requires"])))
    attachments = challenge.get("attachments") or []
    if attachments:
        lines.extend(["", "## Attachments"])
        for attachment in attachments:
            if isinstance(attachment, dict):
                lines.append(f"- `{attachment.get('name', '')}`")
    return "\n".join(lines) + "\n"


def _result_payload(result: dict[str, Any], challenge: dict[str, Any]) -> dict[str, Any]:
    """Only stable fields go into the visible result file."""
    return {
        "challenge_id": challenge.get("id", ""),
        "answers": result.get("answers") or {},
        "solved": result.get("solved") or [],
        "fully_solved": bool(result.get("fully_solved")),
        "turns": int(result.get("turns") or 0),
        "stop_reason": str(result.get("stop_reason") or ""),
        "writeup": str(result.get("writeup") or ""),
    }


def _challenge_ids(challenges: list[dict[str, Any]], requested: list[str], maximum: int) -> list[dict[str, Any]]:
    if requested:
        wanted = set(requested)
        selected = [c for c in challenges if str(c.get("id")) in wanted]
    else:
        selected = [c for c in challenges if not c.get("my_team_fully_solved")]
    return selected[:max(0, maximum)]


def run_competition(args: argparse.Namespace) -> int:
    platform = build_platform()
    competition = platform.competition(args.competition_id)
    print(f"competition: {competition.get('title') or args.competition_id} ({args.competition_id})")
    print(f"phase: {competition.get('phase')} registered: {competition.get('is_registered')}")
    print(f"team: {competition.get('my_team_name')} challenges: {competition.get('challenge_count')}")
    if args.list:
        data = platform.challenges(args.competition_id, limit=100)
        items = data.get("items") or []
        print(f"challenges: {len(items)}")
        for challenge in items:
            print(f"  {challenge.get('id')}  {challenge.get('name')}  "
                  f"[{challenge.get('category')}/{challenge.get('difficulty')}]  "
                  f"fully_solved={challenge.get('my_team_fully_solved')}")
        return 0

    if competition.get("phase") not in {"running", "active"}:
        print("competition is not running; use --list to inspect when it starts", file=sys.stderr)
        return 2
    if not competition.get("is_registered"):
        print("team is not registered for this competition", file=sys.stderr)
        return 3

    listing = platform.challenges(args.competition_id, limit=100)
    challenges = _challenge_ids(listing.get("items") or [], args.challenge or [], args.max_challenges)
    if not challenges:
        print("no challenges selected (event not started or all already solved)", file=sys.stderr)
        return 4

    model = build_model(args.model, args.flavor)
    started = time.monotonic()
    deadline = started + max(60, int(args.max_seconds))
    work_root = Path(args.work_root).expanduser().resolve() / args.competition_id
    work_root.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "competition_id": args.competition_id,
        "competition_title": competition.get("title"),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "challenges": [],
    }

    for ordinal, item in enumerate(challenges, 1):
        cid = str(item.get("id") or "")
        name = str(item.get("name") or cid)
        if time.monotonic() >= deadline:
            summary["challenges"].append({"id": cid, "name": name, "status": "skipped_deadline"})
            break
        work_dir = work_root / cid.replace("/", "_")
        work_dir.mkdir(parents=True, exist_ok=True)
        print(f"[{ordinal}/{len(challenges)}] {cid} {name}", flush=True)
        record: dict[str, Any] = {"id": cid, "name": name, "status": "running"}
        state: dict[str, Any] = {}
        instance_id: str | None = None
        try:
            detail = platform.challenge(cid, competition_id=args.competition_id)
            run_mode = "qa" if detail.get("is_qa_only") else "instance"
            readme = _render_readme(detail)
            (work_dir / "README.md").write_text(readme, encoding="utf-8")
            raw = {
                "run_mode": run_mode,
                "competition_id": args.competition_id,
                "challenge": detail,
                "questions": detail.get("questions") or [],
                "attachments": detail.get("attachments") or [],
            }
            task = Task(
                work_dir=work_dir,
                raw=raw,
                readme=readme,
                challenge_id=cid,
                competition_id=args.competition_id,
                run_mode=run_mode,
                dry_run=False,
            )
            vpn_path: Path | None = None

            def on_instance(instance: str, info: dict[str, Any]) -> None:
                nonlocal vpn_path
                endpoint = info.get("vpn_endpoint") or {}
                if not isinstance(endpoint, dict) or not endpoint:
                    return
                directory = Path(args.vpn_dir).expanduser().resolve() / args.competition_id
                directory.mkdir(parents=True, exist_ok=True)
                vpn_path = directory / (cid.replace("/", "_") + ".conf")
                vpn_path.write_bytes(platform.vpn_config(instance))
                try:
                    vpn_path.chmod(0o600)
                except OSError:
                    pass
                record["vpn_config"] = str(vpn_path)
                if os.environ.get("QUT_WG_UP") == "1":
                    try:
                        completed = subprocess.run(
                            ["wg-quick", "up", str(vpn_path)],
                            capture_output=True, text=True, timeout=45,
                        )
                        record["vpn_up"] = completed.returncode == 0
                        if completed.returncode != 0:
                            record["vpn_up_error"] = (completed.stderr or completed.stdout or "")[:240]
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        record["vpn_up_error"] = (type(exc).__name__ + ": " + str(exc))[:240]

            def on_update(result: dict[str, Any]) -> None:
                state.clear()
                state.update(result)
                if result.get("instance_id"):
                    state["instance_id"] = result["instance_id"]
                try:
                    write_result(work_dir, _result_payload(result, detail))
                except OSError as exc:
                    record["result_write_error"] = str(exc)[:160]

            result = run(
                task, platform, model,
                max_turns=max(1, int(args.max_turns)),
                deadline=deadline,
                on_update=on_update,
                on_instance=on_instance,
            )
            instance_id = result.get("instance_id") or state.get("instance_id")
            record.update({
                "status": "finished",
                "run_mode": run_mode,
                "solved": result.get("solved") or [],
                "fully_solved": bool(result.get("fully_solved")),
                "turns": int(result.get("turns") or 0),
                "stop_reason": result.get("stop_reason") or "",
                "instance_id": instance_id,
                "model_requests": getattr(model, "logical_requests", 0),
            })
            if result.get("startup_fallback"):
                record["startup_fallback"] = result["startup_fallback"]
        except (PlatformError, BudgetExpired, ModelError, OSError, ValueError) as exc:
            instance_id = state.get("instance_id") or None
            record.update({
                "status": "error",
                "error": (type(exc).__name__ + ": " + str(exc))[:400],
                "solved": state.get("solved") or [],
                "fully_solved": bool(state.get("fully_solved")),
                "instance_id": instance_id,
            })
            print(f"  error: {record['error']}", flush=True)
        finally:
            if vpn_path is not None and record.get("vpn_up") and not args.keep_vpn:
                try:
                    subprocess.run(["wg-quick", "down", str(vpn_path)],
                                   capture_output=True, text=True, timeout=30)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if (instance_id and not args.keep_instance
                    and not str(instance_id).startswith("fallback-")):
                try:
                    platform.close_instance(str(instance_id), args.competition_id)
                except PlatformError as exc:
                    record["close_error"] = str(exc)[:160]
            summary["challenges"].append(record)
            try:
                summary["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                (work_root / "official-summary.json").write_text(
                    json.dumps(scrub(summary), ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass

    print(json.dumps(scrub(summary), ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Official TPCTF 2026 Agent Track solve runner")
    parser.add_argument("--env-file", action="append", default=[], help="KEY=VALUE file (may repeat)")
    parser.add_argument("--competition-id", default="")
    parser.add_argument("--model", default="", help="override LLM_MODEL")
    parser.add_argument("--flavor", choices=["openai", "anthropic"], default="")
    parser.add_argument("--challenge", action="append", default=[], help="challenge id (may repeat)")
    parser.add_argument("--max-challenges", type=int, default=4)
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    parser.add_argument("--max-seconds", type=int, default=DEFAULT_TIME_BUDGET)
    parser.add_argument("--work-root", default="runtime/official")
    parser.add_argument("--vpn-dir", default="runtime/vpn", help="where WireGuard profiles are saved")
    parser.add_argument("--list", action="store_true", help="list challenges and exit")
    parser.add_argument("--keep-instance", action="store_true", help="do not close instances (debug)")
    parser.add_argument("--keep-vpn", action="store_true", help="do not wg-quick down after a challenge")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    for env_file in args.env_file:
        load_env_file(env_file)
    if not args.competition_id:
        args.competition_id = _env("CTFY_COMPETITION_ID", default=DEFAULT_COMPETITION_ID)
    if not args.competition_id:
        raise SystemExit("missing --competition-id or CTFY_COMPETITION_ID")
    return run_competition(args)


if __name__ == "__main__":
    raise SystemExit(main())
