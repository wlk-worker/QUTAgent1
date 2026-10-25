"""Run the isolated category-lab experiments.

Examples (from the repository root, Windows or Linux):

    python -X utf8 scripts/run_lab.py --model fake --set dev          # Web traversal
    python -X utf8 scripts/run_lab.py --model fake --set web-sqli     # SQL injection
    python -X utf8 scripts/run_lab.py --model fake --set ai-mcp       # MCP / AI
    python -X utf8 scripts/run_lab.py --model fake --set pwn          # Linux/WSL/image only

``--model real`` reads LLM_FLAVOR, LLM_MODEL, LLM_API_KEY and optionally
LLM_BASE_URL from the environment. Missing credentials produce a machine-readable
``blocked`` experiment (exit code 2), never a fabricated success rate. ``pwn``
also returns a machine-readable ``blocked`` experiment when the host has no POSIX
ELF runtime/gcc (for example native Windows), instead of pretending the case ran.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from labs.runner import EXPERIMENTS, run_experiment  # noqa: E402

# Only these names are loaded from --llm-env-file. The file is never printed,
# copied into evidence, or passed to the fake model; keep it outside version
# control (artifacts/ and .env.* are gitignored).
_LLM_ENV_KEYS = {"LLM_FLAVOR", "LLM_MODEL", "LLM_API_KEY", "LLM_BASE_URL"}


def load_llm_env_file(path: str | None) -> int:
    """Load LLM_* lines from a local KEY=VALUE file without echoing values.

    Returns the number of variables loaded. Raises ValueError for a missing or
    unreadable file. Shell syntax beyond simple KEY=VALUE is deliberately not
    supported; this is not a general dotenv implementation.
    """
    if not path:
        return 0
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    loaded = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key not in _LLM_ENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if value:
            os.environ[key] = value
            loaded += 1
    return loaded


def _summary_view(experiment: dict) -> dict:
    cases = []
    for case in experiment.get("cases") or []:
        cases.append({
            "case_id": case.get("case_id"),
            "kind": case.get("kind"),
            "category": case.get("category"),
            "tags": case.get("tags"),
            "success": case.get("success"),
            "stop_reason": case.get("stop_reason"),
            "platform_accepted_flag": case.get("platform_accepted_flag"),
            "submissions": case.get("submission_count"),
            "turns": case.get("turns"),
            "http_calls": case.get("http_calls"),
            "mcp_calls": case.get("mcp_calls"),
            "model_requests": case.get("model_requests"),
            "tokens": case.get("tokens"),
            "wall_seconds": case.get("wall_seconds"),
            "flag_sha256": case.get("flag_sha256"),
            "downloaded_attachments": case.get("downloaded_attachments"),
            "evidence": case.get("evidence"),
            "error": case.get("error"),
        })
    return {
        "experiment_id": experiment.get("experiment_id"),
        "status": experiment.get("status"),
        "model": experiment.get("model"),
        "set": experiment.get("set"),
        "kind": experiment.get("kind"),
        "seeds": experiment.get("seeds"),
        "budget": experiment.get("budget"),
        "summary": experiment.get("summary"),
        "blocked": experiment.get("blocked"),
        "pwn_preflight": experiment.get("pwn_preflight"),
        "xss_preflight": experiment.get("xss_preflight"),
        "error": experiment.get("error"),
        "experiment_json": (experiment.get("evidence") or {}).get("experiment_json"),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated Web-lab experiment runner")
    parser.add_argument("--model", choices=["fake", "real"], default="fake",
                        help="fake: scripted local model; real: LLM_* provider (blocked if unset)")
    parser.add_argument("--set", dest="set_name", choices=sorted(EXPERIMENTS), default="dev",
                        help="fixed seed set: " + ", ".join(sorted(EXPERIMENTS)))
    parser.add_argument("--out", default=str(ROOT / "artifacts" / "lab"),
                        help="evidence root (default: artifacts/lab, gitignored)")
    parser.add_argument("--seeds", default="", help="optional comma-separated seed override (debug only)")
    parser.add_argument("--timeout-s", type=float, default=None, help="override per-case time budget")
    parser.add_argument("--max-turns", type=int, default=None, help="override per-case turn budget")
    parser.add_argument("--max-requests", type=int, default=None, help="override per-case model request budget")
    parser.add_argument("--llm-env-file", default="",
                        help="optional local KEY=VALUE file with LLM_* for --model real; never echoed")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.llm_env_file:
        try:
            count = load_llm_env_file(args.llm_env_file)
        except OSError as exc:
            print(f"cannot read --llm-env-file: {type(exc).__name__}", file=sys.stderr)
            return 2
        print(f"loaded {count} LLM_* value(s) from --llm-env-file (values not printed)")

    seeds = None
    if args.seeds.strip():
        try:
            seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
        except ValueError:
            parser.error("--seeds must be comma-separated integers")
    experiment, exit_code = run_experiment(
        args.model, args.set_name, out_dir=args.out, seeds=seeds,
        timeout_s=args.timeout_s, max_turns=args.max_turns,
        max_requests=args.max_requests, verbose=not args.quiet)
    print(json.dumps(_summary_view(experiment), ensure_ascii=False, indent=2))
    summary = experiment.get("summary") or {}
    print(f"\nstatus={experiment.get('status')} "
          f"success={summary.get('succeeded', 0)}/{summary.get('total', 0)} "
          f"wall={summary.get('wall_seconds_total')}s")
    if experiment.get("status") == "blocked":
        blocked = experiment.get("blocked") or {}
        print(f"BLOCKED: {blocked.get('reason')} missing={blocked.get('missing')}")
        print(f"blocked evidence: {Path(args.out) / f'blocked-{args.model}-{args.set_name}.json'}")
        print(f"rerun: {blocked.get('rerun')}")
    else:
        evidence = experiment.get("evidence") or {}
        print(f"evidence: {Path(args.out) / 'experiment.json'}")
        print(f"run dir: {evidence.get('run_dir')}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
