#!/usr/bin/env python3
"""Check a local LLM_* env file without printing secret values.

Usage:
    python -X utf8 scripts/check_llm_env.py --env-file artifacts/llm.env

Exit 0 only when LLM_FLAVOR, LLM_MODEL and LLM_API_KEY are non-empty. The file
is never copied into evidence; values are never printed.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.run_lab import load_llm_env_file  # noqa: E402

REQUIRED = ("LLM_FLAVOR", "LLM_MODEL", "LLM_API_KEY")
OPTIONAL = ("LLM_BASE_URL",)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate LLM_* settings without echoing them")
    parser.add_argument("--env-file", required=True, help="local KEY=VALUE file (gitignored)")
    args = parser.parse_args()
    try:
        load_llm_env_file(args.env_file)
    except OSError as exc:
        print(f"cannot read env file: {type(exc).__name__}", file=sys.stderr)
        return 2
    status = {key: bool(os.environ.get(key)) for key in (*REQUIRED, *OPTIONAL)}
    for key in (*REQUIRED, *OPTIONAL):
        print(f"{key}: {'set' if status[key] else 'MISSING'}")
    missing = [key for key in REQUIRED if not status[key]]
    if missing:
        print("MISSING required: " + ", ".join(missing))
        return 2
    print("LLM credentials present; the next step can run the real-model lab.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
