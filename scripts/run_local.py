"""Run the real entrypoint with a synthetic CTFY-0001 dry-run task."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "dry-run"


def main() -> int:
    # Keep the scratch directory inside the repository on purpose: the DSH
    # Windows sandbox can make its own %TEMP% children unreadable to the
    # sandboxed process. Cleanup is best-effort; a cleanup failure must not
    # turn a successful dry run into a non-zero exit.
    scratch = ROOT / "artifacts" / "local-run"
    scratch.mkdir(parents=True, exist_ok=True)
    # 0o750 rather than tempfile's 0o700: the DSH Windows sandbox maps a 0o700
    # directory to an ACL its own child processes cannot write through.
    work_dir = scratch / f"qutagent-dry-run-{uuid.uuid4().hex}"
    work_dir.mkdir(mode=0o750)
    try:
        shutil.copy2(EXAMPLE / "task.json", work_dir / "task.json")
        shutil.copy2(EXAMPLE / "README.md", work_dir / "README.md")

        # Dry run must be self-contained even if the developer has live keys set.
        env = {key: value for key, value in os.environ.items()
               if key not in {"CTFY_TOKEN", "LLM_API_KEY", "OPENAI_API_KEY",
                              "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}}
        env["CTFY_WORK_DIR"] = str(work_dir)
        env["CTFY_EVAL_DRY_RUN"] = "1"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "agent" / "main.py")],
            cwd=ROOT, env=env, check=False, timeout=30,
        )
        result_path = work_dir / "result.json"
        if not result_path.exists():
            print(f"entrypoint exited {completed.returncode} without result.json", file=sys.stderr)
            return 1
        result = json.loads(result_path.read_text(encoding="utf-8"))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if completed.returncode != 0 or result.get("schema_version") != 2 or result.get("stop_reason") != "dry_run":
            print("dry-run contract check failed", file=sys.stderr)
            return 1
        print("Local dry run passed. This does not validate a real challenge or image registration.")
        return 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
