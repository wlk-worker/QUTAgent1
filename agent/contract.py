"""CTFY-0001 input/output boundary. No credentials are serialized here."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .security import scrub


@dataclass(frozen=True)
class Task:
    work_dir: Path
    raw: dict[str, Any]
    readme: str
    challenge_id: str
    competition_id: str
    run_mode: str
    dry_run: bool

    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> "Task":
        env = environ if environ is not None else os.environ
        work_dir = Path(env.get("CTFY_WORK_DIR") or "/ctfy/work").resolve()
        path = work_dir / "task.json"
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if not isinstance(raw, dict):
            raise ValueError("task.json must be an object")
        readme_path = work_dir / "README.md"
        readme = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
        challenge = raw.get("challenge") or {}
        return cls(
            work_dir=work_dir,
            raw=raw,
            readme=readme,
            challenge_id=str(env.get("CTFY_EVAL_CHALLENGE_ID") or challenge.get("id") or ""),
            competition_id=str(env.get("CTFY_EVAL_COMPETITION_ID") or raw.get("competition_id") or ""),
            run_mode=str(raw.get("run_mode") or ""),
            dry_run=env.get("CTFY_EVAL_DRY_RUN") == "1" or raw.get("dry_run") is True,
        )


def write_result(work_dir: Path, result: dict[str, Any]) -> Path:
    """Make every visible result a complete JSON object, even on interruption."""
    work_dir.mkdir(parents=True, exist_ok=True)
    target = work_dir / "result.json"
    payload = json.dumps(scrub({"schema_version": 2, **result}), ensure_ascii=False, separators=(",", ":"))
    fd, tmp_name = tempfile.mkstemp(prefix=".result-", suffix=".json", dir=work_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return target

