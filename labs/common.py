"""Shared helpers for the local, process-isolated Web lab.

Everything here uses only the Python standard library. The lab runs as a set of
ordinary child processes on the same Windows host, each bound to an ephemeral
127.0.0.1 port and each using its own temporary directory. That is *process,
port and directory* isolation, not container or VM isolation; see
docs/lab-experiments.md for the limits.

Deliberately no ``tempfile`` use: some confined Windows development shells deny
writes inside directories created with mode 0o700, which breaks tempfile. All
scratch directories are created below ``artifacts/lab/_work`` with default
permissions and removed after each run.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts" / "lab"
FLAG_PATTERN = re.compile(r"flag\{[0-9a-fA-F]{16,}\}")

# Only these inherited variables reach lab child processes. In particular no
# LLM_*, CTFY_* or other credential-looking variable is forwarded by accident.
CHILD_ENV_ALLOWLIST = {
    "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL",
    "LC_CTYPE", "TZ", "TERM", "TMPDIR", "TEMP", "TMP", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "PYTHONIOENCODING",
    "PYTHONUTF8",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def make_dir(path: Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def workspace_temp(prefix: str = "qutagent-lab-") -> Path:
    """Create a scratch directory inside the (gitignored) workspace.

    Default permissions are used on purpose: confined Windows shells may deny
    writes to directories created with mode 0o700.
    """
    base = ARTIFACTS / "_work"
    make_dir(base)
    path = base / f"{prefix}{uuid.uuid4().hex[:12]}"
    path.mkdir()
    return path


def write_json(path: Path, data) -> Path:
    path = Path(path)
    make_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    os.replace(tmp, path)
    return path


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def append_jsonl(path: Path, data, lock=None) -> None:
    line = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    path = Path(path)
    make_dir(path.parent)
    if lock is not None:
        with lock:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
    else:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")


def read_jsonl(path: Path) -> list:
    records = []
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        return []
    return records


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_flag(seed: int = 0) -> str:
    """Independent random flag per target process; seed only labels the case."""
    return "flag{" + hashlib.sha256(f"{seed}:{secrets.token_hex(16)}".encode()).hexdigest()[:32] + "}"


def child_environment(overrides: dict | None = None) -> dict:
    env = {key: value for key, value in os.environ.items()
           if key.upper() in CHILD_ENV_ALLOWLIST}
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONUTF8"] = "1"
    if overrides:
        env.update({key: str(value) for key, value in overrides.items()})
    return env


def spawn_module(module: str, arguments: list[str], *, stderr_path: Path):
    """Start one lab server as an independent child process.

    The module is launched by file path rather than ``-m`` because the bundled
    embedded Windows Python runs isolated (``*._pth``): it ignores PYTHONPATH
    and does not put the working directory on ``sys.path``. Running the script
    directly gives it its own directory on ``sys.path``. Servers report
    readiness through a JSON file (not a pipe) so a chatty or crashing child can
    never deadlock the runner on a full pipe.
    """
    script = ROOT / (module.replace(".", "/") + ".py")
    if not script.exists():
        raise FileNotFoundError(f"lab module not found: {script}")
    make_dir(Path(stderr_path).parent)
    stderr = Path(stderr_path).open("ab")
    # The bundled embedded Windows Python is isolated: neither PYTHONPATH nor a
    # script directory reliably reaches sys.path. Bootstrap the lab modules
    # explicitly with runpy, passing argparse arguments via sys.argv[1:].
    bootstrap = (
        "import runpy, sys; "
        f"sys.path.insert(0, {str(ROOT / 'labs')!r}); "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        f"runpy.run_path({str(script)!r}, run_name='__main__')"
    )
    process = subprocess.Popen(
        [sys.executable, "-X", "utf8", "-c", bootstrap, *arguments],
        cwd=str(ROOT),
        env=child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr,
    )
    return process, stderr


def wait_ready(path: Path, *, timeout_s: float = 20.0, process=None) -> dict:
    deadline = time.monotonic() + timeout_s
    path = Path(path)
    while time.monotonic() < deadline:
        if path.exists():
            data = read_json(path)
            if isinstance(data, dict) and data.get("port"):
                return data
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"lab server exited early with code {process.returncode}")
        time.sleep(0.05)
    raise TimeoutError(f"lab server did not become ready: {path.name}")


def stop_process(process, *, timeout_s: float = 5.0) -> None:
    if process is None:
        return
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=timeout_s)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def sanitize_text(text: str, flag: str | None) -> str:
    if flag:
        text = text.replace(flag, "flag{[REDACTED]}")
    return FLAG_PATTERN.sub("flag{[REDACTED]}", text)


def sanitize_copy(source: Path, destination: Path, flag: str | None) -> bool:
    """Copy evidence with the dynamic flag removed; returns True if copied.

    Bytes are rewritten so platform newlines are preserved exactly instead of
    being translated twice on Windows.
    """
    source, destination = Path(source), Path(destination)
    if not source.exists():
        return False
    data = source.read_bytes().decode("utf-8", errors="replace")
    make_dir(destination.parent)
    destination.write_bytes(sanitize_text(data, flag).encode("utf-8"))
    return True


def write_text(path: Path, text: str) -> Path:
    path = Path(path)
    make_dir(path.parent)
    path.write_bytes(text.encode("utf-8"))
    return path


def relative_to_workspace(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def cleanup_work(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
