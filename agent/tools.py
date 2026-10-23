"""Linux command groups, bounded pipe capture and an environment allowlist."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from .budget import BudgetExpired, remaining
from .security import command_environment, redact


def shell(command: str, cwd: Path, timeout_s=20, output_limit=12000, *, deadline=None):
    if not command or len(command) > 8000:
        return {"exit_code": -1, "error": "invalid_command"}
    start = time.monotonic()
    try:
        timeout = remaining(deadline, max(0.01, min(timeout_s, 90)))
    except BudgetExpired:
        return {"exit_code": -1, "error": "deadline", "elapsed_s": 0}
    if os.name != "posix":
        return {"exit_code": -1, "error": "shell_requires_linux"}
    try:
        process = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc", "-c", command], cwd=cwd,
            env=command_environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError as exc:
        return {"exit_code": -1, "error": type(exc).__name__}

    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}

    def drain(name, pipe):
        try:
            while True:
                block = pipe.read(4096)
                if not block:
                    break
                totals[name] += len(block)
                room = max(0, output_limit - len(chunks[name]))
                chunks[name].extend(block[:room])
        finally:
            pipe.close()

    threads = [threading.Thread(target=drain, args=(name, pipe), daemon=True)
               for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr))]
    for thread in threads:
        thread.start()
    timed_out = False
    end = start + timeout
    try:
        process.wait(timeout=max(0.001, end - time.monotonic()))
        for thread in threads:
            thread.join(max(0, end - time.monotonic()))
        timed_out = any(thread.is_alive() for thread in threads)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # Remove background descendants even if their shell exited normally.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=1)
        for thread in threads:
            thread.join(0.25)
    result = {"exit_code": process.returncode,
              **{name: redact(bytes(data).decode("utf-8", errors="replace")) for name, data in chunks.items()},
              "timed_out": timed_out,
              "truncated": any(count > output_limit for count in totals.values()),
              "captured_bytes": sum(len(data) for data in chunks.values()),
              "elapsed_s": round(time.monotonic() - start, 3)}
    if timed_out:
        result["error"] = "timeout"
    return result
