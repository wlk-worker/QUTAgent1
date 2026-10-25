#!/usr/bin/env python3
"""Verify the QUTAgent competition image toolchain and emit one JSON report.

Run inside the image (no network access needed):

    python /app/scripts/check_toolchain.py
    python /app/scripts/check_toolchain.py --output /tmp/toolchain.json

The full report is printed to stdout as JSON. Exit codes:

* 0 -- every *required* capability is present (optional gaps are still listed);
* 1 -- at least one required capability is missing or broken;
* 2 -- the report itself could not be produced.

Checks are deliberately fixed: the script only looks up known executables,
imports known modules and runs a small number of hard-coded, bounded probes.
It never executes challenge input.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
TIMEOUT_S = 25
BROWSER_TIMEOUT_MS = 30_000
MAX_VERSION_CHARS = 160
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# id, executable, version args, required, category, note
COMMANDS: list[tuple[str, str, list[str], bool, str, str]] = [
    ("python", "python", ["--version"], True, "general", "Python interpreter"),
    ("curl", "curl", ["--version"], True, "web", "HTTP client"),
    ("wget", "wget", ["--version"], True, "web", "HTTP downloader"),
    ("jq", "jq", ["--version"], True, "general", "JSON processor"),
    ("file", "file", ["--version"], True, "general", "file type identification"),
    ("xxd", "xxd", ["-v"], True, "general", "hex dump"),
    ("hexdump", "hexdump", ["--version"], False, "general", "hex dump"),
    ("unzip", "unzip", ["-v"], True, "general", "ZIP extraction"),
    ("zip", "zip", ["-v"], True, "general", "ZIP creation"),
    ("git", "git", ["--version"], True, "general", "version control"),
    ("openssl", "openssl", ["version"], True, "ai-security", "TLS/crypto CLI"),
    ("gcc", "gcc", ["--version"], True, "general", "C compiler (exploit builds)"),
    ("g++", "g++", ["--version"], True, "general", "C++ compiler"),
    ("make", "make", ["--version"], True, "general", "build driver"),
    ("ruby", "ruby", ["--version"], True, "general", "Ruby runtime (gems)"),
    ("gem", "gem", ["--version"], True, "general", "Ruby package manager"),
    ("nmap", "nmap", ["--version"], True, "web", "port/service scanner"),
    ("nc", "nc", ["-h"], True, "pwn", "netcat"),
    ("socat", "socat", ["-V"], True, "pwn", "socket relay"),
    ("sqlmap", "sqlmap", ["--version"], True, "web", "SQL injection scanner"),
    ("ffuf", "ffuf", ["-V"], True, "web", "content discovery"),
    ("gobuster", "gobuster", ["version"], True, "web", "directory/DNS brute force"),
    ("nikto", "nikto", ["-Version"], False, "web", "Perl web scanner"),
    ("nuclei", "nuclei", ["-version"], False, "web", "template scanner"),
    ("grpcurl", "grpcurl", ["--version"], False, "ai-security", "gRPC probing"),
    ("binwalk", "binwalk", ["--help"], True, "general", "firmware extraction"),
    ("patchelf", "patchelf", ["--version"], True, "pwn", "ELF patching"),
    ("gdb", "gdb", ["--version"], True, "pwn", "debugger"),
    ("gdbserver", "gdbserver", ["--version"], True, "pwn", "remote debugging"),
    ("readelf", "readelf", ["--version"], True, "pwn", "ELF headers"),
    ("objdump", "objdump", ["--version"], True, "pwn", "disassembler"),
    ("strings", "strings", ["--version"], True, "pwn", "string extraction"),
    ("nm", "nm", ["--version"], True, "pwn", "symbol table"),
    ("r2", "r2", ["-v"], True, "pwn", "radare2"),
    ("rabin2", "rabin2", ["-v"], False, "pwn", "radare2 binary info"),
    ("ROPgadget", "ROPgadget", ["--version"], True, "pwn", "ROP gadget finder"),
    ("one_gadget", "one_gadget", ["--version"], True, "pwn", "libc one-shot gadgets"),
    ("seccomp-tools", "seccomp-tools", ["--version"], False, "pwn", "seccomp filter tooling"),
    ("checksec", "checksec", ["--version"], False, "pwn", "checksec.sh"),
]

# module, distribution, required, category, note
IMPORTS: list[tuple[str, str, bool, str, str]] = [
    ("pwn", "pwntools", True, "pwn", "pwntools"),
    ("requests", "requests", True, "web", "HTTP client"),
    ("httpx", "httpx", True, "web", "HTTP client (sync/async)"),
    ("bs4", "beautifulsoup4", True, "web", "HTML parsing"),
    ("websocket", "websocket-client", True, "ai-security", "WebSocket client"),
    ("z3", "z3-solver", True, "pwn", "SMT solver"),
    ("capstone", "capstone", True, "pwn", "disassembly engine"),
    ("mcp", "mcp", True, "ai-security", "Model Context Protocol SDK"),
    ("angr", "angr", False, "pwn", "symbolic execution"),
    ("playwright", "playwright", False, "web", "headless browser driver"),
    ("elftools", "pyelftools", False, "pwn", "ELF parsing"),
    ("lxml", "lxml", False, "web", "fast HTML/XML parsing"),
]

# path, required, category, note
FILES: list[tuple[str, bool, str, str]] = [
    ("/app/agent/main.py", True, "entrypoint", "absolute-path entrypoint"),
    ("/app/tool-versions.txt", False, "inventory", "build-time package inventory"),
    ("/app/toolchain.txt", False, "inventory", "in-image tool cheat sheet"),
    ("/usr/local/bin/ctf-checksec", True, "helper", "hardening summary helper"),
    ("/usr/local/bin/ctf-disasm", True, "helper", "bounded disassembly helper"),
    ("/usr/local/bin/ctf-debug", True, "helper", "batch gdb helper"),
    ("/usr/local/bin/ctf-strings", True, "helper", "bounded strings helper"),
    ("/usr/local/bin/ctf-browse", True, "helper", "bounded headless-browser helper"),
    ("/opt/nuclei-templates", False, "web", "starter nuclei templates"),
    ("/opt/playwright", False, "web", "Playwright browser directory"),
]

# runtime probes: id, category, required, note
PROBES: list[tuple[str, str, bool, str]] = [
    ("workdir_writable", "entrypoint", True, "/ctfy/work is writable by the runtime user"),
    ("gdb_batch", "pwn", True, "gdb runs non-interactively in batch mode"),
    ("pwn_checksec", "pwn", True, "pwntools checksec works on an ELF"),
    ("agent_entry_import", "entrypoint", True, "agent.main imports as the entrypoint does"),
    ("chromium_launch", "web", False, "headless Chromium actually launches"),
]


def _clean(text: str) -> str:
    text = _CONTROL.sub("", text or "")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return (lines[0] if lines else "")[:MAX_VERSION_CHARS]


def _probe_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("TERM", "dumb")
    env.setdefault("NO_COLOR", "1")
    return env


def _run(argv: list[str], timeout: int = TIMEOUT_S) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env=_probe_env(), stdin=subprocess.DEVNULL)


def check_command(item: tuple[str, str, list[str], bool, str, str]) -> dict[str, Any]:
    check_id, executable, version_args, required, category, note = item
    check: dict[str, Any] = {"id": check_id, "kind": "command", "name": executable,
                             "required": required, "category": category,
                             "note": note, "ok": False, "detail": {}}
    path = shutil.which(executable)
    if not path:
        check["detail"] = {"missing": "executable not found on PATH"}
        return check
    check["ok"] = True
    check["detail"] = {"path": path, "version": None}
    try:
        result = _run([path, *version_args])
    except (OSError, subprocess.SubprocessError) as exc:
        check["detail"]["version_probe_error"] = type(exc).__name__
        return check
    output = _clean(result.stdout) or _clean(result.stderr)
    if output:
        check["detail"]["version"] = output
    if result.returncode != 0:
        check["detail"]["version_probe_exit"] = result.returncode
    return check


def check_import(item: tuple[str, str, bool, str, str]) -> dict[str, Any]:
    module_name, distribution, required, category, note = item
    check: dict[str, Any] = {"id": f"import:{module_name}", "kind": "import",
                             "name": module_name, "distribution": distribution,
                             "required": required, "category": category,
                             "note": note, "ok": False, "detail": {}}
    # A real file object is required: some libraries (pwntools) call
    # sys.stdout.fileno(), which io.StringIO does not provide.
    try:
        sink = open(os.devnull, "w", encoding="utf-8")
    except OSError:
        sink = None
    try:
        if sink is not None:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                module = importlib.import_module(module_name)
        else:
            module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - report the failure class, never crash
        check["detail"] = {"error": type(exc).__name__,
                           "message": _clean(str(exc))}
        return check
    finally:
        if sink is not None:
            sink.close()
    check["ok"] = True
    version = None
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        version = getattr(module, "__version__", None)
    check["detail"] = {"version": str(version) if version is not None else None}
    return check


def check_file(item: tuple[str, bool, str, str]) -> dict[str, Any]:
    raw_path, required, category, note = item
    path = Path(raw_path)
    check: dict[str, Any] = {"id": f"file:{raw_path}", "kind": "file", "name": raw_path,
                             "required": required, "category": category,
                             "note": note, "ok": False, "detail": {}}
    try:
        exists = path.exists()
    except OSError as exc:
        check["detail"] = {"error": type(exc).__name__}
        return check
    check["detail"] = {"exists": exists}
    if not exists:
        return check
    if path.is_dir():
        check["detail"]["kind"] = "directory"
        try:
            entries = sorted(child.name for child in path.iterdir())[:12]
        except OSError as exc:
            check["detail"]["error"] = type(exc).__name__
            return check
        check["detail"]["entries"] = entries
        check["ok"] = True
        return check
    check["detail"]["kind"] = "file"
    check["detail"]["readable"] = os.access(path, os.R_OK)
    check["detail"]["executable"] = os.access(path, os.X_OK)
    check["detail"]["bytes"] = path.stat().st_size
    check["ok"] = check["detail"]["readable"]
    return check


def _probe_workdir() -> tuple[bool, dict[str, Any]]:
    work = Path(os.environ.get("CTFY_WORK_DIR") or "/ctfy/work")
    writable = work.is_dir() and os.access(work, os.W_OK)
    return writable, {"path": str(work), "exists": work.is_dir(), "writable": writable}


def _probe_gdb_batch() -> tuple[bool, dict[str, Any]]:
    gdb = shutil.which("gdb")
    if not gdb:
        return False, {"missing": "gdb"}
    # `info version` is not a gdb command (gdb 16.3 exits 1); `show version` is.
    result = _run([gdb, "-q", "-batch", "-nx", "-ex", "show version", "/bin/true"])
    return result.returncode == 0, {"exit": result.returncode,
                                    "stdout": _clean(result.stdout),
                                    "stderr": _clean(result.stderr)}


def _probe_pwn_checksec() -> tuple[bool, dict[str, Any]]:
    pwn = shutil.which("pwn")
    if not pwn:
        return False, {"missing": "pwn"}
    result = _run([pwn, "checksec", "--file", "/bin/true"])
    combined = (result.stdout or "") + (result.stderr or "")
    # pwntools needs pkg_resources (setuptools<81) to populate PLT entries; a
    # warning here means its ELF/ROP features are degraded even though the
    # command exits 0.
    degraded = "Could not populate PLT" in combined
    return result.returncode == 0 and not degraded, {
        "exit": result.returncode,
        "stdout": _clean(result.stdout),
        "plt_population_degraded": degraded,
    }


def _probe_agent_entry() -> tuple[bool, dict[str, Any]]:
    code = ("import sys; sys.path.insert(0, '/app'); "
            "import agent.main; print(agent.main.__name__)")
    result = _run([sys.executable, "-c", code])
    return result.returncode == 0, {"exit": result.returncode,
                                     "stdout": _clean(result.stdout),
                                     "stderr": _clean(result.stderr)}


def _probe_chromium_launch() -> tuple[bool, dict[str, Any]]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        return False, {"error": type(exc).__name__, "message": _clean(str(exc))}
    detail: dict[str, Any] = {}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                timeout=BROWSER_TIMEOUT_MS,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                page = browser.new_page()
                page.set_content("<title>qutagent</title>")
                detail["title"] = page.title()
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - optional capability, report the cause
        detail.update({"error": type(exc).__name__, "message": _clean(str(exc))})
        return False, detail
    return detail.get("title") == "qutagent", detail


RUNTIME_PROBES: dict[str, Callable[[], tuple[bool, dict[str, Any]]]] = {
    "workdir_writable": _probe_workdir,
    "gdb_batch": _probe_gdb_batch,
    "pwn_checksec": _probe_pwn_checksec,
    "agent_entry_import": _probe_agent_entry,
    "chromium_launch": _probe_chromium_launch,
}


def check_probe(item: tuple[str, str, bool, str]) -> dict[str, Any]:
    probe_id, category, required, note = item
    check: dict[str, Any] = {"id": f"probe:{probe_id}", "kind": "probe",
                             "name": probe_id, "required": required,
                             "category": category, "note": note,
                             "ok": False, "detail": {}}
    function = RUNTIME_PROBES.get(probe_id)
    if function is None:
        check["detail"] = {"error": "unknown_probe"}
        return check
    try:
        ok, detail = function()
    except Exception as exc:  # noqa: BLE001 - probes must never abort the report
        ok, detail = False, {"error": type(exc).__name__,
                             "message": _clean(str(exc))}
    check["ok"] = bool(ok)
    check["detail"] = detail or {}
    return check


def build_report() -> dict[str, Any]:
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    checks.extend(check_command(item) for item in COMMANDS)
    checks.extend(check_import(item) for item in IMPORTS)
    checks.extend(check_file(item) for item in FILES)
    checks.extend(check_probe(item) for item in PROBES)

    required_failed = [c["id"] for c in checks if c["required"] and not c["ok"]]
    optional_failed = [c["id"] for c in checks if not c["required"] and not c["ok"]]
    by_category: dict[str, dict[str, int]] = {}
    for check in checks:
        bucket = by_category.setdefault(check["category"], {"total": 0, "ok": 0, "failed": 0})
        bucket["total"] += 1
        bucket["ok" if check["ok"] else "failed"] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "image": {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": platform.python_version(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "cwd": os.getcwd(),
        },
        "summary": {
            "verdict": "passed" if not required_failed else "failed",
            "total": len(checks),
            "ok": sum(1 for c in checks if c["ok"]),
            "failed": sum(1 for c in checks if not c["ok"]),
            "required_failed": required_failed,
            "optional_failed": optional_failed,
            "by_category": by_category,
            "elapsed_s": round(time.monotonic() - started, 3),
        },
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the QUTAgent image toolchain and print a JSON report.")
    parser.add_argument("--output", metavar="PATH",
                        help="also write the report to PATH (JSON)")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the summary object, not every check")
    args = parser.parse_args(argv)
    try:
        report = build_report()
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"schema_version": SCHEMA_VERSION, "verdict": "error",
                          "error": type(exc).__name__,
                          "message": _clean(str(exc))}, ensure_ascii=False))
        return 2
    payload = report if not args.quiet else {
        "schema_version": report["schema_version"],
        "generated_at": report["generated_at"],
        "image": report["image"],
        "summary": report["summary"],
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        try:
            Path(args.output).write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"error": "output_write_failed",
                              "message": _clean(str(exc))}), file=sys.stderr)
            return 2
    return 0 if report["summary"]["verdict"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
