"""Authorized local Pwn target: a small Linux amd64 ret2win service.

The target builds a C binary with a classic stack overflow, exposes it over a
localhost TCP socket (``socat`` when available, otherwise a standalone stdlib
TCP bridge), and publishes the binary and source as platform attachments. The
flag is a per-process random file read by the binary's ``win()`` function; it is
generated outside the solver working directory.

This module needs a POSIX host with a real gcc and an ELF runtime (Linux /
container). On Windows it can be imported but ``main`` refuses to start; the lab
runner records a machine-readable ``blocked`` experiment instead of pretending
the case ran. It never claims to substitute for a Linux verification.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import socketserver
import subprocess
import threading
import time
from pathlib import Path

try:  # normal package import
    from .common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json

VULN_C = r"""// Authorized QUTAgent lab target: classic ret2win stack overflow.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((used))
void win(void) {
    FILE *stream = fopen("flag.txt", "r");
    char line[256];
    if (stream != NULL && fgets(line, sizeof(line), stream) != NULL) {
        printf("Congratulations! %s", line);
        fflush(stdout);
    } else {
        printf("win() reached, but flag.txt is missing\n");
        fflush(stdout);
    }
    fclose(stream);
    exit(0);
}

void vuln(void) {
    char buffer[64];
    puts("Tell me your name:");
    fgets(buffer, 512, stdin);
    printf("Thanks %s\n", buffer);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== QUTAgent lab ret2win ===");
    vuln();
    puts("bye");
    return 0;
}
"""


def preflight() -> dict:
    """Report whether this host can build and run the ELF pwn target."""
    probes = {
        "os_name": os.name,
        "platform": "linux" if os.name == "posix" else os.name,
        "gcc": shutil.which("gcc"),
        "socat": shutil.which("socat"),
        "docker": shutil.which("docker"),
        "podman": shutil.which("podman"),
        "wsl": shutil.which("wsl"),
    }
    if os.name != "posix":
        return {"supported": False, "reason": "pwn_requires_linux_elf_runtime", "probes": probes}
    if not probes["gcc"]:
        return {"supported": False, "reason": "gcc_missing", "probes": probes}
    return {"supported": True, "reason": None, "probes": probes}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def build_pwn(root: Path, seed: int) -> dict:
    root = Path(root)
    source_dir = make_dir(root / "src")
    attachments = make_dir(root / "attachments")
    make_dir(root / "private")
    flag = new_flag(seed)
    flag_file = root / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    source_file = source_dir / "vuln.c"
    source_file.write_bytes(VULN_C.encode("utf-8"))
    binary = attachments / "vuln"
    command = [shutil.which("gcc") or "gcc", "-O0", "-g", "-fno-stack-protector",
               "-fno-pie", "-no-pie", "-Wno-stringop-overflow",
               "-o", str(binary), str(source_file)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if completed.returncode != 0 or not binary.exists():
        raise RuntimeError("gcc failed: " + (completed.stderr or completed.stdout)[:500])
    os.chmod(binary, 0o755)
    (attachments / "vuln.c").write_bytes(source_file.read_bytes())
    return {"root": root, "flag": flag, "flag_file": flag_file, "binary": binary,
            "source": source_file, "attachments": attachments, "gcc_command": command}


class _PythonBridge(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, binary: Path, cwd: Path, timeout_s: float = 30):
        self.binary = Path(binary)
        self.work_dir = Path(cwd)
        self.timeout_s = timeout_s
        super().__init__(address, _BridgeHandler)


class _BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        process = subprocess.Popen(
            [str(self.server.binary)], cwd=str(self.server.work_dir),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def client_to_process():
            try:
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        break
                    process.stdin.write(data)
                    process.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass

        def process_to_client():
            try:
                while True:
                    data = process.stdout.read(4096)
                    if not data:
                        break
                    self.request.sendall(data)
            except (OSError, ValueError):
                pass

        reader = threading.Thread(target=process_to_client, daemon=True)
        reader.start()
        sender = threading.Thread(target=client_to_process, daemon=True)
        sender.start()
        reader.join(timeout=self.server.timeout_s)
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _readme(port: int) -> str:
    return f"""# Lab Pwn Challenge: ret2win service

Authorized local lab challenge (Linux amd64). Network service:

    127.0.0.1:{port}

Player-visible attachments (download them through the platform): `vuln` and
`vuln.c`.

The service reads a name from stdin into a fixed-size stack buffer. Build a local
copy of the binary from the attachment, triage it (`ctf-checksec`, `ctf-disasm`,
`ctf-debug`, `nm`/`readelf`), find the win function and the return-address
offset, then write a pwntools/socket exploit script and run it against the
service. The flag is printed by the binary's win function.

Rules of engagement: local lab only; do not touch hosts outside the supplied
service; submit the exact flag string with the exploit output as evidence.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized local Linux pwn target")
    parser.add_argument("--root", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--port", type=int, default=0, help="0 chooses a free port")
    parser.add_argument("--bridge", choices=["auto", "socat", "python"], default="auto")
    args = parser.parse_args()

    status = preflight()
    if not status["supported"]:
        raise SystemExit(f"pwn target unsupported on this host: {status['reason']}")
    root = make_dir(Path(args.root))
    make_dir(Path(args.log).parent)
    state = build_pwn(root, args.seed)
    port = args.port or _free_port()
    bridge = None
    process = None
    if args.bridge in {"auto", "socat"} and state["attachments"] and shutil.which("socat"):
        command = [shutil.which("socat") or "socat",
                   f"TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork",
                   "EXEC:./attachments/vuln"]
        process = subprocess.Popen(command, cwd=str(root), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    bridge = "socat"
                    break
            except OSError:
                if process.poll() is not None:
                    break
                time.sleep(0.05)
        if bridge is None and process is not None:
            try:
                process.kill()
            except OSError:
                pass
            process = None
    if bridge is None:
        server = _PythonBridge(("127.0.0.1", port), state["binary"], root)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1},
                                  daemon=True)
        thread.start()
        bridge = "python"
        process = server
    append_jsonl(Path(args.log), {
        "ts": now_iso(), "seed": args.seed, "event": "pwn_service_ready",
        "bridge": bridge, "port": port, "binary": str(state["binary"]),
        "gcc_command": state["gcc_command"],
    })
    write_json(Path(args.ready_file), {
        "service": "pwn_target",
        "root": str(root),
        "host": "127.0.0.1",
        "port": port,
        "bridge": bridge,
        "flag_file": str(state["flag_file"]),
        "flag_sha256": sha256_text(state["flag"]),
        "attachments_dir": str(state["attachments"]),
        "attachments": [
            {"name": "vuln", "size": state["binary"].stat().st_size},
            {"name": "vuln.c", "size": (state["attachments"] / "vuln.c").stat().st_size},
        ],
        "category": "pwn",
        "tags": ["pwn", "ret2win", "bof", "lab"],
        "name": "Lab: ret2win service",
        "description": "Authorized local Linux amd64 ret2win stack-overflow service.",
        "question_prompt": "Exploit the service and submit the flag printed by win().",
        "readme": _readme(port),
        "services": [{"service_type": "tcp", "name": "vuln",
                      "host": "127.0.0.1", "port": port,
                      "url": f"tcp://127.0.0.1:{port}",
                      "description": "ret2win service"}],
    })
    try:
        while True:
            if isinstance(process, _PythonBridge):
                time.sleep(0.2)
            elif process is not None and process.poll() is not None:
                break
            else:
                time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        if isinstance(process, _PythonBridge):
            process.shutdown()
            process.server_close()
        elif process is not None:
            try:
                process.kill()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
