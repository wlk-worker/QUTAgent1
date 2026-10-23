"""Generate and locally validate one candidate Web challenge without credentials.

This is the offline authoring stage. Platform upload needs the competition's
actual authoring rules, time window and separately authorized credentials.
"""
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

try:
    from .generate import generate
except ImportError:
    from generate import generate


def prepare(output_root: Path, seed: int | None, cli: str, smoke_runs: int) -> Path:
    output_root = output_root.resolve()
    if seed is None:
        for _ in range(20):
            seed = secrets.randbits(32)
            if not (output_root / f"document-desk-{seed}").exists():
                break
        else:
            raise RuntimeError("could not choose an unused seed")
    destination = output_root / f"document-desk-{seed}"
    generate(destination, seed)
    commands = [[cli, "challenge", "audit", destination.name,
                 "--challenges-dir", str(output_root), "--strict", "--json"]]
    commands.extend([cli, "challenge", "smoke", destination.name,
                     "--challenges-dir", str(output_root), "--ephemeral-ports",
                     "--timeout", "180"] for _ in range(smoke_runs))
    checks = []
    for command in commands:
        started = time.monotonic()
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=240)
            code = process.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            code = -1
            failure = type(exc).__name__
        else:
            failure = "" if code == 0 else "check_failed"
        checks.append({"kind": command[2], "exit_code": code,
                       "elapsed_s": round(time.monotonic() - started, 2), "failure": failure})
        if code != 0:
            break
    report = {"schema_version": 1, "candidate": str(destination), "seed": seed,
              "ctfy_cli": cli, "checks": checks,
              "locally_validated": len(checks) == len(commands) and all(c["exit_code"] == 0 for c in checks),
              "uploaded": False, "platform_reviewed": False}
    report_path = output_root / f"{destination.name}.verification.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(report_path)
    if not report["locally_validated"]:
        raise RuntimeError(f"local authoring check failed; inspect {report_path}")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=Path("author/generated"))
    parser.add_argument("--seed", type=int)
    parser.add_argument("--ctfy-admin", default="ctfy-admin")
    parser.add_argument("--smoke-runs", type=int, default=2)
    args = parser.parse_args()
    if args.smoke_runs < 1 or args.smoke_runs > 5:
        parser.error("--smoke-runs must be between 1 and 5")
    try:
        print(prepare(args.output_root, args.seed, args.ctfy_admin, args.smoke_runs))
    except (FileExistsError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
