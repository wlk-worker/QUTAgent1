"""Portable teammate launcher. No credentials or author-machine paths embedded."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "runtime" / "qutagent-linux-amd64.tar.gz"
SETS = ("dev", "validation", "web-sqli", "xss", "pwn", "ssrf", "ai-mcp", "ai-mcp-traversal")


def execute(args, timeout=600, capture=False):
    result = subprocess.run(args, cwd=ROOT, timeout=timeout, check=False,
                            capture_output=capture, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        if capture:
            # Docker inspection calls never contain credential values.
            print(result.stderr.strip(), file=sys.stderr)
        raise RuntimeError(f"command exited {result.returncode}: {args[0]}")
    return result.stdout.strip() if capture else ""


def package_info():
    path = ROOT / "HANDOFF_MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def image_name():
    return package_info().get("image", {}).get("reference") or "qutagent:dev"


def docker_ready():
    if not shutil.which("docker"):
        raise RuntimeError("Docker CLI missing. Use Docker Desktop in Linux-container mode, or run in WSL/Linux with Docker.")
    kind = execute(["docker", "info", "--format", "{{.OSType}}"], timeout=30, capture=True)
    if kind != "linux":
        raise RuntimeError("Docker must run Linux containers.")


def ensure_image(override=None, *, force_load=False):
    docker_ready()
    image = override or image_name()
    probe = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                           cwd=ROOT, capture_output=True, text=True, timeout=30)
    if probe.returncode or force_load:
        if image != image_name() or not ARCHIVE.exists():
            raise RuntimeError("Image not installed and no bundled image archive. Run: python scripts/team.py build")
        expected_archive = package_info().get("image", {}).get("archive_sha256")
        if expected_archive:
            sha = hashlib.sha256()
            with ARCHIVE.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    sha.update(block)
            if sha.hexdigest() != expected_archive:
                raise RuntimeError("Bundled image archive checksum mismatch; download/copy it again.")
        print("Loading the bundled Linux/amd64 image; this can take several minutes.", flush=True)
        execute(["docker", "load", "--input", str(ARCHIVE)], timeout=1200)
        actual = execute(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture=True)
    else:
        actual = probe.stdout.strip()
    expected = package_info().get("image", {}).get("id") if image == image_name() else None
    if expected and actual != expected:
        raise RuntimeError("Installed image does not match the handoff manifest. Restore the bundled image or use an explicitly versioned new release.")
    return image


def container_args(image, *, network="none", repo=False):
    args = ["docker", "run", "--rm", "--init", "--platform", "linux/amd64", "--network", network]
    if repo:
        args += ["--mount", f"type=bind,src={ROOT},dst=/repo", "--workdir", "/repo"]
        if os.name == "posix":
            args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    args += ["--entrypoint", "python", image]
    return args


def image_dry_run(image):
    base = ROOT / "artifacts" / "team"
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dry-run-", dir=base)).resolve()
    work.chmod(0o777)  # image user 10001 must write the bind-mounted workspace
    try:
        for name in ("task.json", "README.md"):
            shutil.copyfile(ROOT / "examples" / "dry-run" / name, work / name)
        execute(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                 "--mount", f"type=bind,src={work},dst=/ctfy/work",
                 "--env", "CTFY_EVAL_DRY_RUN=1", image], timeout=60)
        result = json.loads((work / "result.json").read_text(encoding="utf-8"))
        if result.get("schema_version") != 2 or result.get("stop_reason") != "dry_run":
            raise RuntimeError("Image dry-run returned an unexpected result.")
        print("image_dry_run_passed", flush=True)
    finally:
        if work.is_relative_to(base.resolve()) and work != base.resolve():
            shutil.rmtree(work, ignore_errors=True)


def lab(image, args):
    command = container_args(image, network="bridge" if args.model == "real" else "none", repo=True)
    command += ["-X", "utf8", "scripts/run_lab.py", "--model", args.model, "--set", args.set,
                "--timeout-s", str(args.timeout_s), "--max-turns", str(args.max_turns),
                "--max-requests", str(args.max_requests)]
    if args.model == "real":
        config = ROOT / "artifacts" / "llm.env"
        if not config.exists():
            raise RuntimeError("Create artifacts/llm.env from examples/llm.env.example and fill in your own model settings.")
        if "REPLACE_WITH_" in config.read_text(encoding="utf-8"):
            raise RuntimeError("Replace every placeholder in artifacts/llm.env before requesting a real model.")
        print("Real-model lab uses your configured provider and may incur API charges.", flush=True)
        command += ["--llm-env-file", "/repo/artifacts/llm.env"]
    execute(command, timeout=max(180, 3 * (args.timeout_s + 70)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="smoke",
                        choices=("smoke", "doctor", "tests", "lab", "build", "load", "local"))
    parser.add_argument("--model", default="fake", choices=("fake", "real"))
    parser.add_argument("--image", default=None, help="explicitly select a separately verified local image")
    parser.add_argument("--set", default="validation", choices=SETS)
    parser.add_argument("--timeout-s", type=float, default=180)
    parser.add_argument("--max-turns", type=int, default=10)
    parser.add_argument("--max-requests", type=int, default=10)
    args = parser.parse_args()
    if not 0 < args.timeout_s <= 600 or not 1 <= args.max_turns <= 64 or not 1 <= args.max_requests <= 64:
        parser.error("budget must be: timeout 0..600 seconds, turns/requests 1..64 per case")
    if args.command == "local":
        execute([sys.executable, "scripts/run_local.py"], timeout=45)
        return 0
    if args.command == "build":
        docker_ready()
        target = args.image or "qutagent:local"
        execute(["docker", "build", "--platform", "linux/amd64", "--tag", target, "."], timeout=3600)
        print(f"New image built. Verify it with: python scripts/team.py smoke --image {target}")
        return 0
    image = ensure_image(args.image, force_load=args.command == "load")
    if args.command == "load":
        print("bundled_image_loaded_and_verified")
        return 0
    if args.command in {"smoke", "doctor"}:
        execute(container_args(image) + ["/app/scripts/check_toolchain.py", "--quiet"], timeout=600)
        image_dry_run(image)
    if args.command == "smoke":
        args.model, args.set = "fake", "dev"
        args.timeout_s, args.max_turns, args.max_requests = 60, 8, 8
        lab(image, args)
        print("team_smoke_passed (local fake-model validation; no contest submission)")
    elif args.command == "tests":
        execute(container_args(image, repo=True) + ["-X", "utf8", "-m", "unittest", "discover", "-s", "tests", "-q"], timeout=600)
    elif args.command == "lab":
        lab(image, args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Team launcher: {exc}", file=sys.stderr)
        raise SystemExit(1)
