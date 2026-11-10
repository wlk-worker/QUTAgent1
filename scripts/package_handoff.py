"""Export an allowlisted teammate package without local credentials/history.

Run on Linux/WSL to include a locally built Docker image. The source-only path
also works with Python and Git on Windows. No registry credentials are exported.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ADDITIONS = ("scripts/team.py", "scripts/package_handoff.py", "docs/TEAM_START.md",
             "examples/llm.env.example", "examples/platform.env.example", "start.cmd", "start.sh")
ALLOWED_DIRS = {"agent", "author", "docs", "examples", "labs", "scripts", "tests", "toolbox"}
ALLOWED_ROOT = {".dockerignore", ".gitattributes", ".gitignore", "Dockerfile", "README.md", "requirements.lock", "start.cmd", "start.sh"}
KEY_NAMES = {"LLM_API_KEY", "CTFY_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}
TOKEN_PATTERN = re.compile(rb"\b(?:sk-[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")


def run(command, *, timeout=120):
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, timeout=timeout)
    return result.stdout


def digest(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def known_credentials():
    # Used in memory only, never printed or included in a manifest.
    values = {str(v) for k, v in os.environ.items()
              if any(term in k.upper() for term in ("KEY", "TOKEN", "PASSWORD", "SECRET")) and len(str(v)) >= 8}
    local_files = list((ROOT / "artifacts").glob("*.env")) + list(ROOT.glob(".env*"))
    for path in local_files:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.removeprefix("export ").strip() in KEY_NAMES:
                value = value.strip().strip("\"'")
                if len(value) >= 8 and not value.startswith("REPLACE_"):
                    values.add(value)
    return tuple(value.encode("utf-8") for value in values)


def audit_bytes(data, credentials, label):
    if any(value in data for value in credentials) or TOKEN_PATTERN.search(data):
        raise RuntimeError(f"Credential guard rejected {label}; values were not printed.")


def files_to_export():
    tracked = run(["git", "ls-files", "-z"]).decode("utf-8").split("\0")
    selected = set(ADDITIONS)
    for name in tracked:
        if not name:
            continue
        path = Path(name)
        if path.parts[0] in ALLOWED_DIRS or name in ALLOWED_ROOT:
            if not (name.startswith("author/generated/") or "__pycache__" in path.parts):
                selected.add(name)
    for name in sorted(selected):
        path = ROOT / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
            raise RuntimeError(f"Invalid export member: {name}")
        if path.suffix.lower() in {".env", ".key", ".pem", ".token", ".pyc"}:
            raise RuntimeError(f"Sensitive export suffix: {name}")
    return sorted(selected)


def image_metadata(image):
    data = json.loads(run(["docker", "image", "inspect", image]))[0]
    if data["Os"] != "linux" or data["Architecture"] != "amd64":
        raise RuntimeError("Expected a Linux/amd64 image.")
    for item in data["Config"].get("Env") or []:
        name, _, value = item.partition("=")
        if any(term in name.upper() for term in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")) and value:
            raise RuntimeError("Image contains a credential-like environment setting.")
    return {"id": data["Id"], "os": data["Os"], "architecture": data["Architecture"],
            "uncompressed_bytes": data["Size"], "user": data["Config"]["User"],
            "entrypoint": data["Config"]["Entrypoint"]}


def verify_image_sources(image, source_hashes):
    mapping = {name: "/app/" + name for name in source_hashes if name.startswith("agent/") and name.endswith(".py")}
    mapping.update({name: "/usr/local/bin/" + Path(name).name
                    for name in source_hashes if name.startswith("toolbox/bin/")})
    code = ("import json,hashlib,pathlib; paths=" + repr(mapping)
            + "; print(json.dumps({k:hashlib.sha256(pathlib.Path(v).read_bytes()).hexdigest() for k,v in paths.items()}))")
    observed = json.loads(run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code]))
    if any(source_hashes[name] != value for name, value in observed.items()):
        raise RuntimeError("Image code does not match current agent/toolbox sources. Rebuild before packaging.")
    return len(observed)


def export_image(image, destination, credentials):
    print("Exporting Docker image...", flush=True)
    with destination.open("wb") as output:
        process = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=6, mtime=0) as compressed:
                shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
            error = process.stderr.read()
            if process.wait(timeout=120):
                raise RuntimeError("docker save failed (details omitted to protect credentials).")
        finally:
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    verify_image_archive(destination, credentials)


def scan_stream(stream, credentials):
    overlap = max((len(value) for value in credentials), default=1) - 1
    tail = b""
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        data = tail + block
        if any(value in data for value in credentials):
            raise RuntimeError("Known credential found in image export; export refused.")
        tail = data[-overlap:] if overlap else b""


def verify_image_archive(destination, credentials):
    # Check the outer archive and decoded layer files, including deleted files
    # retained in old layers. No file names or values from layers are printed.
    print("Checking image archive and layer contents for known local credentials...", flush=True)
    with gzip.open(destination, "rb") as stream:
        scan_stream(stream, credentials)
    with tarfile.open(destination, "r:gz") as archive:
        manifest = archive.extractfile("manifest.json")
        if manifest is None:
            raise RuntimeError("Image export has no Docker manifest.json.")
        entries = json.load(manifest)
        layers = set()
        for entry in entries:
            config = archive.extractfile(entry["Config"])
            scan_stream(config, credentials)
            layers.update(entry["Layers"])
        for name in sorted(layers):
            blob = archive.extractfile(name)
            if blob is None:
                raise RuntimeError("Image layer missing.")
            with tarfile.open(fileobj=blob, mode="r|*") as layer:
                for member in layer:
                    if member.isfile():
                        content = layer.extractfile(member)
                        if content:
                            scan_stream(content, credentials)


def zip_tree(source, destination, *, include_image):
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source)
            if not include_image and relative.parts[0] == "runtime":
                continue
            archive.write(path, str(Path(source.name) / relative),
                          compress_type=zipfile.ZIP_STORED if path.suffix == ".gz" else zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("ZIP CRC verification failed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="qutagent:dev")
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--release-date", default=datetime.now(timezone.utc).strftime("%Y%m%d"))
    parser.add_argument("--audit-image-archive", type=Path, default=None)
    args = parser.parse_args()
    credentials = known_credentials()
    if args.audit_image_archive:
        verify_image_archive(args.audit_image_archive.resolve(), credentials)
        print("image_archive_audit_passed")
        return
    commit = run(["git", "rev-parse", "HEAD"]).decode().strip()
    if not re.fullmatch(r"\d{8}", args.release_date):
        parser.error("--release-date must be YYYYMMDD")
    name = "QUTAgent-team-" + args.release_date + "-" + commit[:7]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stage = output / (".stage-" + uuid.uuid4().hex[:8]) / name
    stage.mkdir(parents=True)
    hashes = {}
    for name_in_repo in files_to_export():
        data = (ROOT / name_in_repo).read_bytes()
        audit_bytes(data, credentials, name_in_repo)
        target = stage / name_in_repo
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if target.suffix == ".sh" or name_in_repo.startswith("toolbox/bin/"):
            target.chmod(0o755)
        hashes[name_in_repo] = hashlib.sha256(data).hexdigest()
    shutil.copyfile(stage / "docs" / "TEAM_START.md", stage / "START_HERE.md")
    hashes["START_HERE.md"] = digest(stage / "START_HERE.md")
    metadata = {"reference": "qutagent:team-" + args.release_date + "-" + commit[:7]}
    if not args.source_only:
        metadata.update(image_metadata(args.image))
        metadata["matched_code_files"] = verify_image_sources(args.image, hashes)
        run(["docker", "tag", args.image, metadata["reference"]])
        runtime = stage / "runtime" / "qutagent-linux-amd64.tar.gz"
        runtime.parent.mkdir()
        export_image(metadata["reference"], runtime, credentials)
        metadata["archive"] = "runtime/" + runtime.name
        metadata["archive_sha256"] = digest(runtime)
        metadata["archive_bytes"] = runtime.stat().st_size
    report = {"schema_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "base_commit": commit, "includes_uncommitted_handoff_files": True,
              "image": metadata, "source_sha256": hashes,
              "excluded": ["Git history", "artifacts/", "author/generated/", "_research/", "research/", "local env files", "Docker login configuration", "temporary directories"],
              "credential_scan": "Known local/environment credential values checked in source and uncompressed image export; source token-pattern scan passed. Not a guarantee about unknown secrets.",
              "verification": "See HANDOFF_VERIFICATION.md; contest approval is not implied."}
    (stage / "HANDOFF_MANIFEST.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (stage / "HANDOFF_VERIFICATION.md").write_text("Verification pending. The release builder will update this file after testing the extracted package.\n", encoding="utf-8")
    source_zip = output / (name + "-source.zip")
    if source_zip.exists():
        raise FileExistsError("Release already exists; choose a new --output directory.")
    zip_tree(stage, source_zip, include_image=False)
    full_zip = output / (name + "-full.zip")
    if not args.source_only:
        if full_zip.exists():
            raise FileExistsError("Release already exists; choose a new --output directory.")
        zip_tree(stage, full_zip, include_image=True)
    (output / "handoff-build.json").write_text(json.dumps({"stage": str(stage), "source_zip": str(source_zip),
            "full_zip": str(full_zip) if not args.source_only else None}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage": str(stage), "source_zip": str(source_zip),
                      "full_zip": str(full_zip) if not args.source_only else None}, indent=2))


if __name__ == "__main__":
    main()
