"""Authoring controller for the CTFY-0002 peer-authoring flow.

One controlled pass per candidate challenge:

1. select (or generate) a seed challenge package with :mod:`author.generate`;
2. run the strongest local audit/smoke that the installed CLI actually offers
   (``ctfy authoring check/smoke --local`` when present, otherwise the
   ``ctfy-admin challenge audit --strict`` / ``smoke`` pair from CTFy 0.7.0);
3. pack a deterministic ``.tar.gz`` (LF text, build junk excluded) and hash it;
4. write a report that contains no flag, no token and no credential;
5. optionally upload it, only when ``--authorized`` is given **and** the
   platform URL and token come from the environment, then read back the status
   with GET only. A dry run never opens a network connection.

The upload request shape is taken from the CTFy 0.7.0 source snapshot in
``_research/ctfy/pypi/extracted``:

* ``POST /api/v1/competitions/{competition_id}/authored-challenges``
* multipart form fields: ``slug`` (author label) and
  ``file`` (``<slug>.tar.gz``, ``application/gzip``);
* success is ``201`` and the row carries the server-minted ``id``,
  ``review_status`` (starts ``pending``) and ``auto_smoke``;
* read-back is ``GET .../authored-challenges`` and
  ``GET .../authored-challenges/{challenge_id}/audit``.

The platform is authoritative. This module never claims upload success unless
the platform answered, and never treats an upload as review or publication.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:  # package import (``python -m author.controller``)
    from .generate import generate
except ImportError:  # direct script import (``python author/controller.py``)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from author.generate import generate


SCHEMA_VERSION = 1
API_PREFIX = "/api/v1"
PLATFORM_URL_ENV = "CTFY_PLATFORM_URL"
TOKEN_ENV = "CTFY_TOKEN"

AUTHORED_PATH = "/competitions/{competition_id}/authored-challenges"
AUDIT_PATH = AUTHORED_PATH + "/{challenge_id}/audit"

ARCHIVE_DEFAULT_DIR = Path("artifacts") / "authoring"
PACKAGE_DEFAULT_ROOT = Path("author") / "generated"
USER_AGENT = "QUTAgent-authoring-controller/1 (dry-run by default)"

#: Directory names never packed. Mirrors CTFy's own packer so a locally built
#: archive and ``ctfy authoring upload`` cannot disagree about build junk.
SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".venv"})
SKIP_FILES = frozenset({".DS_Store"})
#: Extensions whose CRLF is normalised to LF before packing. The generated
#: ``rotate.sh`` broke a real smoke run once because Windows wrote CRLF; the
#: platform stores bytes verbatim, so the controller normalises text members.
TEXT_SUFFIXES = frozenset({".sh", ".py", ".yml", ".yaml", ".json", ".md", ".txt",
                           ".conf", ".cfg", ".ini", ".toml", ".service"})
TEXT_NAMES = frozenset({"Dockerfile", "AUTHORING.md"})

_TOOL_PROBE_TIMEOUT_S = 15.0
_CHECK_TIMEOUT_S = 300.0
_SECRET_ENV_KEYS = (
    "CTFY_TOKEN",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
)
MAX_REPORTED_REASONS = 12
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_EXCERPT = 1200


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuthoringError(Exception):
    """Base class for a controlled failure; the message never holds secrets."""


class BlockedError(AuthoringError):
    """The requested action cannot run without missing configuration/consent."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        self.message = message
        super().__init__(f"{reason}: {message}")


class TransportError(AuthoringError):
    """No trustworthy answer from the platform.

    For a POST this is *result unknown*: the request may or may not have been
    applied. The controller records that fact and does not retry the mutation.
    """

    def __init__(self, message: str, *, mutation_outcome_unknown: bool = False) -> None:
        self.mutation_outcome_unknown = mutation_outcome_unknown
        super().__init__(message)


class RefusedError(AuthoringError):
    """The platform answered with a 3xx/4xx/5xx refusal envelope."""

    def __init__(self, status: int, code: str, detail: str,
                 reasons: Iterable[str] = ()) -> None:
        self.status = status
        self.code = code
        self.detail = detail
        self.reasons = list(reasons)
        text = f"HTTP {status}"
        if code:
            text += f" {code}"
        if detail:
            text += f": {detail}"
        if self.reasons:
            text += "; " + "; ".join(self.reasons[:MAX_REPORTED_REASONS])
        super().__init__(text)


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


def environment_secrets(environ: Mapping[str, str] | None = None) -> list[str]:
    """Credential values known in this process, for redaction only."""
    env = os.environ if environ is None else environ
    values: list[str] = []
    for key in _SECRET_ENV_KEYS:
        value = env.get(key, "")
        if value and len(value) >= 4:
            values.append(value)
    return values


def redact(text: str, secrets: Iterable[str]) -> str:
    """Remove every known credential value from ``text``."""
    if not text:
        return text
    for value in sorted((s for s in secrets if s), key=len, reverse=True):
        if value and value in text:
            text = text.replace(value, "[REDACTED]")
    return text


# ---------------------------------------------------------------------------
# HTTP transport (stdlib only, injectable for tests)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is not an answer this tool may follow.

    Following it would send the bearer token to whatever host the response
    names, which is exactly the trust boundary the uploader must not cross.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass(frozen=True)
class MultipartFile:
    field: str
    filename: str
    content: bytes
    content_type: str = "application/gzip"


def encode_multipart(fields: Mapping[str, str], file: MultipartFile,
                     *, boundary: str | None = None) -> tuple[bytes, str]:
    """Encode the exact form body CTFy's upload route reads (``slug`` + file)."""
    boundary = boundary or ("qutagent" + secrets.token_hex(16))
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(b"--" + boundary.encode("ascii"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"'.encode("utf-8"))
        chunks.append(b"")
        chunks.append(str(value).encode("utf-8"))
    chunks.append(b"--" + boundary.encode("ascii"))
    chunks.append(
        (f'Content-Disposition: form-data; name="{file.field}"; '
         f'filename="{file.filename}"').encode("utf-8")
    )
    chunks.append(f"Content-Type: {file.content_type}".encode("ascii"))
    chunks.append(b"")
    chunks.append(file.content)
    chunks.append(b"--" + boundary.encode("ascii") + b"--")
    chunks.append(b"")
    body = b"\r\n".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


def _decode_envelope(body: bytes) -> tuple[str, str, list[str]]:
    """``(code, detail, reasons)`` from the platform's error envelope.

    Source: ``ctfy.server.error_handlers`` / ``ctfy.sdk._helpers`` — the body
    is ``{"code": ..., "detail": ...}`` where ``detail`` is either a string or
    ``{"message": ..., "reasons": [...]}``.
    """
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return "", body[:500].decode("utf-8", "replace").strip(), []
    if not isinstance(payload, dict):
        return "", "", []
    code = str(payload.get("code") or "")
    detail = payload.get("detail")
    reasons: list[str] = []
    if isinstance(detail, dict):
        message = str(detail.get("message") or "")
        raw_reasons = detail.get("reasons")
        if isinstance(raw_reasons, list):
            reasons = [str(item) for item in raw_reasons[:MAX_REPORTED_REASONS]]
        detail_text = message
    elif detail is None:
        detail_text = ""
    else:
        detail_text = str(detail)
    return code, detail_text, reasons


class PlatformHttp:
    """Minimal ``/api/v1`` client with bearer auth and no redirects.

    ``opener`` is injectable so tests can assert that a dry run sends zero
    requests. The token is held for the ``Authorization`` header only and is
    never placed in a report, log line or exception.
    """

    def __init__(self, base_url: str, token: str, *,
                 opener: Any = None,
                 timeout: float = 30.0,
                 max_response_bytes: int = _MAX_RESPONSE_BYTES,
                 secrets: Iterable[str] = ()) -> None:
        root = base_url.rstrip("/")
        self.base_url = root if root.endswith(API_PREFIX) else root + API_PREFIX
        self._token = token
        self._secrets = tuple(secrets)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        handlers: list[Any] = [_NoRedirect()]
        self._opener = opener or urllib.request.build_opener(*handlers)
        self.requests_sent = 0

    @property
    def secrets(self) -> tuple[str, ...]:
        """Credential values this client must redact from anything it reports."""
        return self._secrets

    def _url(self, path: str) -> str:
        return self.base_url + (path if path.startswith("/") else "/" + path)

    def request(self, method: str, path: str, *,
                json_body: Mapping[str, Any] | None = None,
                multipart: tuple[Mapping[str, str], MultipartFile] | None = None,
                accept: str = "application/json") -> HttpResponse:
        body: bytes | None = None
        content_type = ""
        if multipart is not None:
            fields, file = multipart
            body, content_type = encode_multipart(fields, file)
        elif json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            content_type = "application/json"
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if content_type:
            headers["Content-Type"] = content_type
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(self._url(path), data=body,
                                         headers=headers, method=method.upper())
        self.requests_sent += 1
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raw = self._read_bounded(exc, method)
            code, detail, reasons = _decode_envelope(raw)
            raise RefusedError(exc.code, redact(code, self._secrets),
                               redact(detail, self._secrets),
                               [redact(r, self._secrets) for r in reasons]) from None
        except urllib.error.URLError as exc:
            reason = redact(str(getattr(exc, "reason", exc)), self._secrets)
            raise TransportError(
                f"network error on {method.upper()} {self._url(path)}: {reason}",
                mutation_outcome_unknown=method.upper() != "GET",
            ) from None
        except OSError as exc:  # socket timeouts that are not URLError
            raise TransportError(
                f"transport error on {method.upper()} {self._url(path)}: "
                f"{redact(type(exc).__name__, self._secrets)}",
                mutation_outcome_unknown=method.upper() != "GET",
            ) from None
        raw = self._read_bounded(response, method)
        status = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 0)
        return HttpResponse(status, dict(getattr(response, "headers", {}) or {}), raw)

    def _read_bounded(self, response: Any, method: str) -> bytes:
        try:
            raw = response.read(self.max_response_bytes + 1)
        except OSError as exc:
            raise TransportError(
                f"read error on {method.upper()}: {type(exc).__name__}",
                mutation_outcome_unknown=method.upper() != "GET",
            ) from None
        if len(raw) > self.max_response_bytes:
            raise TransportError(
                f"response exceeded {self.max_response_bytes} bytes",
                mutation_outcome_unknown=method.upper() != "GET",
            )
        return raw

    def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.request(method, path, **kwargs)
        if not 200 <= response.status < 300:
            code, detail, reasons = _decode_envelope(response.body)
            raise RefusedError(response.status, redact(code, self._secrets),
                               redact(detail, self._secrets),
                               [redact(r, self._secrets) for r in reasons])
        try:
            return response.json()
        except ValueError:
            raise TransportError(
                f"non-JSON response on {method.upper()} {self._url(path)}",
                mutation_outcome_unknown=method.upper() != "GET",
            ) from None


# ---------------------------------------------------------------------------
# Local tool discovery and checks
# ---------------------------------------------------------------------------


@dataclass
class Tooling:
    """What the locally installed CTFy CLI can actually do."""

    ctfy: str | None = None
    ctfy_admin: str | None = None
    ctfy_version: str = ""
    ctfy_admin_version: str = ""
    authoring_check: bool = False
    authoring_smoke_local: bool = False
    authoring_subcommands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def any_tool(self) -> bool:
        return bool(self.ctfy or self.ctfy_admin)


def _run_probe(run: Any, command: list[str], *, timeout: float,
               env: Mapping[str, str] | None) -> tuple[int, str]:
    try:
        completed = run(command, capture_output=True, text=True, timeout=timeout,
                        env=dict(env) if env is not None else None)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, type(exc).__name__
    output = ((getattr(completed, "stdout", "") or "")
              + (getattr(completed, "stderr", "") or ""))
    return int(getattr(completed, "returncode", -1)), output


def _cli_version(run: Any, cli: str, env: Mapping[str, str] | None) -> str:
    for flag in ("--version", "-V"):
        code, output = _run_probe(run, [cli, flag], timeout=_TOOL_PROBE_TIMEOUT_S, env=env)
        if code == 0 and output.strip():
            return output.strip().splitlines()[0][:200]
    return ""


def _parse_subcommands(help_text: str) -> list[str]:
    found: list[str] = []
    for line in help_text.splitlines():
        match = re.match(r"^\s{0,6}([a-z][a-z0-9-]{1,30})\b", line)
        if match:
            found.append(match.group(1))
    return sorted(set(found))


def discover_tooling(*, ctfy: str | None = None, ctfy_admin: str | None = None,
                     run: Any = subprocess.run,
                     which: Any = shutil.which,
                     env: Mapping[str, str] | None = None) -> Tooling:
    """Detect the CLI commands and whether the CTFY-0002 authoring pair exists.

    ``ctfy authoring check`` / ``ctfy authoring smoke --local`` are the
    documented commands but are absent from PyPI ctfy 0.7.0. Detection is by
    the live ``ctfy authoring --help`` text so the recorded evidence says what
    was actually available, not what the standard says.
    """
    resolved_ctfy = ctfy or which("ctfy")
    resolved_admin = ctfy_admin or which("ctfy-admin")
    tooling = Tooling(ctfy=resolved_ctfy, ctfy_admin=resolved_admin)
    check_env = dict(env) if env is not None else None
    if resolved_ctfy:
        tooling.ctfy_version = _cli_version(run, resolved_ctfy, check_env)
        code, output = _run_probe(run, [resolved_ctfy, "authoring", "--help"],
                                  timeout=_TOOL_PROBE_TIMEOUT_S, env=check_env)
        if code == 0:
            tooling.authoring_subcommands = _parse_subcommands(output)
            tooling.authoring_check = "check" in tooling.authoring_subcommands
            tooling.authoring_smoke_local = (
                "smoke" in tooling.authoring_subcommands and "--local" in output
            )
            if not (tooling.authoring_check and tooling.authoring_smoke_local):
                tooling.notes.append(
                    "ctfy authoring exists but does not advertise check + "
                    "smoke --local; using the ctfy-admin fallback")
        else:
            tooling.notes.append("ctfy authoring --help failed; no preferred CLI path")
    if resolved_admin:
        tooling.ctfy_admin_version = _cli_version(run, resolved_admin, check_env)
    if not tooling.any_tool:
        tooling.notes.append(
            "neither ctfy nor ctfy-admin is on PATH; local audit/smoke did not run")
    return tooling


def _check_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for a local check child: credentials deliberately removed."""
    env = dict(os.environ if environ is None else environ)
    for key in _SECRET_ENV_KEYS:
        env.pop(key, None)
    return env


def plan_checks(tooling: Tooling, package: Path, output_root: Path,
                smoke_runs: int) -> list[dict[str, Any]]:
    """Build the local-check command list from what this CLI actually offers."""
    specs: list[dict[str, Any]] = []
    if tooling.ctfy and tooling.authoring_check:
        specs.append({
            "kind": "authoring_check",
            "source": "ctfy authoring check (preferred CLI)",
            "command": [tooling.ctfy, "authoring", "check", str(package)],
        })
        if tooling.authoring_smoke_local:
            for _ in range(smoke_runs):
                specs.append({
                    "kind": "authoring_smoke_local",
                    "source": "ctfy authoring smoke --local (preferred CLI)",
                    "command": [tooling.ctfy, "authoring", "smoke", str(package),
                                "--local"],
                })
        return specs
    if tooling.ctfy_admin:
        specs.append({
            "kind": "admin_audit",
            "source": "ctfy-admin challenge audit --strict (0.7.0 fallback)",
            "command": [tooling.ctfy_admin, "challenge", "audit", package.name,
                        "--challenges-dir", str(output_root), "--strict", "--json"],
        })
        for _ in range(smoke_runs):
            specs.append({
                "kind": "admin_smoke",
                "source": "ctfy-admin challenge smoke (0.7.0 fallback)",
                "command": [tooling.ctfy_admin, "challenge", "smoke", package.name,
                            "--challenges-dir", str(output_root),
                            "--ephemeral-ports", "--timeout", "180"],
            })
    return specs


def run_checks(specs: list[dict[str, Any]], *, run: Any = subprocess.run,
               env: Mapping[str, str] | None = None,
               secrets: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Execute planned checks, stopping at the first failure; never leaks env."""
    results: list[dict[str, Any]] = []
    check_env = _check_environment(env)
    for spec in specs:
        started = time.monotonic()
        code, output = _run_probe(run, list(spec["command"]),
                                  timeout=_CHECK_TIMEOUT_S, env=check_env)
        elapsed = round(time.monotonic() - started, 2)
        excerpt = redact(output.strip()[-_MAX_OUTPUT_EXCERPT:], secrets)
        result = {
            "kind": spec["kind"],
            "source": spec["source"],
            "command": [Path(str(part)).name if index == 0 else str(part)
                        for index, part in enumerate(spec["command"])],
            "exit_code": code,
            "elapsed_s": elapsed,
            "passed": code == 0,
            "failure": "" if code == 0 else ("check_failed" if code > 0 else "check_error"),
            "output_excerpt": excerpt,
        }
        results.append(result)
        if code != 0:
            break
    return results


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------


def _iter_packable_files(root: Path) -> tuple[dict[str, bytes], list[str]]:
    """Read regular files below ``root``; report what is excluded."""
    files: dict[str, bytes] = {}
    skipped: list[str] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            path = here / dirname
            relative = path.relative_to(root)
            if dirname in SKIP_DIRS:
                skipped.append(relative.as_posix() + "/")
                continue
            if path.is_symlink():
                skipped.append(relative.as_posix() + "/ (symlink)")
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            path = here / filename
            relative = path.relative_to(root)
            if filename in SKIP_FILES:
                skipped.append(relative.as_posix())
                continue
            if path.is_symlink() or not path.is_file():
                skipped.append(relative.as_posix() + " (not a regular file)")
                continue
            files[relative.as_posix()] = path.read_bytes()
    return files, sorted(skipped)


def _normalise_text(name: str, body: bytes) -> tuple[bytes, bool]:
    suffix = Path(name).suffix.lower()
    if suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES:
        return body, False
    if b"\r\n" not in body:
        return body, False
    return body.replace(b"\r\n", b"\n"), True


def _pack_files(files: Mapping[str, bytes], prefix: str) -> bytes:
    """Deterministic ``.tar.gz``: sorted members, PAX, mode 0644, mtime 0.

    The wrapping directory is the server's documented shape (one leading
    component is stripped server-side). Gzip mtime is pinned so the sha256 is
    stable for one tree.
    """
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name in sorted(files):
                body = files[name]
                info = tarfile.TarInfo(name=f"{prefix}/{name}")
                info.size = len(body)
                info.mode = 0o644
                info.mtime = 0
                tar.addfile(info, io.BytesIO(body))
    return raw.getvalue()


def build_archive(package: Path, archive_path: Path | None = None) -> dict[str, Any]:
    """Pack ``package`` and return the metadata the report records."""
    root = package.resolve()
    if not root.is_dir():
        raise BlockedError("package_missing", f"package directory does not exist: {package}")
    if not (root / "metadata.yaml").is_file():
        raise BlockedError("package_invalid",
                           f"package has no metadata.yaml: {package}")
    files, skipped = _iter_packable_files(root)
    if not files:
        raise BlockedError("package_empty", f"package has no regular files: {package}")
    normalised: list[str] = []
    for name, body in list(files.items()):
        files[name], changed = _normalise_text(name, body)
        if changed:
            normalised.append(name)
    blob = _pack_files(files, root.name)
    digest = hashlib.sha256(blob).hexdigest()
    target = Path(archive_path) if archive_path else (ARCHIVE_DEFAULT_DIR
                                                      / f"{root.name}.tar.gz")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(blob)
    return {
        "path": str(target),
        "sha256": digest,
        "size_bytes": len(blob),
        "file_count": len(files),
        "members": sorted(files),
        "skipped": skipped,
        "crlf_normalised": sorted(normalised),
        "wrapping_directory": root.name,
        "format": "tar.gz (gzip mtime 0, PAX, mode 0644, sorted members)",
    }


# ---------------------------------------------------------------------------
# Seed selection / generation
# ---------------------------------------------------------------------------


def _pick_unused_seed(output_root: Path) -> int:
    for _ in range(50):
        candidate = secrets.randbits(32)
        if not (output_root / f"document-desk-{candidate}").exists():
            return candidate
    raise AuthoringError("could not choose an unused seed")


def select_or_generate_package(*, seed: int | None = None,
                               package: Path | None = None,
                               output_root: Path = PACKAGE_DEFAULT_ROOT) -> dict[str, Any]:
    """Generate a seed package, or reuse an existing one as the candidate.

    An existing ``document-desk-<seed>`` directory is reused (the controller
    never overwrites it); the report records ``package_source`` so a later
    reader can tell a fresh generation from a reused tree.
    """
    output_root = Path(output_root)
    if package is not None:
        target = Path(package)
        if not target.is_dir():
            raise BlockedError("package_missing", f"package directory does not exist: {target}")
        return {"package": target, "seed": seed, "package_source": "selected"}
    if seed is None:
        seed = _pick_unused_seed(output_root)
    target = output_root / f"document-desk-{seed}"
    if target.is_dir() and any(target.iterdir()):
        return {"package": target, "seed": seed, "package_source": "reused"}
    output_root.mkdir(parents=True, exist_ok=True)
    generate(target, seed)
    return {"package": target, "seed": seed, "package_source": "generated"}


# ---------------------------------------------------------------------------
# Upload and read-back
# ---------------------------------------------------------------------------


def validate_slug(slug: str) -> str:
    """Mirror the server's label rules locally to fail before packing.

    Source: ``ctfy.core.authored_challenges.authored_challenge_slug`` — fold
    whitespace/dashes/case, then require ``^[A-Z0-9]+(-[A-Z0-9]+)*$``.
    """
    folded = "-".join(part for part in slug.strip().split("-") if part).lower()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", folded):
        raise BlockedError(
            "invalid_slug",
            f"{slug!r} is not a usable challenge name: letters, digits and dashes",
        )
    return folded


def upload_body(slug: str, archive: bytes) -> tuple[Mapping[str, str], MultipartFile]:
    return ({"slug": slug}, MultipartFile(
        field="file",
        filename=f"{slug}.tar.gz",
        content=archive,
        content_type="application/gzip",
    ))


def _request_shape(competition_id: str, slug: str, archive: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": "POST",
        "path": API_PREFIX + AUTHORED_PATH.format(competition_id=competition_id),
        "multipart_fields": ["slug", "file"],
        "slug": slug,
        "file": {
            "field": "file",
            "filename": f"{slug}.tar.gz",
            "content_type": "application/gzip",
            "sha256": archive["sha256"],
            "size_bytes": archive["size_bytes"],
        },
        "authorization": "Bearer <redacted: read from CTFY_TOKEN in the environment>",
    }


def _safe_upload_row(payload: Any, secrets: Iterable[str]) -> dict[str, Any]:
    """Only the fields this report needs, all redacted."""
    if not isinstance(payload, dict):
        return {"raw_type": type(payload).__name__}
    auto_smoke = payload.get("auto_smoke")
    if isinstance(auto_smoke, dict):
        auto_smoke = {key: auto_smoke.get(key)
                      for key in ("outcome", "budget", "remaining", "available_at")}
    else:
        auto_smoke = None
    keys = ("id", "slug", "title", "review_status", "reviewed_at", "review_note",
            "file_count", "total_bytes", "smoke_verdict", "smoke_in_flight",
            "in_catalog", "curation", "destination")
    row = {key: payload.get(key) for key in keys if key in payload}
    row["auto_smoke"] = auto_smoke
    row["platform_reviewed"] = row.get("review_status") in {"approved", "rejected"}
    return json.loads(redact(json.dumps(row, ensure_ascii=False), secrets))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def poll_authored_status(client: PlatformHttp, competition_id: str, *,
                         challenge_id: str = "", slug: str = "",
                         wait_seconds: float = 0.0, interval: float = 2.0,
                         sleep: Any = time.sleep, clock: Any = time.monotonic) -> dict[str, Any]:
    """Read-only review/audit polling. Never uploads again."""
    deadline = clock() + max(0.0, wait_seconds)
    rounds: list[dict[str, Any]] = []
    final: dict[str, Any] = {"status": "unknown"}
    while True:
        rows = client.request_json("GET", AUTHORED_PATH.format(
            competition_id=competition_id))
        if not isinstance(rows, list):
            rows = []
        row = None
        for candidate in rows:
            if not isinstance(candidate, dict):
                continue
            if challenge_id and candidate.get("id") == challenge_id:
                row = candidate
                break
            if not challenge_id and slug and candidate.get("slug") == slug:
                row = candidate
                break
        entry: dict[str, Any] = {"checked_at": _iso_now(), "row_found": row is not None}
        if row is not None:
            challenge_id = str(row.get("id") or challenge_id)
            entry.update({
                "id": row.get("id"),
                "slug": row.get("slug"),
                "review_status": row.get("review_status"),
                "review_note": redact(str(row.get("review_note") or ""), client.secrets),
                "smoke_verdict": row.get("smoke_verdict"),
                "smoke_in_flight": row.get("smoke_in_flight"),
                "in_catalog": row.get("in_catalog"),
                "curation": row.get("curation"),
            })
            if challenge_id:
                try:
                    audit = client.request_json("GET", AUDIT_PATH.format(
                        competition_id=competition_id, challenge_id=challenge_id))
                except RefusedError as exc:
                    entry["audit"] = {"unavailable": True, "status": exc.status,
                                      "code": exc.code}
                else:
                    if isinstance(audit, dict):
                        findings = audit.get("findings") or []
                        entry["audit"] = {
                            "outcome": audit.get("outcome"),
                            "errors": audit.get("errors"),
                            "warnings": audit.get("warnings"),
                            "truncated": audit.get("truncated"),
                            "finding_count": len(findings) if isinstance(findings, list) else None,
                        }
                    else:
                        entry["audit"] = {"unexpected": type(audit).__name__}
            final = entry
        rounds.append(entry)
        status = str(entry.get("review_status") or "")
        if status in {"approved", "rejected"}:
            break
        if clock() >= deadline:
            break
        sleep(interval)
    return {
        "wait_seconds": wait_seconds,
        "interval_s": interval,
        "rounds": rounds,
        "final": final,
        "timed_out": final.get("review_status") not in {"approved", "rejected"},
        "read_only": True,
        "uploaded_again": False,
    }


# ---------------------------------------------------------------------------
# Report / flow
# ---------------------------------------------------------------------------


def write_json_report(report: Mapping[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    return path


def _report_path(archive_dir: Path | None, slug: str) -> Path:
    return (Path(archive_dir) if archive_dir else ARCHIVE_DEFAULT_DIR) / f"{slug}.authoring-report.json"


def run_authoring_flow(*, seed: int | None = None,
                       package: Path | None = None,
                       output_root: Path = PACKAGE_DEFAULT_ROOT,
                       archive_path: Path | None = None,
                       report_path: Path | None = None,
                       competition_id: str = "",
                       authorized: bool = False,
                       token: str | None = None,
                       platform_url: str | None = None,
                       smoke_runs: int = 1,
                       poll: bool = False,
                       wait_seconds: float = 0.0,
                       interval: float = 2.0,
                       ctfy: str | None = None,
                       ctfy_admin: str | None = None,
                       tooling: Tooling | None = None,
                       run: Any = subprocess.run,
                       opener: Any = None,
                       environ: Mapping[str, str] | None = None,
                       sleep: Any = time.sleep,
                       clock: Any = time.monotonic) -> dict[str, Any]:
    """Run one controlled authoring pass and return a secret-free report.

    Expected outcomes are encoded in ``status`` / ``exit_code`` rather than
    raised, so a blocked or refused run still leaves inspectable evidence.
    """
    env = os.environ if environ is None else environ
    secrets_found = environment_secrets(env)
    chosen_token = token if token is not None else env.get(TOKEN_ENV, "")
    if chosen_token and chosen_token not in secrets_found and len(chosen_token) >= 4:
        secrets_found.append(chosen_token)
    chosen_url = platform_url if platform_url is not None else env.get(PLATFORM_URL_ENV, "")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _iso_now(),
        "mode": "authorized_upload" if authorized else "dry_run",
        "network_sent": False,
        "uploaded": False,
        "platform_reviewed": False,
        "status": "unknown",
        "exit_code": 0,
        "seed": seed,
        "competition_id": competition_id,
        "checks": [],
        "archive": None,
        "upload": {
            "attempted": False,
            "request": None,
            "response": None,
            "refusal": None,
            "transport": None,
            "uploaded": False,
            "review_status": None,
            "platform_reviewed": False,
        },
        "poll": None,
        "evidence_level": "",
        "flag_included_in_report": False,
        "secrets_in_report": False,
        "notes": [],
    }

    def finish(status: str, exit_code: int, evidence: str) -> dict[str, Any]:
        report["status"] = status
        report["exit_code"] = exit_code
        report["evidence_level"] = evidence
        report["upload"]["uploaded"] = bool(report["upload"]["uploaded"])
        report["upload"]["platform_reviewed"] = bool(report["upload"]["platform_reviewed"])
        report["uploaded"] = bool(report["upload"]["uploaded"])
        report["platform_reviewed"] = bool(report["upload"]["platform_reviewed"])
        target = Path(report_path) if report_path else _report_path(
            Path(str((report.get("archive") or {}).get("path", ""))).parent
            if report.get("archive") else ARCHIVE_DEFAULT_DIR,
            str(report.get("slug") or "candidate"),
        )
        report["report_path"] = str(target)
        serialised = json.dumps(report, ensure_ascii=False)
        report["flag_included_in_report"] = bool(
            re.search(r"(?:ctfy|flag)\{[^}]*\}", serialised))
        serialised = json.dumps(report, ensure_ascii=False)
        leaked = [value for value in secrets_found if value and value in serialised]
        report["secrets_in_report"] = bool(leaked)
        if leaked:  # defence in depth: never persist a report with a token in it
            report["notes"].append("redaction_guard_tripped; report replaced with safe stub")
            for key in ("upload", "checks", "archive", "poll"):
                report[key] = None
            serialised = json.dumps(report, ensure_ascii=False)
        write_json_report(json.loads(serialised), target)
        return report

    def blocked(reason: str, message: str) -> dict[str, Any]:
        report["upload"]["attempted"] = False
        report["blocked"] = {"reason": reason, "message": message}
        report["notes"].append(message)
        return finish("blocked", 2, "blocked_" + reason)

    # -- consent gate -----------------------------------------------------
    if authorized:
        if not competition_id:
            return blocked("missing_competition_id",
                           "authorized upload needs --competition-id")
        if not chosen_url:
            return blocked("missing_platform_url",
                           f"authorized upload needs {PLATFORM_URL_ENV} in the environment")
        if not chosen_token:
            return blocked("missing_token",
                           f"authorized upload needs {TOKEN_ENV} in the environment "
                           "(never pass a token on the command line)")
    report["platform_url_configured"] = bool(chosen_url)
    report["token_configured"] = bool(chosen_token)

    # -- package ----------------------------------------------------------
    try:
        selection = select_or_generate_package(seed=seed, package=package,
                                               output_root=output_root)
    except (BlockedError, AuthoringError) as exc:
        return blocked(getattr(exc, "reason", "package_error"), str(exc))
    report["seed"] = selection["seed"]
    report["package"] = str(selection["package"])
    report["package_source"] = selection["package_source"]
    slug = validate_slug(selection["package"].name)
    report["slug"] = slug

    # -- local checks -----------------------------------------------------
    if tooling is None:
        tooling = discover_tooling(ctfy=ctfy, ctfy_admin=ctfy_admin, run=run,
                                   env=env)
    report["tooling"] = {
        "ctfy": tooling.ctfy,
        "ctfy_version": tooling.ctfy_version,
        "ctfy_admin": tooling.ctfy_admin,
        "ctfy_admin_version": tooling.ctfy_admin_version,
        "authoring_check": tooling.authoring_check,
        "authoring_smoke_local": tooling.authoring_smoke_local,
        "notes": tooling.notes,
    }
    specs = plan_checks(tooling, selection["package"], output_root, max(0, smoke_runs))
    if specs:
        checks = run_checks(specs, run=run, env=env, secrets=secrets_found)
        report["checks"] = checks
        passed = all(item["passed"] for item in checks) and len(checks) == len(specs)
    else:
        checks = []
        passed = None
    report["local_checks"] = {
        "planned": len(specs),
        "executed": len(checks),
        "passed": passed,
        "available": bool(specs),
        "evidence": (
            "local_checks_passed" if passed is True
            else "local_checks_failed" if passed is False
            else "local_checks_unavailable"
        ),
        "note": (
            "no ctfy/ctfy-admin on PATH; local audit and smoke did not run, so "
            "this package is packaged and hashed but not locally validated"
            if passed is None else ""
        ),
    }

    # -- archive ----------------------------------------------------------
    try:
        archive = build_archive(selection["package"], archive_path)
    except (BlockedError, AuthoringError) as exc:
        return blocked(getattr(exc, "reason", "archive_error"), str(exc))
    report["archive"] = archive
    if report_path is None:
        report_path = _report_path(Path(archive["path"]).parent, slug)

    if passed is False:
        report["notes"].append(
            "local audit/smoke failed; the package is left packaged for inspection "
            "and was not uploaded")
        return finish("local_validation_failed", 1, "local_checks_failed")

    # -- dry run ----------------------------------------------------------
    planned = _request_shape(competition_id or "{competition_id}", slug, archive)
    report["upload"]["request"] = planned
    if not authorized:
        report["notes"].append(
            "dry run: no HTTP request was built into a connection; use --authorized "
            "with CTFY_PLATFORM_URL and CTFY_TOKEN to upload")
        return finish("dry_run", 0, "local_packaged_unsubmitted")

    # -- authorized upload ------------------------------------------------
    client = PlatformHttp(chosen_url, chosen_token, opener=opener,
                          secrets=secrets_found)
    body = upload_body(slug, Path(archive["path"]).read_bytes())
    report["upload"]["attempted"] = True
    try:
        response = client.request("POST", AUTHORED_PATH.format(
            competition_id=competition_id), multipart=body)
    except RefusedError as exc:
        report["network_sent"] = True
        report["upload"]["refusal"] = {
            "status": exc.status,
            "code": exc.code,
            "detail": exc.detail,
            "reasons": exc.reasons,
        }
        report["notes"].append(
            "platform refused the upload; the local package remains unsubmitted")
        return finish("refused", 3, "upload_refused")
    except TransportError as exc:
        report["network_sent"] = True
        report["upload"]["transport"] = {
            "message": redact(str(exc), secrets_found),
            "mutation_outcome_unknown": exc.mutation_outcome_unknown,
        }
        report["notes"].append(
            "upload POST outcome is unknown; the controller does not retry a "
            "mutation after a transport failure")
        return finish("transport_unknown", 3, "upload_outcome_unknown")

    report["network_sent"] = True
    report["upload"]["http_status"] = response.status
    if not 200 <= response.status < 300:
        code, detail, reasons = _decode_envelope(response.body)
        report["upload"]["refusal"] = {
            "status": response.status,
            "code": redact(code, secrets_found),
            "detail": redact(detail, secrets_found),
            "reasons": [redact(item, secrets_found) for item in reasons],
        }
        return finish("refused", 3, "upload_refused")
    try:
        payload = response.json()
    except ValueError:
        report["notes"].append("platform accepted the POST but the response was not JSON")
        payload = {}
    row = _safe_upload_row(payload, secrets_found)
    report["upload"]["response"] = row
    report["upload"]["uploaded"] = True
    report["upload"]["review_status"] = row.get("review_status")
    report["upload"]["platform_reviewed"] = bool(row.get("platform_reviewed"))
    report["notes"].append(
        "upload accepted by the platform; review_status is not approval and no "
        "entry is created by uploading")
    challenge_id = str(row.get("id") or "")

    # -- read-only follow-up ---------------------------------------------
    if poll or wait_seconds > 0:
        try:
            report["poll"] = poll_authored_status(
                client, competition_id, challenge_id=challenge_id, slug=slug,
                wait_seconds=wait_seconds, interval=interval, sleep=sleep,
                clock=clock)
        except RefusedError as exc:
            report["poll"] = {"read_only": True, "error_status": exc.status,
                              "error_code": exc.code, "uploaded_again": False}
        final_status = ""
        if report["poll"]:
            final_status = str((report["poll"].get("final") or {}).get("review_status") or "")
        if final_status:
            report["upload"]["review_status"] = final_status
            report["upload"]["platform_reviewed"] = final_status in {"approved", "rejected"}
    if report["upload"]["platform_reviewed"]:
        return finish("uploaded_and_reviewed", 0, "uploaded_operator_reviewed")
    return finish("uploaded_pending_review", 0, "uploaded_pending_operator_review")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CTFY-0002 authoring controller: package, check, optional "
                    "authorized upload, read-only review polling.")
    parser.add_argument("--seed", type=int,
                        help="seed for author/generate.py; omitted picks an unused one")
    parser.add_argument("--package", type=Path,
                        help="reuse an existing challenge package instead of generating")
    parser.add_argument("--output-root", type=Path, default=PACKAGE_DEFAULT_ROOT)
    parser.add_argument("--archive", type=Path, help="output .tar.gz path")
    parser.add_argument("--report", type=Path, help="output report path")
    parser.add_argument("--competition-id", default="",
                        help="competition id for the authored-challenges route")
    parser.add_argument("--dry-run", action="store_true",
                        help="explicit dry-run (the default); sends no request")
    parser.add_argument("--authorized", action="store_true",
                        help="explicitly allow the upload POST; requires CTFY_PLATFORM_URL "
                             "and CTFY_TOKEN in the environment")
    parser.add_argument("--smoke-runs", type=int, default=1,
                        help="dynamic smoke repetitions when the local CLI offers them")
    parser.add_argument("--ctfy", default=None, help="path to the ctfy executable")
    parser.add_argument("--ctfy-admin", default=None, help="path to ctfy-admin")
    parser.add_argument("--poll", action="store_true",
                        help="after an authorized upload, read back status with GET only")
    parser.add_argument("--wait-seconds", type=float, default=0.0,
                        help="total read-only poll budget in seconds")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between read-only poll requests")
    parser.add_argument("--json", action="store_true", help="print the full report JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.dry_run and args.authorized:
        parser.error("--dry-run and --authorized are mutually exclusive")
    if args.smoke_runs < 0 or args.smoke_runs > 5:
        parser.error("--smoke-runs must be between 0 and 5")
    try:
        report = run_authoring_flow(
            seed=args.seed, package=args.package, output_root=args.output_root,
            archive_path=args.archive, report_path=args.report,
            competition_id=args.competition_id, authorized=args.authorized,
            smoke_runs=args.smoke_runs, poll=args.poll,
            wait_seconds=args.wait_seconds, interval=args.interval,
            ctfy=args.ctfy, ctfy_admin=args.ctfy_admin,
        )
    except AuthoringError as exc:
        print(f"authoring error: {redact(str(exc), environment_secrets())}",
              file=sys.stderr)
        return 1
    if args.json:
        safe = dict(report)
        print(json.dumps(safe, ensure_ascii=False, indent=2))
    else:
        print(f"authoring {report['mode']}: status={report['status']} "
              f"evidence={report['evidence_level']}")
        print(f"  package: {report.get('package')} (source: {report.get('package_source')})")
        local = report.get("local_checks") or {}
        print(f"  local checks: {local.get('evidence')}"
              f" ({local.get('executed', 0)}/{local.get('planned', 0)} executed)")
        archive = report.get("archive") or {}
        print(f"  archive: {archive.get('path')}")
        print(f"  sha256: {archive.get('sha256')}")
        upload = report.get("upload") or {}
        print(f"  network sent: {report.get('network_sent')}; uploaded: {upload.get('uploaded')}; "
              f"platform reviewed: {upload.get('platform_reviewed')}")
        if upload.get("refusal"):
            refusal = upload["refusal"]
            print(f"  refusal: HTTP {refusal.get('status')} {refusal.get('code')}")
        if report.get("blocked"):
            print(f"  blocked: {report['blocked']['reason']}")
        print(f"  report: {report.get('report_path')}")
        print("This run does not prove platform review or publication unless the "
              "report says the platform returned a reviewed status.")
    return int(report.get("exit_code", 1))


if __name__ == "__main__":
    raise SystemExit(main())
