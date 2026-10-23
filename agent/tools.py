"""Linux command groups, bounded pipe capture, an environment allowlist and a
scope-restricted structured HTTP tool. None of this is an OS isolation boundary.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .budget import BudgetExpired, bounded_call, remaining
from .security import command_environment, redact

REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def normalize_origin(value: str) -> str:
    """Return a lower-case ``scheme://host[:port]`` scope key or raise ValueError."""
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("invalid origin")
    if parsed.username or parsed.password:
        raise ValueError("origin must not contain credentials")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("invalid host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    default = 443 if parsed.scheme == "https" else 80
    host_part = f"[{host}]" if ":" in host else host
    netloc = host_part if port in (None, default) else f"{host_part}:{port}"
    return f"{parsed.scheme.lower()}://{netloc}"



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


def _http_result(method, url, origin, status, raw, headers, max_bytes, started_at):
    truncated = len(raw) > max_bytes
    body = raw[:max_bytes]
    text = body.decode("utf-8", errors="replace")
    reported = {}
    for key, value in list(headers.items())[:32]:
        reported[str(key)[:100]] = str(value)[:500]
    return {
        "method": method,
        "url": url,
        "origin": origin,
        "status": status,
        "ok": 200 <= status < 300,
        "headers": reported,
        "body_preview": text,
        "body_bytes": len(raw),
        "truncated": truncated,
        "redirect_blocked": status in REDIRECT_STATUSES,
        "elapsed_s": round(time.monotonic() - started_at, 3),
    }


def http_request(method: str, url: str, *, allowed_origins, body=None, timeout_s=15,
                 max_response_bytes=64_000, deadline=None, opener=None,
                 clock=time.monotonic):
    """Bounded GET/POST limited to an explicit origin allowlist.

    Redirects are never followed. Response bodies are size-capped and returned
    as a text preview together with status, headers and truncation metadata.
    HTTP error statuses are observations, not exceptions; network failures and
    scope violations are returned as ``{"error": ...}`` objects.
    """
    started_at = time.monotonic()
    method = str(method or "").upper()
    if method not in {"GET", "POST"}:
        return {"error": "method_not_allowed", "method": method}
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        origin = normalize_origin(url)
    except ValueError:
        return {"error": "invalid_url"}
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"error": "invalid_url"}
    if parsed.username or parsed.password or parsed.fragment:
        return {"error": "invalid_url"}
    try:
        allowed = {normalize_origin(item) for item in allowed_origins}
    except (TypeError, ValueError):
        return {"error": "invalid_allowed_origins"}
    if origin not in allowed:
        return {"error": "origin_not_allowed", "origin": origin,
                "allowed_origins": sorted(allowed)}
    if body is not None and method == "GET":
        return {"error": "body_not_allowed_for_get"}
    payload = None
    headers = {"Accept": "*/*", "User-Agent": "QUTAgent-lab/1"}
    if body is not None:
        if isinstance(body, (dict, list)):
            try:
                payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            except (TypeError, ValueError):
                return {"error": "invalid_body"}
            headers["Content-Type"] = "application/json; charset=utf-8"
        elif isinstance(body, str):
            payload = body.encode("utf-8")
            headers["Content-Type"] = "text/plain; charset=utf-8"
        elif isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
        else:
            return {"error": "invalid_body"}
    try:
        capped = max(256, min(int(max_response_bytes), 1_000_000))
    except (TypeError, ValueError):
        return {"error": "invalid_max_response_bytes"}
    try:
        timeout = remaining(deadline, max(0.1, min(float(timeout_s), 90)), clock)
    except (BudgetExpired, TypeError, ValueError):
        return {"error": "deadline", "elapsed_s": 0}
    safe_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    request = urllib.request.Request(safe_url, data=payload, method=method, headers=headers)
    client = opener or urllib.request.build_opener(_NoRedirect)

    def fetch():
        with client.open(request, timeout=timeout) as response:
            raw = response.read(capped + 1)
            return int(response.status), raw, dict(response.headers.items())

    try:
        status, raw, response_headers = bounded_call(fetch, timeout)
        return _http_result(method, safe_url, origin, status, raw, response_headers,
                            capped, started_at)
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        try:
            raw = bounded_call(lambda: exc.read(capped + 1),
                               remaining(deadline, 5, clock))
        except (BudgetExpired, OSError):
            raw = b""
        finally:
            exc.close()
        result = _http_result(method, safe_url, origin, status, raw, response_headers,
                              capped, started_at)
        if result["redirect_blocked"]:
            result["location"] = response_headers.get("Location", "")
            result["note"] = "redirect refused; target hosts are not followed"
        return result
    except BudgetExpired:
        return {"error": "timeout", "url": safe_url, "origin": origin,
                "elapsed_s": round(time.monotonic() - started_at, 3)}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"error": "network_error", "url": safe_url, "origin": origin,
                "elapsed_s": round(time.monotonic() - started_at, 3)}
