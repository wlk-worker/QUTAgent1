"""Linux command groups, bounded pipe capture, an environment allowlist and a
scope-restricted structured HTTP tool. None of this is an OS isolation boundary.
"""
from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
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

# Request headers a model may set on the structured HTTP tool. Everything else
# (Host, Content-Length, Transfer-Encoding, proxy headers, ...) is refused so a
# model cannot smuggle framing or proxy controls through the tool.
ALLOWED_REQUEST_HEADERS = frozenset({
    "accept", "accept-language", "authorization", "cache-control", "content-type",
    "cookie", "origin", "referer", "user-agent", "x-csrf-token",
    "x-requested-with", "x-xsrf-token", "x-api-key", "x-auth-token",
    "x-mcp-token",
})
FORBIDDEN_REQUEST_HEADERS = frozenset({
    "connection", "content-length", "expect", "host", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 64_000
_SECRET_ENV_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
_SECRET_MIN_LEN = 6
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_MAX_HEADER_VALUE = 4_096


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


def _encode_body(body):
    """Return ``(payload, content_type)`` for a request body or raise ValueError."""
    if isinstance(body, (dict, list)):
        try:
            return json.dumps(body, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_body") from exc
    if isinstance(body, str):
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    if isinstance(body, (bytes, bytearray)):
        return bytes(body), None
    raise ValueError("invalid_body")


def secret_values(environ=None) -> set[str]:
    """Credential-like environment values that must never reach a target.

    Mirrors ``agent.security.redact``: variables whose names contain KEY, TOKEN,
    SECRET or PASSWORD. Short values are ignored to avoid false positives.
    """
    source = os.environ if environ is None else environ
    values = set()
    for key, value in source.items():
        if not value or not any(hint in str(key).upper() for hint in _SECRET_ENV_HINTS):
            continue
        text = str(value)
        if len(text) >= _SECRET_MIN_LEN:
            values.add(text)
    return values


def _request_header_error(name: str, code: str) -> dict:
    return {"error": code, "header": str(name)[:64]}


def prepare_headers(headers, *, environ=None) -> tuple[dict | None, dict | None]:
    """Validate model-supplied request headers; return ``(headers, error)``.

    Only :data:`ALLOWED_REQUEST_HEADERS` may be set, values may not contain CR/LF
    (header injection), and no value may contain a platform/model credential.
    Error objects never echo the offending value.
    """
    if headers is None:
        return {}, None
    if not isinstance(headers, dict):
        return None, {"error": "invalid_headers"}
    lowered = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip()
        if not _HEADER_NAME.match(name):
            return None, _request_header_error(name, "invalid_header_name")
        if name.lower() in FORBIDDEN_REQUEST_HEADERS:
            return None, _request_header_error(name, "header_not_allowed")
        if name.lower() not in ALLOWED_REQUEST_HEADERS:
            return None, _request_header_error(name, "header_not_allowed")
        if isinstance(raw_value, bool) or not isinstance(raw_value, (str, int, float)):
            return None, _request_header_error(name, "invalid_header_value")
        value = str(raw_value)
        if "\r" in value or "\n" in value or "\x00" in value:
            return None, _request_header_error(name, "header_injection")
        if len(value) > _MAX_HEADER_VALUE:
            return None, _request_header_error(name, "header_value_too_long")
        lowered[name] = value
    secrets = secret_values(environ)
    for name, value in lowered.items():
        if any(secret in value for secret in secrets):
            return None, _request_header_error(name, "secret_in_header")
    return lowered, None


def _merge_headers(defaults: dict, extra: dict) -> dict:
    """Case-insensitively merge ``extra`` over ``defaults``."""
    merged = dict(defaults)
    index = {key.lower(): key for key in merged}
    for name, value in extra.items():
        existing = index.get(name.lower())
        if existing is not None:
            merged.pop(existing, None)
        merged[name] = value
        index[name.lower()] = name
    return merged


def _get_header(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _redact_observation(result: dict, environ=None) -> dict:
    """Strip credential-like values from an observation before it reaches the model."""
    for key in ("body_preview", "location"):
        if isinstance(result.get(key), str):
            result[key] = redact(result[key], environ)
    if isinstance(result.get("headers"), dict):
        result["headers"] = {str(key): redact(str(value), environ)
                             for key, value in result["headers"].items()}
    return result


def shell(command: str, cwd: Path, timeout_s=20, output_limit=12000, *, deadline=None):
    if not command or len(command) > 8000:
        return {"exit_code": -1, "error": "invalid_command"}
    start = time.monotonic()
    try:
        timeout = remaining(deadline, max(0.01, min(timeout_s, 180)))
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
    stamp = str(time.time_ns())
    obs_dir = Path(cwd) / ".obs"
    try:
        obs_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        obs_dir = None
    full_paths: dict[str, str] = {}

    def drain(name, pipe):
        handle = None
        if obs_dir is not None:
            path = obs_dir / (stamp + "-" + name + ".out")
            try:
                handle = path.open("w", encoding="utf-8", errors="replace")
                full_paths[name] = str(path)
            except OSError:
                handle = None
        try:
            while True:
                block = pipe.read(4096)
                if not block:
                    break
                totals[name] += len(block)
                room = max(0, output_limit - len(chunks[name]))
                chunks[name].extend(block[:room])
                if handle is not None:
                    handle.write(redact(block.decode("utf-8", errors="replace")))
        finally:
            if handle is not None:
                handle.close()
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
    stdout = redact(bytes(chunks["stdout"]).decode("utf-8", errors="replace"))
    stderr = redact(bytes(chunks["stderr"]).decode("utf-8", errors="replace"))
    result = {"exit_code": process.returncode,
              "stdout": stdout, "stderr": stderr,
              "stdout_tail": stdout[-2000:], "stderr_tail": stderr[-2000:],
              "full_output": full_paths.get("stdout"),
              "full_error": full_paths.get("stderr"),
              "timed_out": timed_out,
              "truncated": any(count > output_limit for count in totals.values()),
              "captured_bytes": sum(len(data) for data in chunks.values()),
              "full_output_bytes": dict(totals),
              "elapsed_s": round(time.monotonic() - start, 3)}
    if timed_out:
        result["error"] = "timeout"
    return result


def _http_result(method, url, origin, status, raw, headers, max_bytes, started_at,
                 preview_bytes=None):
    truncated = len(raw) > max_bytes
    preview_limit = max(256, min(int(preview_bytes or max_bytes), max_bytes))
    body = raw[:preview_limit]
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


def _save_http_body(result: dict, raw: bytes, save_to: str | None) -> dict:
    """Persist the (possibly binary) body for reversing/forensics tasks."""
    if not save_to:
        return result
    try:
        path = Path(save_to)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    except (OSError, ValueError) as exc:
        result["save_error"] = type(exc).__name__
        return result
    result.update({
        "saved_to": str(path),
        "saved_bytes": len(raw),
        "saved_sha256": hashlib.sha256(raw).hexdigest(),
    })
    return result


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
        try:
            payload, content_type = _encode_body(body)
        except ValueError:
            return {"error": "invalid_body"}
        if content_type:
            headers["Content-Type"] = content_type
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
    client = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect)

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


def _clean_url(parsed: urllib.parse.SplitResult) -> str:
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


class HttpSession:
    """Stateful, scope-restricted HTTP client for Web and AI challenges.

    Differences from :func:`http_request` (kept unchanged for compatibility):

    * a cookie jar persists ``Set-Cookie`` values across calls in one solve run;
    * model-supplied headers pass an allowlist and CR/LF injection checks;
    * platform/model credential values are refused in outgoing headers and
      redacted from observations;
    * redirects are followed only while every hop stays on the *original*
      origin and within ``max_redirects``; a cross-origin hop is refused and
      never requested;
    * response bodies are size-capped and the whole call is bounded by
      ``deadline``.

    This is a scope and output-hygiene control, not an OS isolation boundary.
    """

    def __init__(self, allowed_origins, *, timeout_s=15, max_response_bytes=MAX_RESPONSE_BYTES,
                 deadline=None, opener=None, max_redirects=MAX_REDIRECTS,
                 clock=time.monotonic, environ=None):
        self.allowed_origins: list[str] = []
        self.set_allowed_origins(allowed_origins)
        self.timeout_s = timeout_s
        self.max_response_bytes = max_response_bytes
        self.deadline = deadline
        self.max_redirects = max(0, min(int(max_redirects), 10))
        self.clock = clock
        self.environ = os.environ if environ is None else environ
        self.jar = http.cookiejar.CookieJar()
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect)

    def set_allowed_origins(self, allowed_origins) -> None:
        """Replace the scope after a platform refresh."""
        self.allowed_origins = sorted({normalize_origin(item) for item in allowed_origins})

    @property
    def cookies(self) -> list[dict]:
        """Cookie-jar contents for diagnostics and tests (never credentials checked)."""
        return [{"name": cookie.name, "value": cookie.value,
                 "domain": cookie.domain, "path": cookie.path}
                for cookie in self.jar]

    def _fetch(self, request, timeout: float, capped: int):
        """Return ``(status, raw, headers)`` or ``(error, b"", {})``; never raises."""
        def fetch():
            with self.opener.open(request, timeout=timeout) as response:
                return int(response.status), response.read(capped + 1), dict(response.headers.items())
        try:
            return bounded_call(fetch, timeout)
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                self.jar.extract_cookies(exc, request)
            except Exception:  # cookie extraction is best-effort, never fatal
                pass
            try:
                raw = bounded_call(lambda: exc.read(capped + 1),
                                   max(0.1, min(timeout, 5)))
            except (BudgetExpired, OSError, ValueError):
                raw = b""
            finally:
                exc.close()
            return status, raw, response_headers
        except BudgetExpired:
            return {"error": "timeout"}, b"", {}
        except (urllib.error.URLError, TimeoutError, OSError):
            return {"error": "network_error"}, b"", {}

    def request(self, method, url, *, body=None, headers=None, save_to=None) -> dict:
        """Perform one bounded request, returning a structured observation."""
        started_at = time.monotonic()
        method = str(method or "").upper()
        if method not in {"GET", "POST"}:
            return {"error": "method_not_allowed", "method": method}
        try:
            parsed = urllib.parse.urlsplit(str(url or ""))
            origin = normalize_origin(url)
        except (TypeError, ValueError):
            return {"error": "invalid_url"}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return {"error": "invalid_url"}
        if parsed.username or parsed.password or parsed.fragment:
            return {"error": "invalid_url"}
        if origin not in self.allowed_origins:
            return {"error": "origin_not_allowed", "origin": origin,
                    "allowed_origins": list(self.allowed_origins)}
        if body is not None and method == "GET":
            return {"error": "body_not_allowed_for_get"}
        request_headers, header_error = prepare_headers(headers, environ=self.environ)
        if header_error:
            return header_error
        payload = None
        if body is not None:
            try:
                payload, content_type = _encode_body(body)
            except ValueError:
                return {"error": "invalid_body"}
            if content_type and not any(key.lower() == "content-type" for key in request_headers):
                request_headers = {**request_headers, "Content-Type": content_type}
        try:
            capped = max(256, min(int(self.max_response_bytes), 1_000_000))
        except (TypeError, ValueError):
            return {"error": "invalid_max_response_bytes"}
        if save_to:
            # Binary/forensics downloads need the body, not a 64 KiB preview.
            capped = max(capped, 4_000_000)
        current_url = _clean_url(parsed)
        current_method, current_payload = method, payload
        redirects: list[str] = []
        merged_headers = _merge_headers(
            {"Accept": "*/*", "User-Agent": "QUTAgent-lab/1"}, request_headers)
        while True:
            try:
                timeout = remaining(self.deadline, max(0.1, min(float(self.timeout_s), 90)),
                                    self.clock)
            except (BudgetExpired, TypeError, ValueError):
                return {"error": "deadline",
                        "elapsed_s": round(time.monotonic() - started_at, 3)}
            request = urllib.request.Request(current_url, data=current_payload,
                                             method=current_method, headers=merged_headers)
            status, raw, response_headers = self._fetch(request, timeout, capped)
            if isinstance(status, dict):
                status.setdefault("url", current_url)
                status.setdefault("origin", origin)
                status.setdefault("elapsed_s", round(time.monotonic() - started_at, 3))
                return status
            location = _get_header(response_headers, "Location")
            if status not in REDIRECT_STATUSES or not location:
                result = _http_result(current_method, current_url, origin, status, raw,
                                      response_headers, capped, started_at,
                                      preview_bytes=64_000 if save_to else None)
                result = _save_http_body(result, raw, save_to)
                result["redirects"] = redirects
                result["cookie_count"] = len(self.jar)
                return _redact_observation(result, self.environ)
            try:
                target = urllib.parse.urljoin(current_url, location)
                target_parsed = urllib.parse.urlsplit(target)
                target_origin = normalize_origin(target)
            except ValueError:
                result = _http_result(current_method, current_url, origin, status, raw,
                                      response_headers, capped, started_at)
                result.update({"redirect_blocked": True, "location": location[:500],
                               "note": "invalid redirect target refused",
                               "redirects": redirects, "cookie_count": len(self.jar)})
                return _redact_observation(result, self.environ)
            cross_origin = target_origin != origin
            if cross_origin or len(redirects) >= self.max_redirects:
                result = _http_result(current_method, current_url, origin, status, raw,
                                      response_headers, capped, started_at)
                result.update({
                    "redirect_blocked": True, "location": location[:500],
                    "note": ("cross-origin redirect refused; only the original origin "
                             "may be followed" if cross_origin
                             else "redirect limit reached"),
                    "redirects": redirects, "cookie_count": len(self.jar)})
                return _redact_observation(result, self.environ)
            redirects.append(target)
            if status == 303 or (status in {301, 302} and current_method == "POST"):
                current_method, current_payload = "GET", None
                merged_headers = {key: value for key, value in merged_headers.items()
                                  if key.lower() != "content-type"}
            current_url = urllib.parse.urlunsplit(
                (target_parsed.scheme, target_parsed.netloc, target_parsed.path or "/",
                 target_parsed.query, ""))
