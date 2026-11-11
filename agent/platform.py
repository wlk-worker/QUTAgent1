"""Small REST projection of CTFY-0001. Request shapes follow ctfy 0.7.0 SDK."""
from __future__ import annotations

import http.client
import json
import ssl
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import urllib.error
import urllib.parse
import urllib.request
from .budget import remaining, bounded_call, wait as budget_wait, BudgetExpired
from dataclasses import dataclass
from typing import Any


class PlatformError(RuntimeError):
    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(f"platform {status}: {code} {message}"[:400])
        self.status, self.code = status, code


class Paused(PlatformError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    data: dict[str, Any]
    headers: Any


class Platform:
    def __init__(self, base_url: str, token: str, *, deadline: float | None = None, opener=None, sleep=time.sleep, clock=time.monotonic):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("CTFY_PLATFORM_URL must be an HTTP(S) origin")
        if not token:
            raise ValueError("CTFY_TOKEN is empty")
        self.base_url = base_url.rstrip("/") + "/api/v1"
        self.token = token
        self.deadline = deadline
        self.opener = opener or urllib.request.build_opener(_NoRedirect)
        self.sleep = sleep
        self.clock = clock

    def _can_wait(self, seconds: float) -> bool:
        return self.deadline is None or self.clock() + seconds + 5 < self.deadline

    def request(self, method: str, path: str, payload: dict | None = None, *,
                timeout_ceiling: float | None = None,
                max_retries: int | None = None) -> Response:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("API path must be relative to /api/v1")
        url = self.base_url + path
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        retry_limit = 6 if max_retries is None else max(0, min(int(max_retries), 6))
        attempt = 0
        while True:
            timeout = remaining(self.deadline, 20, self.clock)
            if timeout_ceiling is not None:
                timeout = min(timeout, max(0.2, float(timeout_ceiling)))
            req = urllib.request.Request(url, data=body, method=method, headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            try:
                def fetch():
                    with self.opener.open(req, timeout=timeout) as resp:
                        raw = resp.read(2_000_001)
                        if len(raw) > 2_000_000:
                            raise ValueError("platform_response_too_large")
                        return raw, resp.headers
                raw, headers = bounded_call(fetch, timeout)
                data = json.loads(raw) if raw else {}
                if not isinstance(data, dict):
                    raise ValueError("platform response is not an object")
                return Response(data, headers)
            except urllib.error.HTTPError as exc:
                try:
                    error = json.loads(bounded_call(lambda: exc.read(16_384),
                                                   remaining(self.deadline, 20, self.clock)))
                except (ValueError, OSError):
                    error = {}
                finally:
                    exc.close()
                code = str(error.get("code") or error.get("error") or "http_error") if isinstance(error, dict) else "http_error"
                message = str(error.get("detail") or error.get("message") or "") if isinstance(error, dict) else ""
                wait = _retry_seconds(exc.headers, error, attempt)
                if code == "competition_paused":
                    next_start = error.get("next_session_starts_at") if isinstance(error, dict) else None
                    if isinstance(next_start, str):
                        try:
                            wall_wait = (datetime.fromisoformat(next_start.replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()
                            wait = max(wait, wall_wait)
                        except ValueError:
                            pass
                    if self._can_wait(wait):
                        budget_wait(wait, self.deadline, self.sleep, self.clock)
                        continue
                    raise Paused(exc.code, code, message) from None
                safely_rejected = exc.code == 429 or code == "capacity_exceeded"
                transient_read = method == "GET" and exc.code in (500, 502, 503, 504)
                if safely_rejected or transient_read:
                    if attempt < 4 and self._can_wait(wait):
                        attempt += 1
                        budget_wait(wait, self.deadline, self.sleep, self.clock)
                        continue
                raise PlatformError(exc.code, code, message) from None
            except BudgetExpired:
                if method != "GET":
                    raise PlatformError(0, "mutation_outcome_unknown") from None
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.HTTPException, ssl.SSLError, OSError) as exc:
                # OSError covers socket-level refusals that are neither URLError
                # nor ConnectionError on Windows (WinError 10013 surfaces as
                # PermissionError). Without it such a read escaped as an opaque
                # internal_error instead of a retryable network_error.
                wait = min(2 ** attempt, 16)
                # RemoteDisconnected is a ConnectionResetError, not a
                # URLError: it used to escape as an uncaught internal_error
                # before the model was ever called when many CYBENCH tasks
                # started at once. Retry idempotent GETs with backoff.
                # After an uncertain POST response, retrying could create a
                # second instance or consume a second wrong-answer attempt.
                if method == "GET" and attempt < retry_limit and self._can_wait(wait):
                    attempt += 1
                    budget_wait(wait, self.deadline, self.sleep, self.clock)
                    continue
                raise PlatformError(0, "network_error" if method == "GET" else "mutation_outcome_unknown") from None

    def challenge(self, challenge_id: str, *, timeout_ceiling: float | None = None,
                  max_retries: int | None = None) -> dict:
        return self.request(
            "GET", f"/challenges/{urllib.parse.quote(challenge_id, safe='')}",
            timeout_ceiling=timeout_ceiling, max_retries=max_retries,
        ).data

    def start_instance(self, challenge_id: str, competition_id: str) -> str:
        data = self.request("POST", "/instances", {"challenge_id": challenge_id, "competition_id": competition_id}).data
        return str(data["id"])

    def wait_instance(self, instance_id: str) -> dict:
        escaped = urllib.parse.quote(instance_id, safe="")
        while True:
            response = self.request("GET", f"/instances/{escaped}/status")
            status = str(response.data.get("status", "")).lower()
            if status == "ready":
                return self.request("GET", f"/instances/{escaped}").data
            if status in {"error", "failed", "stopped", "expired"}:
                raise PlatformError(0, "instance_" + status, str(response.data.get("error") or ""))
            wait = _retry_seconds(response.headers, response.data, 0)
            if not self._can_wait(wait):
                raise PlatformError(0, "instance_wait_deadline")
            budget_wait(wait, self.deadline, self.sleep, self.clock)

    def instance(self, instance_id: str) -> dict:
        return self.request("GET", f"/instances/{urllib.parse.quote(instance_id, safe='')}").data

    def submit(self, instance_id: str, question_id: str, answer: str | list[str]) -> dict:
        return self.request("POST", "/submissions", {
            "instance_id": instance_id, "question_id": question_id, "answer": answer,
        }).data

    def submit_qa(self, challenge_id: str, competition_id: str, question_id: str, answer: str | list[str]) -> dict:
        return self.request("POST", "/qa/submissions", {
            "challenge_id": challenge_id, "competition_id": competition_id,
            "question_id": question_id, "answer": answer,
        }).data

    def download_attachment(self, challenge_id: str, name: str, instance_id: str | None = None) -> bytes:
        """Fetch player-visible attachment; never accept traversal or redirects."""
        parts = name.split("/")
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("invalid attachment name")
        source = f"/instances/{urllib.parse.quote(instance_id, safe='')}" if instance_id else f"/challenges/{urllib.parse.quote(challenge_id, safe='')}"
        encoded = "/".join(urllib.parse.quote(part, safe="") for part in parts)
        request = urllib.request.Request(self.base_url + source + "/attachments/" + encoded,
                                         headers={"Authorization": "Bearer " + self.token}, method="GET")
        try:
            timeout = remaining(self.deadline, 30, self.clock)
            def fetch():
                with self.opener.open(request, timeout=timeout) as response:
                    return response.read(50_000_001)
            data = bounded_call(fetch, timeout)
            if len(data) > 50_000_000:
                raise ValueError("attachment too large")
            return data
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise PlatformError(status, "attachment_error") from None
        except BudgetExpired:
            # BudgetExpired is a TimeoutError subclass; it must stay a
            # deadline, not become an indistinguishable network error.
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                http.client.HTTPException, ssl.SSLError, OSError):
            raise PlatformError(0, "network_error") from None


def _retry_seconds(headers: Any, data: Any, attempt: int) -> float:
    values = [headers.get("Retry-After") if headers else None]
    if isinstance(data, dict):
        values += [data.get("poll_after_s"), data.get("retry_after_s")]
    for value in values:
        try:
            return max(1.0, min(float(value), 600.0))
        except (TypeError, ValueError):
            if isinstance(value, str):
                try:
                    delta = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
                    return max(1.0, min(delta, 600.0))
                except (TypeError, ValueError):
                    pass
    return float(min(2 ** attempt, 16))
