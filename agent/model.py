"""One model gateway per run; never falls back to a private credential."""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from .budget import remaining, bounded_call, wait, BudgetExpired


class ModelError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _is_internal_gateway_host(hostname: str | None) -> bool:
    """Whether an http:// gateway is a platform-internal service.

    CTFY-0001 explicitly allows the platform to inject ``LLM_BASE_URL``; in
    the evaluation network it is a Docker/Kubernetes service such as
    ``http://ctfy-llm-relay:8081``, not a public HTTPS domain. The key is a
    per-run gateway handle, and refusing http here made the platform see zero
    model calls. Keep rejecting public plain-HTTP endpoints.
    """
    host = (hostname or "").strip().lower()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if "." not in host:  # Docker/Kubernetes service name, e.g. ctfy-llm-relay
        return True
    if host.endswith((".internal", ".local", ".docker", ".svc", ".cluster.local")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


class Model:
    def __init__(self, flavor: str, model: str, base_url: str, api_key: str, *, opener=None, sleep=time.sleep,
                 deadline=None, max_requests=64, clock=time.monotonic):
        if flavor not in {"openai", "anthropic"}:
            raise ModelError("unsupported LLM_FLAVOR")
        if not api_key:
            raise ModelError("LLM_API_KEY is empty")
        if not model:
            raise ModelError("LLM_MODEL is empty")
        self.flavor, self.model, self.api_key = flavor, model, api_key
        if not base_url:
            native = "OPENAI_BASE_URL" if flavor == "openai" else "ANTHROPIC_BASE_URL"
            base_url = os.environ.get(native, "")
        self.base_url = base_url or ("https://api.openai.com/v1" if flavor == "openai" else "https://api.anthropic.com/v1")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"}:
            raise ModelError("model gateway must be HTTP(S)")
        if parsed.scheme == "http" and not _is_internal_gateway_host(parsed.hostname):
            raise ModelError("public model gateway must use HTTPS")
        # The platform's model gateway is an internal service; environment
        # HTTP(S)_PROXY settings in a foreign image must not intercept it.
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect)
        self.sleep = sleep
        self.input_tokens = 0
        self.output_tokens = 0
        self.deadline, self.max_requests, self.clock = deadline, max_requests, clock
        self.requests = 0
        # Logical completion calls.  HTTP retries (429/network/empty reply) are
        # bounded separately so a transient retry cannot consume the caller's
        # whole per-run request budget (MMLU-CS-0021/0054/0100).
        self.logical_requests = 0

    def _endpoint(self) -> str:
        suffix = "/chat/completions" if self.flavor == "openai" else "/messages"
        base = self.base_url.rstrip("/")
        if base.endswith(suffix):
            return base
        return base + suffix if base.endswith("/v1") else base + "/v1" + suffix

    def complete(self, system: str, messages: list[dict], max_tokens: int = 1200) -> str:
        if self.logical_requests >= self.max_requests:
            raise ModelError("model_request_limit")
        self.logical_requests += 1
        if self.flavor == "openai":
            base_payload = {"model": self.model,
                            "messages": [{"role": "system", "content": system}, *messages],
                            "temperature": 0}
            headers = {"Authorization": "Bearer " + self.api_key}
        else:
            base_payload = {"model": self.model, "system": system,
                            "messages": messages, "temperature": 0}
            headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        headers["Content-Type"] = "application/json"
        for attempt in range(4):
            timeout = remaining(self.deadline, 90, self.clock)
            # Secondary guard against a retry storm; logical calls are capped
            # above, so 4xx/5xx/network retries do not exhaust the run budget.
            if self.requests >= max(self.max_requests * 4, 4):
                raise ModelError("model_request_limit")
            self.requests += 1
            payload = dict(base_payload, max_tokens=max_tokens)
            body = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(self._endpoint(), data=body, headers=headers, method="POST")
            try:
                def fetch():
                    with self.opener.open(request, timeout=timeout) as response:
                        raw = response.read(2_000_001)
                        if len(raw) > 2_000_000:
                            raise ModelError("model_response_too_large")
                        return json.loads(raw)
                data = bounded_call(fetch, timeout)
                usage = data.get("usage") or {}
                self.input_tokens += int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
                self.output_tokens += int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
                if self.flavor == "openai":
                    content = data["choices"][0]["message"]["content"]
                    if isinstance(content, list):
                        content = "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
                else:
                    content = "\n".join(str(p.get("text", "")) for p in data["content"] if p.get("type") == "text")
                if not isinstance(content, str) or not content.strip():
                    # Reasoning models can spend the whole completion budget on
                    # hidden reasoning and return an empty content field. Retry
                    # once or twice with more headroom instead of aborting the
                    # whole task on a transient empty reply.
                    if attempt < 3:
                        max_tokens = min(6000, max(max_tokens * 2, 2400))
                        continue
                    raise ModelError("empty model response")
                return content
            except urllib.error.HTTPError as exc:
                # Never log the request, response body, URL with credentials, or secret headers.
                status = exc.code
                exc.close()
                if status in (429, 500, 502, 503, 504) and attempt < 3:
                    wait(min(2 ** attempt, 8), self.deadline, self.sleep, self.clock)
                    continue
                raise ModelError(f"model HTTP {status}") from None
            except BudgetExpired:
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < 3:
                    wait(min(2 ** attempt, 8), self.deadline, self.sleep, self.clock)
                    continue
                raise ModelError("model network error") from None
            except (KeyError, IndexError, ValueError, TypeError) as exc:
                raise ModelError("invalid model response") from exc
        raise ModelError("model retries exhausted")
