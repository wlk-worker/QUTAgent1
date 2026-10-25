"""Fake model policy for the MCP/AI lab (link validation only).

Reads the platform-provided MCP service URL from the briefing, calls
``tools/list``, reads the read-only policy note, then calls ``get_flag`` and
submits the flag returned in the real MCP tool response. It never receives the
flag out-of-band; the agent's real MCP client performs the JSON-RPC/SSE calls.
"""
from __future__ import annotations

try:
    from .fake_provider import (
        URL_RE, brief_question_id, first_service, flag_in,
        parse_briefing, parse_observations, serve,
    )
except ImportError:
    from fake_provider import (
        URL_RE, brief_question_id, first_service, flag_in,
        parse_briefing, parse_observations, serve,
    )


def _mcp_url(brief: dict, messages: list[dict]) -> str | None:
    service = first_service(brief, "mcp") or first_service(brief)
    candidate = ""
    if service:
        candidate = str(service.get("url") or "")
        if not candidate and service.get("host") and service.get("port"):
            candidate = f"http://{service['host']}:{service['port']}/mcp"
    if not candidate:
        for entry in brief.get("scope") or []:
            match = URL_RE.search(str(entry))
            if match:
                candidate = match.group(0)
                break
    if not candidate:
        return None
    candidate = candidate.rstrip("/")
    if candidate.endswith("/mcp"):
        return candidate
    return candidate + "/mcp"


def _mcp_observations(observations: list[dict]) -> list[dict]:
    return [item for item in observations
            if any(key in item for key in ("tools", "content", "structured_content"))]


def _flag_observation(observations: list[dict]) -> str | None:
    for item in reversed(observations):
        flag = flag_in(item)
        if flag:
            return flag
    return None


def decide(messages: list[dict]) -> dict:
    brief = parse_briefing(messages)
    question_id = brief_question_id(brief)
    url = _mcp_url(brief, messages)
    observations = parse_observations(messages)
    if not url:
        return {"action": "finish", "reason": "fake_model_no_mcp_service_in_brief"}
    flag = _flag_observation(observations)
    if flag:
        return {"action": "submit", "question_id": question_id, "answer": flag,
                "evidence": f"MCP tools/call get_flag returned the flag from {url}"}
    if any("verdict" in item for item in observations):
        return {"action": "finish", "reason": "submission already decided by the platform"}

    mcp_observations = _mcp_observations(observations)
    errors = [item for item in observations if item.get("error")]
    if any(item.get("error") == "jsonrpc_error" for item in errors):
        if not any(item.get("tool") == "get_flag" for item in mcp_observations):
            return {"action": "mcp", "url": url, "op": "call", "tool": "get_flag",
                    "arguments": {}, "why": "fallback to the flag tool after a tool error"}
        return {"action": "finish", "reason": "MCP tool call failed"}

    if not any("tools" in item for item in mcp_observations):
        return {"action": "mcp", "url": url, "op": "list_tools",
                "why": "enumerate the in-scope MCP server tools"}
    if not any(item.get("tool") == "read_note" for item in mcp_observations):
        return {"action": "mcp", "url": url, "op": "call", "tool": "read_note",
                "arguments": {"name": "policy"}, "why": "read the read-only server policy note"}
    if not any(item.get("tool") == "get_flag" for item in mcp_observations):
        return {"action": "mcp", "url": url, "op": "call", "tool": "get_flag",
                "arguments": {}, "why": "read the flag through the MCP tool"}
    return {"action": "finish", "reason": "no scripted MCP step left for this observation"}


if __name__ == "__main__":
    raise SystemExit(serve(decide, "Fake model for the MCP lab", "fake-mcp-model"))
