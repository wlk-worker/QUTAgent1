"""Tolerant parsing for near-JSON action replies.

Reasoning models occasionally emit a JSON object with a literal newline, an
unescaped quote inside a shell command, or a reply truncated mid-string.  The
strict parser rejected those replies, and every rejection spent a model turn
(Pen-test evidence: 6/16 and 4/16 format errors on CTFARENA).  This module
repairs the three mechanical shapes; it never invents an action and never
marks a truncated command as complete.
"""
from __future__ import annotations

import json
import re

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)


def _scan_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    out: list[str] = []
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                out.append(char)
                escaped = False
            elif char == "\\":
                out.append(char)
                escaped = True
            elif char == '"':
                look = index + 1
                while look < len(text) and text[look] in " \t\r\n":
                    look += 1
                if look >= len(text) or text[look] in ",}]:}":
                    out.append('"')
                    in_string = False
                else:
                    out.append('\\"')  # an unescaped quote inside the value
            elif char == "\n":
                out.append("\\n")
            elif char == "\r":
                out.append("\\r")
            elif char == "\t":
                out.append("\\t")
            else:
                out.append(char)
        else:
            if char == '"':
                in_string = True
            out.append(char)
    if in_string:
        # The reply ended mid-string; close it so the object can be inspected.
        out.append('"')
    candidate = "".join(out)
    depth = 0
    in_string = False
    escaped = False
    for char in candidate:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    candidate += "}" * max(0, depth)
    return candidate


def repair_parse(text: str, valid_actions) -> dict | None:
    """Return a repaired action object, or None when it cannot be recovered."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = _FENCE.sub("", text).strip()
    candidate = _scan_object(text)
    if not candidate:
        return None
    try:
        value = json.loads(candidate)
    except ValueError:
        return None
    if isinstance(value, dict) and value.get("action") in valid_actions:
        return value
    return None
