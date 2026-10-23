"""Output hygiene helpers, not an OS isolation boundary."""
import os

SAFE_ENV = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "TMPDIR",
            "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}


def command_environment(environ=None):
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key.upper() in SAFE_ENV}


def redact(text, environ=None):
    source = os.environ if environ is None else environ
    values = {v for k, v in source.items() if v and any(word in k.upper()
              for word in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    return text


def scrub(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(k)): scrub(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [scrub(v) for v in value]
    return value
