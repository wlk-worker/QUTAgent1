"""Authorized local SSRF target with a weak hostname denylist (bypass lab).

The public edge exposes ``/fetch?url=`` which fetches a caller-supplied URL from
the server side. A naive denylist rejects the exact hostnames ``localhost``,
``127.0.0.1`` and ``0.0.0.0`` (case-insensitive), but it does not understand
IPv6 loopback: ``http://[::1]:<internal-port>/flag`` reaches an HTTP metadata
service that is bound only to loopback (127.0.0.1 and ::1) and therefore is not
part of the solver-visible platform services.

The edge still enforces that every resolved address is loopback and never
follows redirects, so the lab cannot be used to fetch external hosts. The flag is
generated per process and logged nowhere.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # normal package import
    from .common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, new_flag, now_iso, sha256_text, write_json

DENIED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
MAX_FETCH_BYTES = 16_384
DENY_SNIPPET = "http://127.0.0.1:{port}/flag"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class TargetState:
    def __init__(self, root: Path, seed: int, log_path: Path):
        self.root = Path(root)
        self.seed = seed
        self.log_path = Path(log_path)
        self.lock = threading.RLock()
        self.private = make_dir(self.root / "private")
        self.flag = new_flag(seed)
        self.flag_file = self.private / "flag.txt"
        self.flag_file.write_text(self.flag + "\n", encoding="utf-8")
        self.origin = ""
        self.port = 0
        self.internal_port = 0
        self.internal_servers: list = []
        self.opener = urllib.request.build_opener(_NoRedirect)


class _InternalHandler(BaseHTTPRequestHandler):
    server_version = "LabMetadata/0.1"
    protocol_version = "HTTP/1.0"
    state: TargetState | None = None

    def log_message(self, *args):
        pass

    def _reply(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def do_GET(self):  # noqa: N802
        state = type(self).state
        route = urllib.parse.urlsplit(self.path).path
        if route == "/flag" and state is not None:
            self._reply(200, (state.flag + "\n").encode("utf-8"),
                        "text/plain; charset=utf-8")
        elif route == "/":
            self._reply(200, b'{"paths": ["/flag"]}',
                        "application/json; charset=utf-8")
        else:
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")


class _InternalHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True


def _start_internal(state: TargetState) -> str:
    """Start the internal flag service on the same port on 127.0.0.1 and ::1."""
    handler = type("InternalHandler", (_InternalHandler,), {"state": state})
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()
    ipv4 = ThreadingHTTPServer(("127.0.0.1", port), handler)
    ipv4.daemon_threads = True
    state.internal_servers.append(ipv4)
    try:
        ipv6 = _InternalHTTPServer(("::1", port), handler)
        ipv6.daemon_threads = True
        state.internal_servers.append(ipv6)
    except OSError:
        pass
    for server in state.internal_servers:
        threading.Thread(target=server.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True).start()
    state.internal_port = port
    return f"http://[::1]:{port}/flag"


def _home(state: TargetState) -> str:
    hint = DENY_SNIPPET.format(port=state.internal_port)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Acme Link Preview</title></head>
<body>
<h1>Acme Link Preview</h1>
<form action="/fetch" method="get">
  <input name="url" size="80" placeholder="https://example.com">
  <button type="submit">Preview</button>
</form>
<p>Deployment {state.seed}. The edge proxy fetches previews server-side.</p>
<!--
  debug note: the internal metadata service is at {hint}; the edge denylist
  blocks localhost/127.0.0.1/0.0.0.0 hostnames only. Keep it out of production.
-->
</body></html>
"""


def _host_is_loopback(host: str, port: int) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        address = info[4][0]
        try:
            if not ipaddress.ip_address(address).is_loopback:
                return False
        except ValueError:
            return False
    return True


def _fetch(state: TargetState, raw_url: str) -> dict:
    """Weak-denylist SSRF fetch; loopback-only and redirects refused."""
    target_url = str(raw_url or "")[:2500]
    if not target_url:
        return {"status": 400, "error": "missing_url"}
    try:
        parsed = urllib.parse.urlsplit(target_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return {"status": 400, "error": "invalid_url"}
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"status": 400, "error": "invalid_url"}
    # Weak denylist bug: exact hostname comparison, naive list, no IPv6/redirect
    # analysis. The intended bypass is IPv6 loopback [::1].
    if parsed.hostname.lower() in DENIED_HOSTS:
        return {"status": 403, "error": "host_denied",
                "detail": "host is on the denylist"}
    if parsed.username or parsed.password:
        return {"status": 403, "error": "userinfo_not_allowed"}
    if not _host_is_loopback(parsed.hostname, port):
        return {"status": 403, "error": "external_host_not_allowed"}
    safe_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    request = urllib.request.Request(safe_url, method="GET",
                                     headers={"User-Agent": "AcmePreview/1"})
    try:
        with state.opener.open(request, timeout=5) as response:
            raw = response.read(MAX_FETCH_BYTES + 1)
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read(MAX_FETCH_BYTES + 1)
        finally:
            exc.close()
    except urllib.error.URLError:
        return {"status": 502, "error": "fetch_failed"}
    except TimeoutError:
        return {"status": 504, "error": "fetch_timeout"}
    text = raw[:MAX_FETCH_BYTES].decode("utf-8", errors="replace")
    return {"status": status, "url": safe_url, "bytes": len(raw),
            "body": text, "truncated": len(raw) > MAX_FETCH_BYTES}


def _make_handler(state: TargetState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AcmePreview/1.0"
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _record(self, status: int) -> None:
            append_jsonl(state.log_path, {
                "ts": now_iso(), "seed": state.seed, "method": self.command,
                "path": urllib.parse.urlsplit(self.path).path, "status": status,
            }, lock=state.lock)

        def _json(self, status: int, data: dict) -> None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status)

        def _html(self, status: int, text: str) -> None:
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status)

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/":
                self._html(200, _home(state))
                return
            if parsed.path == "/fetch":
                values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                raw_url = (values.get("url") or [""])[0]
                result = _fetch(state, raw_url)
                self._json(result.get("status", 400), result)
                return
            if parsed.path == "/health":
                self._json(200, {"ok": True, "internal_port": state.internal_port})
                return
            self._json(404, {"error": "not_found"})

    return Handler


def _readme(state: TargetState) -> str:
    hint = DENY_SNIPPET.format(port=state.internal_port)
    return f"""# Lab Web Challenge: Acme Link Preview (SSRF, weak denylist)

Authorized local lab challenge. The public edge is at `http://127.0.0.1:<port>`.
It exposes a server-side preview endpoint:

    GET /fetch?url=<url-encoded URL>

The edge has a denylist for internal hostnames (`localhost`, `127.0.0.1`,
`0.0.0.0`), but it only compares exact hostnames. A deployment metadata service
is bound to loopback on an internal port and serves the flag at:

    {hint}

Only the public edge is listed in the platform instance services; the metadata
service is internal. The literal address above is denied by the hostname list;
find an equivalent loopback spelling that the weak denylist misses, make the
preview proxy fetch the internal flag, then submit the exact flag string.

Rules of engagement: local lab only; the proxy is restricted to loopback and
refuses redirects; do not touch other hosts.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized local SSRF weak-denylist target")
    parser.add_argument("--root", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    root = make_dir(Path(args.root))
    make_dir(Path(args.log).parent)
    state = TargetState(root, args.seed, Path(args.log))
    _start_internal(state)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _make_handler(state))
    server.daemon_threads = True
    state.port = server.server_port
    state.origin = f"http://127.0.0.1:{server.server_port}"
    write_json(Path(args.ready_file), {
        "service": "ssrf_target",
        "port": server.server_port,
        "origin": state.origin,
        "root": str(root),
        "flag_file": str(state.flag_file),
        "flag_sha256": sha256_text(state.flag),
        "internal_port": state.internal_port,
        "category": "web",
        "tags": ["ssrf", "web", "denylist-bypass", "lab"],
        "name": "Lab: Acme Link Preview (SSRF)",
        "description": ("Authorized local preview service with a weak hostname denylist "
                        "and an IPv6-loopback metadata service."),
        "question_prompt": "Bypass the weak SSRF denylist to fetch the internal metadata "
                           "flag and submit it.",
        "readme": _readme(state).replace("<port>", str(server.server_port)),
        "services": [{"service_type": "http", "name": "acme-preview",
                      "host": "127.0.0.1", "port": server.server_port,
                      "url": state.origin, "description": "Acme Link Preview"}],
    })
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        for internal in state.internal_servers:
            internal.shutdown()
            internal.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
