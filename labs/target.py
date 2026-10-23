"""Deliberately vulnerable, authorization-scoped Web target for the local lab.

The only vulnerability is intentional and local: ``/download`` validates the
*raw* query string (blocking literal ``..`` and absolute paths) before calling
``urllib.parse.unquote`` and joining the decoded name onto the public root.
Percent-encoded traversal (for example ``%2e%2e/private/flag.txt``) therefore
escapes the public root. A second, non-bypassable containment check keeps the
target inside its own temporary root so the lab can never read host files.

The flag is generated randomly per target process, stored in
``<root>/private/flag.txt``, and never written to the target request log.
"""
from __future__ import annotations

import argparse
import hashlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:  # normal package import (python -m labs.target)
    from .common import append_jsonl, make_dir, new_flag, now_iso, write_json
except ImportError:  # direct script execution
    from common import append_jsonl, make_dir, new_flag, now_iso, write_json


HOME = """<!doctype html>
<html><head><meta charset="utf-8"><title>Acme File Shelf</title></head>
<body>
<h1>Acme File Shelf</h1>
<p>Public shelf listing: <a href="/files/">/files/</a></p>
<p>Single-file API: <a href="/download?name=quote.txt">/download?name=quote.txt</a></p>
<!--
  dev note: /download validates the raw query string (it rejects ".." and a
  leading slash) and only then calls urllib.parse.unquote before joining the
  name onto ./public. Public files live in ./public; deployment secrets live
  in ../private and are not web-accessible.
-->
</body></html>
"""

LISTING = """<!doctype html>
<html><head><meta charset="utf-8"><title>File Shelf - public</title></head>
<body><h1>Public files</h1><ul>
<li><a href="/files/quote.txt">quote.txt</a></li>
<li><a href="/files/README.txt">README.txt</a></li>
</ul>
<p>Use <code>/download?name=&lt;file&gt;</code> for the legacy download endpoint.</p>
</body></html>
"""

SHELF_NOTES = """Shelf operations notes
======================

* Public files are served from ./public by the shelf process.
* The legacy /download endpoint was written before the realpath helper existed.
  It validates the raw query string and only afterwards calls unquote(); the
  decoded value is joined onto ./public without resolving it first.
* Deployment secrets are kept in ../private (for this deployment the flag file
  is ../private/flag.txt, relative to the public root). It must never be served.
* The /files/<name> route does not decode input, so it is not affected.
"""


def _raw_query_param(query: str, name: str) -> str | None:
    """Return a query parameter *without* decoding it.

    parse_qs would decode before the (intentionally naive) validation step, so
    the target uses a deliberately small raw parser instead.
    """
    for part in query.split("&"):
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


def _make_handler(root: Path, public: Path, log_path: Path,
                  seed: int, lock: threading.Lock):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AcmeFileShelf/1.4"
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):  # request logging is structured below
            pass

        def _record(self, status: int, body: bytes) -> None:
            append_jsonl(log_path, {
                "ts": now_iso(), "seed": seed, "method": self.command,
                "path": self.path, "status": status, "bytes": len(body),
            }, lock=lock)

        def _respond(self, status: int, body: bytes, content_type: str) -> bytes:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError):
                pass
            self._record(status, body)
            return body

        def _text(self, status: int, text: str, content_type: str = "text/html; charset=utf-8"):
            self._respond(status, text.encode("utf-8"), content_type)

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlsplit(self.path)
            route = parsed.path
            if route == "/":
                self._text(200, HOME)
            elif route == "/files/":
                self._text(200, LISTING)
            elif route in {"/files", "/files/"}:
                self._text(200, LISTING)
            elif route.startswith("/files/"):
                self._serve_literal(route[len("/files/"):])
            elif route == "/download":
                self._serve_download(parsed.query)
            elif route == "/robots.txt":
                self._text(200, "User-agent: *\nDisallow: /download\nDisallow: /private\n",
                           "text/plain; charset=utf-8")
            else:
                self._text(404, "not found\n", "text/plain; charset=utf-8")

        def _serve_literal(self, name: str) -> None:
            # Intentionally does not decode input and blocks traversal literally.
            if not name or name.startswith("/") or ".." in name:
                self._text(403, "blocked by path policy\n", "text/plain; charset=utf-8")
                return
            candidate = (public / name)
            try:
                data = candidate.read_bytes()
            except OSError:
                self._text(404, "not found\n", "text/plain; charset=utf-8")
                return
            self._respond(200, data, "text/plain; charset=utf-8")

        def _serve_download(self, query: str) -> None:
            raw = _raw_query_param(query, "name")
            if raw is None:
                self._text(400, "missing name\n", "text/plain; charset=utf-8")
                return
            # Naive, intentionally bypassable prefix/traversal policy: it runs on
            # the still-encoded string, before unquote().
            if not raw or raw.startswith("/") or ".." in raw:
                self._text(403, "blocked by path policy\n", "text/plain; charset=utf-8")
                return
            decoded = unquote(raw)
            candidate = (public / decoded)
            try:
                resolved = candidate.resolve()
                root_resolved = root.resolve()
            except OSError:
                self._text(400, "bad path\n", "text/plain; charset=utf-8")
                return
            # Host-containment guard: allows ../private inside the lab root,
            # but never escapes the temporary target root itself.
            if not resolved.is_relative_to(root_resolved):
                self._text(404, "not found\n", "text/plain; charset=utf-8")
                return
            try:
                data = resolved.read_bytes()
            except OSError:
                self._text(404, "not found\n", "text/plain; charset=utf-8")
                return
            self._respond(200, data, "text/plain; charset=utf-8")

    return Handler


def build_target(root: Path, seed: int = 0) -> dict:
    root = Path(root)
    public = make_dir(root / "public")
    private = make_dir(root / "private")
    make_dir(public / "files")
    flag = new_flag(seed)
    flag_file = private / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    (public / "files" / "quote.txt").write_text(
        "Small steps, carefully observed, solve large problems.\n", encoding="utf-8")
    (public / "files" / "README.txt").write_text(SHELF_NOTES, encoding="utf-8")
    (public / "index.html").write_text(HOME, encoding="utf-8")
    return {"root": root, "public": public, "private": private,
            "flag": flag, "flag_file": flag_file}


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized local Web lab target")
    parser.add_argument("--root", required=True, help="temporary target root directory")
    parser.add_argument("--ready-file", required=True, help="JSON readiness handshake path")
    parser.add_argument("--log", required=True, help="structured request log path")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--port", type=int, default=0, help="0 chooses an ephemeral port")
    args = parser.parse_args()

    root = make_dir(Path(args.root))
    state = build_target(root, args.seed)
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    handler = _make_handler(root, state["public"], log_path, args.seed, lock)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    server.daemon_threads = True
    origin = f"http://127.0.0.1:{server.server_port}"
    write_json(Path(args.ready_file), {
        "service": "target",
        "port": server.server_port,
        "origin": origin,
        "root": str(root),
        "flag_file": str(state["flag_file"]),
        "flag_sha256": hashlib.sha256(state["flag"].encode()).hexdigest(),
        "hint_path": "/files/README.txt",
    })
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
