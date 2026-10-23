"""Bounded self-contained smoke test of the image's first-stage Web tools."""
import base64
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import threading
import urllib.request


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b'{"page":"&amp;","ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    for tool in ("curl", "jq", "file"):
        assert shutil.which(tool), tool
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=2) as response:
            data = json.load(response)
        assert data["ok"] and html.unescape(data["page"]) == "&"
        assert base64.b64decode("QQ==") == b"A"
        target = Path("/ctfy/work/web-check.json")
        target.write_text(json.dumps(data), encoding="utf-8")
        assert json.loads(target.read_text(encoding="utf-8")) == data
        print("web_tool_smoke_passed")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
