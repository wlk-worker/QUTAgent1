#!/usr/bin/env bash
# Run from WSL/Linux with Docker, Docker Compose and ctfy 0.7.0 installed.
set -euo pipefail

cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -v
docker build --pull=false --platform linux/amd64 -t qutagent:dev .
ctfy agent check qutagent:dev --json
ctfy-admin challenge audit --all --challenges-dir author/generated --strict --json
ctfy-admin challenge smoke --all --challenges-dir author/generated --ephemeral-ports --jobs 2 --timeout 180
