#!/usr/bin/env bash
# Push the local QUTAgent image to the CTFy registry.
#
# Usage (WSL/Linux with Docker):
#   scripts/push_image.sh [env-file] [local-image] [tag]
#
# Reads only CTFY_* values from the gitignored env file (default:
# artifacts/ctfy.env) and never prints the token. Required:
#   CTFY_TOKEN
#   CTFY_REGISTRY_NAMESPACE   (copy the prefix shown on /evals/new)
# Optional:
#   CTFY_REGISTRY=registry.ctfy.io
#   CTFY_REGISTRY_USER=qutagent
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-$ROOT/artifacts/ctfy.env}"
LOCAL_IMAGE="${2:-qutagent:dev}"
TAG="${3:-v1}"

if [ ! -f "$ENV_FILE" ]; then
  echo "missing env file: $ENV_FILE (copy artifacts/ctfy.env.example)" >&2
  exit 2
fi

# Read only the keys we need; do not echo values.
value_of() {
  local key="$1"
  local line
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "$ENV_FILE" | tail -1 || true)"
  [ -n "$line" ] || return 1
  line="${line#*=}"
  line="${line%$'\r'}"
  line="${line#\"}"; line="${line%\"}"
  line="${line#\'}"; line="${line%\'}"
  printf '%s' "$line"
}

TOKEN="$(value_of CTFY_TOKEN || true)"
NAMESPACE="$(value_of CTFY_REGISTRY_NAMESPACE || true)"
REGISTRY="$(value_of CTFY_REGISTRY || true)"
REGISTRY="${REGISTRY:-registry.ctfy.io}"
REGISTRY_USER="$(value_of CTFY_REGISTRY_USER || true)"
REGISTRY_USER="${REGISTRY_USER:-qutagent}"

if [ -z "$TOKEN" ]; then
  echo "CTFY_TOKEN is empty in $ENV_FILE" >&2
  exit 2
fi
if [ -z "$NAMESPACE" ]; then
  echo "CTFY_REGISTRY_NAMESPACE is empty in $ENV_FILE" >&2
  echo "Copy the namespace shown on https://ctfy.tsinghua.edu.cn/evals/new" >&2
  exit 2
fi

TARGET="${REGISTRY}/${NAMESPACE}/qutagent:${TAG}"
echo "local image:  ${LOCAL_IMAGE}"
echo "target image: ${TARGET}"

printf '%s' "$TOKEN" | docker login "$REGISTRY" -u "$REGISTRY_USER" --password-stdin
docker tag "$LOCAL_IMAGE" "$TARGET"
docker push "$TARGET"
echo "pushed: ${TARGET}"
echo "next: open /evals/new, put the target image reference in 镜像地址, choose model, start."
