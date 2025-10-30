#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/safeline-sync"
ENV_FILE="$BASE_DIR/config/.env"
CONFIG_DIR="$BASE_DIR/config"
PERSIST_DIR="$BASE_DIR/persist"
IMAGE="docker.io/parcnetwork/safeline-ipgroup-sources-sync:latest"
DOCKER_BIN="$(command -v docker)"

mkdir -p "$PERSIST_DIR"
$DOCKER_BIN pull "$IMAGE" >/dev/null 2>&1 || true

LOCK_FILE="$PERSIST_DIR/run.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

exec "$DOCKER_BIN" run --rm \
  --env-file "$ENV_FILE" \
  -e STATE_PATH=/app/persist/.ipranges_state.json \
  -e LOG_LEVEL=INFO \
  -v "$CONFIG_DIR:/app/config:ro" \
  -v "$PERSIST_DIR:/app/persist" \
  --user "$(id -u):$(id -g)" \
  "$IMAGE"