#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BASE_DIR="${BASE_DIR_OVERRIDE:-"$(cd "${SCRIPT_DIR}/.."; pwd -P)"}"

CONFIG_DIR="${CONFIG_DIR_OVERRIDE:-"${BASE_DIR}/config"}"
PERSIST_DIR="${PERSIST_DIR_OVERRIDE:-"${BASE_DIR}/persist"}"
ENV_FILE="${ENV_FILE_OVERRIDE:-"${CONFIG_DIR}/.env"}"
IMAGE="${IMAGE_OVERRIDE:-"docker.io/parcnetwork/safeline-ipgroup-sources-sync:latest"}"

if command -v docker >/dev/null 2>&1; then
  RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
  RUNTIME="podman"
else
  echo "Container runtime not found (docker or podman required)." >&2
  exit 1
fi

mkdir -p "${PERSIST_DIR}"
[[ -f "${ENV_FILE}" ]] || { echo "Missing env file: ${ENV_FILE}" >&2; exit 1; }
[[ "${NO_PULL:-0}" == "1" ]] || ${RUNTIME} pull "${IMAGE}" >/dev/null 2>&1 || true

LOCK_FILE="${PERSIST_DIR}/run.lock"
exec 9>"${LOCK_FILE}"
flock -n 9 || exit 0

SOURCES_DIRS_DEFAULT="/app/config/sources.d:/app/config/local.d"
SOURCES_DIRS="${SOURCES_DIRS_OVERRIDE:-"${SOURCES_DIRS_DEFAULT}"}"

exec ${RUNTIME} run --rm \
  --name ip-sync \
  --env-file "${ENV_FILE}" \
  -e "STATE_PATH=/app/persist/.ipranges_state.json" \
  -e "LOG_LEVEL=${LOG_LEVEL:-INFO}" \
  -e "SOURCES_DIRS=${SOURCES_DIRS}" \
  -v "${CONFIG_DIR}:/app/config:ro" \
  -v "${PERSIST_DIR}:/app/persist" \
  --user "$(id -u):$(id -g)" \
  "${IMAGE}" \
  "$@"