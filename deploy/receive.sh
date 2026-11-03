#!/usr/bin/env bash
# Run from the private incoming directory; the registry token arrives on stdin.
set -euo pipefail
umask 077
bundle=$(cd "$(dirname "$0")" && pwd)
export AUTH_DEPLOY_DIR
AUTH_DEPLOY_DIR=$(dirname "$bundle")
export DOCKER_CONFIG
DOCKER_CONFIG=$(mktemp -d)
cleanup() {
  rm -rf "$DOCKER_CONFIG" "$bundle"
}
trap cleanup EXIT

docker compose version > /dev/null
command -v flock > /dev/null
docker login ghcr.io --username "$(cat "$bundle/registry-user")" --password-stdin > /dev/null
bash "$bundle/deploy.sh" "$(cat "$bundle/image")" "$bundle"
