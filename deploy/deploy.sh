#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

image=${1:?Pass the published image digest}
[[ "$image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
test -f .env && test -f authserver.env

exec 9>.deploy.lock
flock -w 180 9

previous_image=""
if [[ -f .current-image ]]; then
  previous_image=$(cat .current-image)
  [[ "$previous_image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
fi

export AUTH_IMAGE="$image"
docker compose --env-file .env -f compose.yml config --quiet
docker compose --env-file .env -f compose.yml pull authserver
# Migrate before replacing the running service. AUTH_SEED=false also applies here.
# Database backups and backward-compatible migrations are required: image rollback
# cannot undo a database migration.
docker compose --env-file .env -f compose.yml run --rm --no-deps authserver migrate
if ! docker compose --env-file .env -f compose.yml up -d --wait --wait-timeout 120 authserver; then
  echo "Auth server health check failed."
  if [[ -n "$previous_image" && -f .last-good-compose.yml ]]; then
    echo "Restoring the previous healthy deployment."
    AUTH_IMAGE="$previous_image" docker compose --env-file .env -f .last-good-compose.yml up -d --wait --wait-timeout 120 authserver
  fi
  exit 1
fi

if [[ -n "$previous_image" ]]; then
  printf '%s\n' "$previous_image" > .previous-image
fi
cp compose.yml .last-good-compose.yml
printf '%s\n' "$image" > .current-image
echo "Auth server deployment is healthy."
