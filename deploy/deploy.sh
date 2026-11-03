#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "${AUTH_DEPLOY_DIR:-$(dirname "$0")}"

image=${1:?Pass the published image digest}
[[ "$image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
exec 9>.deploy.lock
flock -w 180 9

previous_image=""
if [[ -f .current-image ]]; then
  previous_image=$(cat .current-image)
  [[ "$previous_image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
fi

# Install configuration only after acquiring the deployment lock. Keep a private
# copy so failed migrations/deployments also restore the previous environment.
backup=""
config_installed=false
restore_config() {
  if [[ "$config_installed" == true ]]; then
    for name in .env authserver.env compose.yml; do
      if [[ -f "$backup/$name" ]]; then
        cp "$backup/$name" "$name"
      else
        rm -f "$name"
      fi
    done
  fi
}
cleanup() {
  status=$?
  if ((status != 0)); then
    restore_config
  fi
  if [[ -n "$backup" ]]; then
    rm -rf "$backup"
  fi
  exit "$status"
}
trap cleanup EXIT
bundle=${2:-}
if [[ -n "$bundle" ]]; then
  for name in .env authserver.env compose.yml; do
    test -f "$bundle/$name"
  done
  backup=$(mktemp -d "$PWD/.deploy-backup.XXXXXX")
  for name in .env authserver.env compose.yml; do
    if [[ -f "$name" ]]; then
      cp "$name" "$backup/$name"
    fi
  done
  config_installed=true
  for name in .env authserver.env compose.yml; do
    install -m 600 "$bundle/$name" "$name"
  done
fi
test -f .env && test -f authserver.env

export AUTH_IMAGE="$image"
docker compose --env-file .env -f compose.yml config --quiet
docker compose --env-file .env -f compose.yml pull authserver
# Migrate before replacing the running service. AUTH_SEED=false also applies here.
# Database backups and backward-compatible migrations are required: image rollback
# cannot undo a database migration.
docker compose --env-file .env -f compose.yml run --rm --no-deps authserver migrate
if ! docker compose --env-file .env -f compose.yml up -d --wait --wait-timeout 120 authserver; then
  echo "Auth server health check failed."
  restore_config
  if [[ -n "$previous_image" && -f .last-good-compose.yml ]]; then
    echo "Restoring the previous healthy deployment."
    AUTH_IMAGE="$previous_image" docker compose --env-file .env -f .last-good-compose.yml up -d --wait --wait-timeout 120 authserver
  fi
  exit 1
fi

if [[ -n "$bundle" ]]; then
  install -m 700 "$bundle/deploy.sh" deploy.sh
fi
if [[ -n "$previous_image" ]]; then
  printf '%s\n' "$previous_image" > .previous-image
fi
cp compose.yml .last-good-compose.yml
printf '%s\n' "$image" > .current-image
echo "Auth server deployment is healthy."
