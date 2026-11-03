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

web_image=${3:-}
if [[ -z "$web_image" && -f .current-web-image ]]; then
  web_image=$(cat .current-web-image)
fi
[[ "$web_image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
previous_web_image=""
if [[ -f .current-web-image ]]; then
  previous_web_image=$(cat .current-web-image)
  [[ "$previous_web_image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
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
export AUTH_WEB_IMAGE="$web_image"
docker compose --env-file .env -f compose.yml config --quiet
docker compose --env-file .env -f compose.yml pull authserver web
# Migrate before replacing the running service. AUTH_SEED=false also applies here.
# Database backups and backward-compatible migrations are required: image rollback
# cannot undo a database migration.
docker compose --env-file .env -f compose.yml run --rm --no-deps authserver migrate
rollback() {
  if [[ -n "$previous_image" && -f .last-good-compose.yml ]]; then
    restore_config
    echo "Restoring the previous healthy deployment."
    # The previous compose may predate the web service; only bring it
    # back when there is a previous web image to run.
    rollback_services=(authserver)
    [[ -n "$previous_web_image" ]] && rollback_services+=(web)
    AUTH_IMAGE="$previous_image" AUTH_WEB_IMAGE="${previous_web_image:-$web_image}" docker compose --env-file .env -f .last-good-compose.yml up -d --wait --wait-timeout 120 "${rollback_services[@]}"
  else
    # A failed first deployment has no healthy release to restore. Remove the
    # candidate while its Compose configuration is still installed.
    docker compose --env-file .env -f compose.yml down
    restore_config
  fi
}
if ! docker compose --env-file .env -f compose.yml up -d --wait --wait-timeout 120 authserver web; then
  echo "Auth server or web health check failed."
  rollback
  exit 1
fi

# Proxy configuration is part of the release, under the same deployment lock.
# Do not record a last-good release before this step succeeds.
if [[ -n "$bundle" ]] && ! python3 "$bundle/configure-caddy.py"; then
  echo "Caddy configuration failed."
  rollback
  exit 1
fi

if [[ -n "$bundle" ]]; then
  install -m 700 "$bundle/deploy.sh" deploy.sh
fi
if [[ -n "$previous_image" ]]; then
  printf '%s\n' "$previous_image" > .previous-image
fi
if [[ -n "$previous_web_image" ]]; then
  printf '%s\n' "$previous_web_image" > .previous-web-image
fi
cp compose.yml .last-good-compose.yml
printf '%s\n' "$image" > .current-image
printf '%s\n' "$web_image" > .current-web-image
echo "Auth server deployment is healthy."
