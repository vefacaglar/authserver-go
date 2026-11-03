#!/usr/bin/env bash
# Exercise the actual image and production Compose configuration with disposable data.
set -euo pipefail
image=${1:-authserver:ci}
web_image=${2:-authserver-web:ci}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
network="authserver-ci-$$"
database="authserver-ci-db-$$"
project="authserver-ci-$$"
export AUTH_IMAGE="$image" AUTH_WEB_IMAGE="$web_image" AUTH_DOCKER_NETWORK="$network" AUTH_BIND_PORT=15175 AUTH_WEB_BIND_PORT=15176

compose() {
  docker compose --project-name "$project" --env-file "$work/.env" -f "$work/compose.yml" "$@"
}
cleanup() {
  compose down --volumes || true
  docker rm -f "$database" > /dev/null 2>&1 || true
  docker network rm "$network" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cp "$repo/deploy/compose.yml" "$work/compose.yml"
touch "$work/.env"
cat > "$work/authserver.env" <<'ENV'
AUTH_DB_DSN=postgres://authserver:ci-only-password@postgres:5432/authserver?sslmode=disable
AUTH_ADMIN_TOKEN=ci-only-admin-token-not-for-production
ENV
docker network create "$network" > /dev/null
docker run -d --name "$database" --network "$network" --network-alias postgres \
  -e POSTGRES_USER=authserver -e POSTGRES_DB=authserver -e POSTGRES_PASSWORD=ci-only-password \
  postgres:17-alpine > /dev/null
ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if docker exec "$database" pg_isready -U authserver -d authserver > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]]
compose config --quiet
compose run --rm --no-deps authserver migrate
compose run --rm --no-deps authserver migrate
sql() {
  docker exec "$database" psql -U authserver -d authserver -Atqc "$1"
}
[[ "$(sql 'SELECT count(*) FROM oauth_users')" == 0 ]]
[[ "$(sql 'SELECT count(*) FROM oauth_clients')" == 0 ]]
[[ "$(sql 'SELECT count(*) FROM oauth_signing_keys')" == 1 ]]
[[ "$(sql 'SELECT count(*) FROM data_protection_keys')" == 1 ]]
compose up -d --wait --wait-timeout 120
curl --fail --silent --show-error http://127.0.0.1:15175/healthz > /dev/null
curl --fail --silent --show-error http://127.0.0.1:15175/.well-known/openid-configuration \
  | jq -e '.issuer == "https://auth.vefacaglar.com"' > /dev/null
curl --fail --silent --show-error http://127.0.0.1:15175/.well-known/jwks.json \
  | jq -e '(.keys | length) > 0 and all(.keys[]; has("d") | not)' > /dev/null
curl --fail --silent --show-error http://127.0.0.1:15176/login | grep -q '<div id="root">'
echo "Production container and migration checks passed."
