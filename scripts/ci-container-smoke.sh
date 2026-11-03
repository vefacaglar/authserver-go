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
proxy="authserver-ci-proxy-$$"
export AUTH_IMAGE="$image" AUTH_WEB_IMAGE="$web_image" AUTH_DOCKER_NETWORK="$network" AUTH_BIND_PORT=15175 AUTH_WEB_BIND_PORT=15176

compose() {
  docker compose --project-name "$project" --env-file "$work/.env" -f "$work/compose.yml" "$@"
}
cleanup() {
  local status=$?
  if ((status != 0)); then
    echo "Container smoke check failed; collecting diagnostics before cleanup." >&2
    compose ps --all || true
    compose logs --no-color --tail 100 || true
    docker logs --tail 100 "$proxy" 2>/dev/null || true
    local container
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      docker inspect --format '{{.Name}} {{json .State}}' "$container" || true
    done < <(compose ps --all --quiet)
  fi
  compose down --volumes || true
  docker rm -f "$proxy" > /dev/null 2>&1 || true
  docker rm -f "$database" > /dev/null 2>&1 || true
  docker network rm "$network" > /dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
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
# Both containers must run unprivileged.
for service in authserver web; do
  [[ "$(compose exec -T "$service" id -u)" == 10001 ]]
done

# Exercise the generated production path split through one origin. Only TLS
# termination is replaced with HTTP in this isolated, loopback-only test.
python3 - "$repo" "$work/Caddyfile" <<'PY'
from pathlib import Path
import runpy
import sys
proxy = runpy.run_path(str(Path(sys.argv[1]) / 'deploy/configure-caddy.py'))
config = proxy['updated_config']('', 'authserver-go-api:5175', 'authserver-go-web:8080', False)
config = config.replace('auth.vefacaglar.com {', 'http://auth.vefacaglar.com:8080 {', 1)
Path(sys.argv[2]).write_text(config)
PY
docker run -d --name "$proxy" --network "$network" \
  -p 127.0.0.1:15177:8080 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,source=$work/Caddyfile,target=/etc/caddy/Caddyfile,readonly" \
  "$web_image" > /dev/null
curl --fail --silent --show-error --retry 15 --retry-delay 1 --retry-all-errors --max-time 5 \
  -H 'Host: auth.vefacaglar.com' http://127.0.0.1:15177/healthz > /dev/null
python3 "$repo/scripts/check-container-routes.py" http://127.0.0.1:15177
echo "Production container, migration, and same-origin routing checks passed."
