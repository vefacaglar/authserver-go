#!/usr/bin/env bash
#
# dev.sh — one-command local dev runner for go-authserver.
#
# Mirrors the convenience of `pnpm run dev`: it fills in safe local-dev
# defaults (HTTP issuer, no TLS), generates the required secret keys on the
# fly if not already exported, then runs the server in the foreground
# against the PostgreSQL given by AUTH_DB_DSN. Press Ctrl-C to stop it.
#
# Override any value by exporting the matching AUTH_* variable before
# calling this script.

set -euo pipefail
cd "$(dirname "$0")/.."

# --- load .env if present (values already exported win over defaults below) ---
if [ -f .env ]; then set -a; . ./.env; set +a; fi

# --- secrets: generate ephemeral 32-byte keys unless already set ---
gen_key() { head -c 32 /dev/urandom | base64; }

export AUTH_COOKIE_HASH_KEY="${AUTH_COOKIE_HASH_KEY:-$(gen_key)}"
export AUTH_COOKIE_BLOCK_KEY="${AUTH_COOKIE_BLOCK_KEY:-$(gen_key)}"
export AUTH_CSRF_KEY="${AUTH_CSRF_KEY:-$(gen_key)}"
export AUTH_ADMIN_TOKEN="${AUTH_ADMIN_TOKEN:-$(gen_key)}"

# --- local-dev server config ---
# HTTP (not HTTPS) so you can hit it from a browser/curl without certs.
export AUTH_REQUIRE_HTTPS="${AUTH_REQUIRE_HTTPS:-false}"
export AUTH_ISSUER="${AUTH_ISSUER:-http://localhost:5175}"
export AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-:5175}"

# The server runs on PostgreSQL only. Point AUTH_DB_DSN at your database
# (set it here, in your shell, or in a gitignored .env file). A managed
# Postgres such as Neon works out of the box — its data persists across
# server restarts, so sessions survive a restart.
export AUTH_DB_DRIVER="${AUTH_DB_DRIVER:-postgres}"

if [ -z "${AUTH_DB_DSN:-}" ]; then
  echo "ERROR: AUTH_DB_DSN is not set." >&2
  echo "       Put your PostgreSQL DSN in a .env file (gitignored), e.g.:" >&2
  echo "         AUTH_DB_DSN=postgres://USER:PASS@HOST:5432/DB?sslmode=require" >&2
  exit 1
fi

echo "==> go-authserver dev"
echo "    issuer : $AUTH_ISSUER"
echo "    listen : $AUTH_LISTEN_ADDR"
echo "    db     : $AUTH_DB_DRIVER ($AUTH_DB_DSN)"
echo "    admin  : Authorization: Bearer $AUTH_ADMIN_TOKEN"
echo "    discovery: $AUTH_ISSUER/.well-known/openid-configuration"
echo "    (Ctrl-C to stop)"
echo

exec go run ./cmd/authserver
