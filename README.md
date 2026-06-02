# go-authserver

A standalone OAuth2 / OpenID Connect authorization server written in Go.
Functional and security port of an existing, production-hardened C# OIDC server.

This is a **deployable auth server** (single binary + config), not a reusable
library/package.

## Status

Feature-complete: all milestones (T1.1 → T8.3) are implemented and tested.
See [TASKS.md](TASKS.md) for the build plan and [BUILD_PROMPT.md](BUILD_PROMPT.md)
for the full technical spec.

## Quick start

Requires **Go 1.26+** (and a C compiler — the SQLite driver uses cgo).

The repository ships a `Makefile` that plays the role of `package.json`
scripts. The one command you usually want:

```sh
make dev        # like `pnpm run dev` — run the server locally, Ctrl-C to stop
```

`make dev` runs [`scripts/dev.sh`](scripts/dev.sh), which fills in safe
local-dev defaults (HTTP issuer on `http://localhost:5175`, TLS off, a
persistent SQLite file at `./dev.db`), generates the required secret keys
on the fly, then runs the server in the foreground. It prints the issuer,
the admin bearer token, and the discovery URL on boot.

Run `make` with no target to see every task:

| Command | What it does |
| --- | --- |
| `make dev` | Run with local-dev defaults in the foreground (Ctrl-C to stop) |
| `make build` | Compile a binary to `./authserver` |
| `make run` | Build, then run the binary in the foreground |
| `make start` / `make stop` | Run in the **background** / stop it (uses `./.authserver.pid`) |
| `make test` | Run the full test suite |
| `make smoke` | Run the real-OIDC-client smoke test (build-tagged) |
| `make check` | `go vet` + `go test` + `go build` — run before committing |
| `make db-reset` | Delete the local SQLite database (recreated on next run) |
| `make clean` | Remove build artifacts + the dev database |

## Running and stopping

### Foreground (development)

```sh
make dev
```

Stop it with **Ctrl-C** in the same terminal — the server traps
`SIGINT`/`SIGTERM` and shuts down gracefully (drains in-flight requests,
closes the DB).

### Background

```sh
make start     # launches in the background, writes ./.authserver.pid
make stop      # kills the pid and removes the file
```

### Production-style (manual env)

The server is configured **entirely via environment variables** and is
fail-fast: any missing/invalid value aborts startup with a clear message.
For a real (HTTPS) deployment, set the secrets yourself and build a binary:

```sh
export AUTH_ISSUER=https://auth.example.com          # must be https unless AUTH_REQUIRE_HTTPS=false
export AUTH_LISTEN_ADDR=:5175
export AUTH_DB_DRIVER=postgres
export AUTH_DB_DSN="host=db user=auth password=... dbname=auth sslmode=require"
export AUTH_COOKIE_HASH_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_COOKIE_BLOCK_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_CSRF_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_ADMIN_TOKEN=$(head -c 32 /dev/urandom | base64)

make build && ./authserver
```

On first boot the server bootstraps an RSA-2048 signing key, seeds the
standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`), a
public demo client (`demo-public`), a confidential demo client
(`demo-confidential`, fresh keypair each restart), and a demo user
(`demo` / `demo`).

### Configuration reference

| Variable | Default | Notes |
| --- | --- | --- |
| `AUTH_ISSUER` | _(required)_ | Absolute URL; must be `https` unless `AUTH_REQUIRE_HTTPS=false` |
| `AUTH_LISTEN_ADDR` | `:5175` | Bind address |
| `AUTH_REQUIRE_HTTPS` | `true` | `false` enables HTTP + drops the `__Host-` cookie prefix (dev only) |
| `AUTH_DB_DRIVER` | `sqlite` | `sqlite` or `postgres` (`memory` also accepted for throwaway runs) |
| `AUTH_DB_DSN` | `file::memory:?cache=shared` | SQLite file/DSN or Postgres DSN |
| `AUTH_COOKIE_HASH_KEY` | _(required)_ | base64, ≥32 bytes — session cookie HMAC |
| `AUTH_COOKIE_BLOCK_KEY` | _(required)_ | base64, ≥32 bytes — session cookie encryption |
| `AUTH_CSRF_KEY` | _(required)_ | base64, ≥32 bytes — CSRF token key |
| `AUTH_ADMIN_TOKEN` | _(required\*)_ | Admin API bearer; \*not required if `AUTH_ADMIN_ALLOW_ANONYMOUS=true` |
| `AUTH_ADMIN_ALLOW_ANONYMOUS` | `false` | Dev-only: open the admin API without a token |
| `AUTH_AUTH_CODE_LIFETIME` | `60s` | Must be ≤ 2m |
| `AUTH_ACCESS_TOKEN_LIFETIME` | `1h` | |
| `AUTH_ID_TOKEN_LIFETIME` | `1h` | |
| `AUTH_REFRESH_TOKEN_LIFETIME` | `720h` | Sliding lifetime |
| `AUTH_REFRESH_TOKEN_ABS_LIFETIME` | `720h` | Must be ≥ the sliding lifetime |
| `AUTH_DETECT_REFRESH_REUSE` | `true` | Reuse of a rotated refresh token revokes the chain |
| `AUTH_REQUIRE_PKCE` | `true` | S256 only |
| `AUTH_LOGIN_RATE_LIMIT` | `10` | Per-IP requests/sec on `/login` |

## Database & migrations

Persistence is **GORM**, with two supported drivers selected by
`AUTH_DB_DRIVER`:

- `sqlite` — default; great for dev/test. Use a **file DSN**
  (`AUTH_DB_DSN=file:./dev.db`, what `make dev` does) to persist across
  restarts, or `file::memory:?cache=shared` for a throwaway DB.
- `postgres` — production; `AUTH_DB_DSN` is a standard Postgres DSN.

### How migrations work

There is **no separate "generate migration" step**. The schema is derived
directly from the GORM entity structs in
[`internal/store/gormstore/entities.go`](internal/store/gormstore/entities.go),
and `gormstore.Migrate` runs `AutoMigrate` for every entity **automatically
on startup** (see [`cmd/authserver/main.go`](cmd/authserver/main.go)). It is
idempotent and additive: it creates missing tables, columns, and indexes and
leaves existing data alone.

So the workflow is:

1. **Change the schema** → edit the entity struct (add a field, add a
   `gorm:"index"` tag, etc.) in `entities.go`. If it's a brand-new table,
   add the entity to the `allEntities()` slice in the same file.
2. **Apply it** → just start the server (`make dev`). The new column/table/
   index appears on boot. No codegen, no migration files to commit.
3. **Reset locally** → `make db-reset` deletes `dev.db` and the next boot
   recreates the full schema from scratch.

> AutoMigrate intentionally does **not** drop columns or perform
> destructive/altering changes. For a column rename or type change on a
> production Postgres database, write and run the SQL yourself (or add a
> dedicated migration tool) — AutoMigrate will not do it for you.

## Using the server

### Discovery & JWKS

Everything a client needs is advertised at the standard endpoints:

```sh
curl http://localhost:5175/.well-known/openid-configuration
curl http://localhost:5175/.well-known/jwks.json
```

Endpoints: `/connect/authorize`, `/connect/token`, `/connect/userinfo`,
`/connect/revoke`, `/connect/logout`, plus `/login`, `/logout`, `/healthz`.

### Authorization Code + PKCE flow (the seeded demo client)

The `demo-public` client uses PKCE (S256) with redirect URI
`https://demo.example/callback`. End to end:

1. Generate a PKCE pair, then open the authorize URL in a browser:
   ```
   GET /connect/authorize?response_type=code&client_id=demo-public
       &redirect_uri=https://demo.example/callback
       &scope=openid%20profile%20email%20offline_access
       &state=xyz&code_challenge=<challenge>&code_challenge_method=S256
   ```
2. No session yet → you're redirected to `/login`. Sign in as
   **`demo` / `demo`** (the form carries a CSRF token).
3. The server redirects back to `redirect_uri` with `?code=...&state=xyz`.
4. Exchange the code at the token endpoint:
   ```sh
   curl -X POST http://localhost:5175/connect/token \
     -d grant_type=authorization_code \
     -d client_id=demo-public \
     -d code=<code> \
     -d redirect_uri=https://demo.example/callback \
     -d code_verifier=<verifier>
   ```
   You get an `access_token`, an `id_token` (verifiable against JWKS), and —
   because `offline_access` was requested — a `refresh_token`.
5. Call userinfo or refresh:
   ```sh
   curl http://localhost:5175/connect/userinfo -H "Authorization: Bearer <access_token>"
   curl -X POST http://localhost:5175/connect/token \
     -d grant_type=refresh_token -d client_id=demo-public -d refresh_token=<refresh_token>
   ```

The [smoke test](test/smoke_test.go) drives this entire flow with the real
`coreos/go-oidc` library — run `make smoke` to see it pass.

### Admin API

The admin JSON API (clients, scopes, sessions, refresh tokens, keys, audit
log) lives under `/admin` behind a bearer token. `make dev` prints the
token on boot:

```sh
curl http://localhost:5175/admin/api/clients -H "Authorization: Bearer <AUTH_ADMIN_TOKEN>"
```

A minimal admin SPA is served at `/admin` and lists clients via that API.
Key responses always strip the private PEM; mutations require a CSRF token.

## Source of truth

- [BUILD_PROMPT.md](BUILD_PROMPT.md) — full technical spec (architecture,
  models, endpoints, security rules). Read the relevant section before each
  task.
- [TASKS.md](TASKS.md) — ordered, checkbox build plan (T1.1 → T8.3). One
  task per session, in order.
- [AGENTS.md](AGENTS.md) — operating rules for AI agents and human
  contributors.

## Tech stack (locked)

| Concern | Choice |
| --- | --- |
| Language | Go 1.26+ (`log/slog` for logging) |
| HTTP router | `net/http` + `github.com/go-chi/chi/v5` |
| JOSE / JWT / JWKS | `github.com/lestrrat-go/jwx/v2` |
| Persistence | GORM (Postgres in prod, SQLite for dev/test) |
| Session cookie | `github.com/gorilla/securecookie` |
| CSRF | `github.com/gorilla/csrf` |
| Rate limiting | `golang.org/x/time/rate` |
| Password hashing | `golang.org/x/crypto/bcrypt` |
| Entity IDs | `github.com/google/uuid` |

## Layout

```text
internal/clock/        Clock interface + SystemClock / FakeClock
internal/config/       env-driven config + validation
internal/domain/       plain model structs
internal/store/        store interfaces (ports)
  memory/              in-memory implementations
  gormstore/           GORM implementations (M5)
internal/token/        hashing, PKCE, RSA keys, JWT issuance
internal/session/      encrypted SSO cookie
internal/oidc/         HTTP handlers (discovery, jwks, authorize, token, ...)
internal/admin/        admin JSON API + SPA (auth-required)
internal/server/       router + middleware
cmd/authserver/        composition root (wiring, seed, graceful shutdown)
scripts/dev.sh         one-command local dev runner (used by `make dev`)
Makefile               developer task runner (dev/build/test/...)
test/                  end-to-end integration + smoke tests
```

## Security

Targets parity with a hardened C# OIDC server audited against RFC 6749 / 7009 /
7636 / 8414 / 9700 / OIDC Core. Highlights:

- PKCE required by default, S256 only (constant-time verify, `plain` rejected)
- `redirect_uri` exact match — validated before any redirect
- Authorization codes: single-use via atomic CAS, ≤2 minute lifetime,
  hash-only storage
- Refresh tokens: opaque, hash-only, rotated on use, reuse detection revokes
  the chain
- `private_key_jwt` client auth with `jti` replay protection
- Session cookie: encrypted + signed, `__Host-` prefix under HTTPS

Full checklist: [BUILD_PROMPT.md](BUILD_PROMPT.md#security-checklist-must-hold-at-the-end).

## Contributing

Work **one task at a time** from `TASKS.md`, in order. Read the matching
section of `BUILD_PROMPT.md` first. Keep `go build ./...`, `go vet ./...`, and
`go test ./...` clean after every change.
