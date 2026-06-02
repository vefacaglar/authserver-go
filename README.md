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

Requires **Go 1.26+** and a **PostgreSQL** database — the runtime persists
to Postgres only. Point `AUTH_DB_DSN` at your database (a managed Postgres
such as Neon works out of the box); the easiest way is a gitignored `.env`
file. (The test suite uses SQLite via cgo, so running `make test` needs a C
compiler.)

The repository ships a `Makefile` that plays the role of `package.json`
scripts. The one command you usually want:

```sh
make dev        # like `pnpm run dev` — run the server locally, Ctrl-C to stop
```

`make dev` runs [`scripts/dev.sh`](scripts/dev.sh), which fills in safe
local-dev defaults (HTTP issuer on `http://localhost:5175`, TLS off),
generates the required secret keys on the fly, and runs the server in the
foreground against the PostgreSQL given by `AUTH_DB_DSN` (loaded from `.env`
if present). It prints the issuer, the admin bearer token, and the
discovery URL on boot.

Run `make` with no target to see every task:

| Command | What it does |
| --- | --- |
| `make dev` | Run with local-dev defaults in the foreground (Ctrl-C to stop) |
| `make build` | Compile a binary to `./authserver` |
| `make run` | Build, then run the binary in the foreground |
| `make start` / `make stop` | Run in the **background** / stop it. `start` frees port `5175` first, so it always restarts cleanly (no "address already in use") |
| `make start-all` / `make stop-all` | Background the auth server **and** the browser demo client ([examples/loginflow](examples/loginflow)), then open `http://localhost:8090` and log in as `demo`/`demo` |
| `make test` | Run the full test suite |
| `make smoke` | Run the real-OIDC-client smoke test (build-tagged) |
| `make check` | `go vet` + `go test` + `go build` — run before committing |
| `make clean` | Remove build artifacts |

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
export AUTH_ADMIN_TOKEN=$(head -c 32 /dev/urandom | base64)

# Cookie + CSRF keys are generated server-side and stored in the database
# (the data-protection key ring) — no key env vars to manage.
make build && ./authserver migrate && ./authserver serve
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
| `AUTH_DB_DRIVER` | `postgres` | Must be `postgres` — the only supported runtime driver |
| `AUTH_DB_DSN` | _(required)_ | PostgreSQL DSN, e.g. `postgres://user:pass@host:5432/db?sslmode=require` |
| `AUTH_AUTO_MIGRATE` | `true` | Run schema migration on startup. Set `false` in production and run `authserver migrate` at deploy time for fast cold starts |
| `AUTH_SEED` | `true` | Seed demo client/user/scopes on startup. Set `false` in production |
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

Persistence is **GORM on PostgreSQL** (`AUTH_DB_DRIVER=postgres`) — the only
supported runtime driver. An in-memory store would keep sessions, refresh
tokens, and signing keys per-process: they would vanish on restart and
differ across instances behind a load balancer, so each would mint a
different signing key and reject the others' tokens. The server therefore
refuses to start on anything but Postgres. SQLite is used by the test suite
only — never as a runtime driver.

### Commands

The binary has three subcommands:

| Command | What it does |
| --- | --- |
| `authserver serve` | Start the HTTP server (default when no subcommand given) |
| `authserver migrate` | Apply the schema, seed demo fixtures, and pre-create the signing key — run once at deploy time |
| `authserver rotate-keys` | Generate a fresh active signing key and retire the current one (kept in JWKS so old tokens stay verifiable) |
| `authserver rotate-dp-keys` | Rotate the data-protection key (cookie + CSRF material); retired keys stay in the ring so existing sessions keep working |

### How migrations work

There is **no separate "generate migration" step**. The schema is derived
directly from the GORM entity structs in
[`internal/store/gormstore/entities.go`](internal/store/gormstore/entities.go),
and `gormstore.Migrate` runs `AutoMigrate` for every entity. It is
idempotent and additive: it creates missing tables, columns, and indexes and
leaves existing data alone.

So the workflow is:

1. **Change the schema** → edit the entity struct (add a field, add a
   `gorm:"index"` tag, etc.) in `entities.go`. If it's a brand-new table,
   add the entity to the `allEntities()` slice in the same file.
2. **Apply it** → run `authserver migrate` (or start with
   `AUTH_AUTO_MIGRATE=true`). The new column/table/index appears. No codegen,
   no migration files to commit.

### Production cold-start

For serverless / autoscaled deployments, migrating on every boot is slow.
Run the schema step once at deploy time and start the server with migration
and seeding off:

```sh
authserver migrate                       # once, at deploy
AUTH_AUTO_MIGRATE=false AUTH_SEED=false authserver serve
```

The cookie + CSRF keys live in the **data-protection key ring**
(`data_protection_keys` table): generated on the first `migrate`/boot,
shared by every instance from the database, and durable across restarts —
so sessions survive a restart and validate across the whole fleet with no
key env vars to distribute. Rotate them with `authserver rotate-dp-keys`;
retired keys stay in the ring so in-flight sessions keep working.

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
| Persistence | GORM on PostgreSQL (SQLite for tests only) |
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
  memory/              in-memory implementations (tests only)
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
