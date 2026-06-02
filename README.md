# go-authserver

A standalone OAuth2 / OpenID Connect authorization server written in Go.
Functional and security port of an existing, production-hardened C# OIDC server.

This is a **deployable auth server** (single binary + config), not a reusable
library/package.

## Status

Active development, Milestone 1 of 8. See [TASKS.md](TASKS.md) for the build
plan and [BUILD_PROMPT.md](BUILD_PROMPT.md) for the full technical spec.

## Build, test, run

Requires Go 1.23 or newer.

```sh
go build ./...     # compile everything
go vet ./...       # static checks (must be clean)
go test ./...      # run unit + integration tests
go run ./cmd/authserver   # run the binary
```

### Running the server

The server is configured entirely via environment variables. The minimum
required to start it (in-memory store, no auth required for the admin SPA,
no TLS) is:

```sh
export AUTH_ISSUER=https://auth.example.com
export AUTH_COOKIE_HASH_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_COOKIE_BLOCK_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_CSRF_KEY=$(head -c 32 /dev/urandom | base64)
export AUTH_ADMIN_TOKEN=$(head -c 32 /dev/urandom | base64)
go run ./cmd/authserver
```

The first call bootstraps an RSA-2048 signing key, seeds the standard
OIDC scopes (`openid`, `profile`, `email`, `offline_access`), a public
demo client, a confidential demo client (with a freshly generated
keypair — re-seeded every restart), and a demo user (`demo` / `demo`).

### OIDC discovery

The server publishes its metadata at:

```
GET /.well-known/openid-configuration
```

### Smoke test

A real `coreos/go-oidc` client (the same library Kubernetes and
Terraform use) completes the discovery → JWKS → ID-token verify →
userinfo flow against the server. The test is build-tagged so it
does not run by default:

```sh
RUN_SMOKE=1 go test -tags m8smoke -v -count=1 -run TestSmoke_RealOIDCClient ./test/...
```

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
| Language | Go 1.23+ (`log/slog` for logging) |
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
cmd/authserver/        composition root (main)
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
test/                  end-to-end integration tests
web/                   templates + admin SPA assets
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
