# Build Prompt — Go OAuth2 / OpenID Connect Auth Server

> **How to use this file.** This is a self-contained spec for an LLM building a Go OAuth2/OIDC server in a fresh repo. It is a port of an existing, production-hardened C# server (`Vefa.CustomAuth`). The **target is a standalone runnable auth server**, not a reusable library/package. Build the protocol flow first with in-memory stores, prove it, then add GORM persistence behind the same interfaces. Work task-by-task using `TASKS.md`; this file is the reference an implementer reads at every task.

---

## Context

The author has a working C# OAuth2/OIDC SSO server and wants the same capability rebuilt in Go as a deployable service (a single binary + config), not a distributable package. The C# version implements Authorization Code + PKCE, refresh-token rotation with reuse detection, client_credentials, `private_key_jwt` client auth, an SSO session cookie, JWKS key rotation, and a full set of OIDC endpoints, all hardened against a formal RFC 6749 / 7009 / 7636 / 8414 / 9700 / OIDC Core audit. This document encodes that behavior so a Go implementation can reach functional and security parity.

**Intended outcome:** a Go service that another app can point an off-the-shelf OIDC client at (e.g. `coreos/go-oidc`, `golang.org/x/oauth2`) and get working SSO, plus an admin UI to manage clients/scopes/sessions.

---

## Technology decisions (locked)

| Concern | Choice | Notes |
|---|---|---|
| Language / version | **Go 1.23+** | Use `log/slog` for structured logging. |
| HTTP router | **`net/http` + `github.com/go-chi/chi/v5`** | chi for middleware groups (the admin API needs an auth-required group), idiomatic, minimal. |
| JOSE / JWT / JWKS | **`github.com/lestrrat-go/jwx/v2`** | `jwk` for key sets + JWKS endpoint, `jws`/`jwt` for signing & verification, handles RSA keygen, `kid`, and `private_key_jwt` assertion verification cleanly. Do **not** mix with `golang-jwt`. |
| Persistence | **GORM** (`gorm.io/gorm`) | Postgres in prod (`gorm.io/driver/postgres`), SQLite (`gorm.io/driver/sqlite`) for dev + tests. `AutoMigrate` for schema. |
| Session cookie encryption | **`github.com/gorilla/securecookie`** | Encrypt + sign the session id (parity with ASP.NET DataProtection). Keys come from config so multiple instances share them. |
| CSRF | **`github.com/gorilla/csrf`** | On `/login` POST, `/connect/logout` POST, and admin mutating endpoints. |
| Rate limiting | **`golang.org/x/time/rate`** | Per-IP limiter middleware on `/login` POST. |
| Password hashing (sample users) | **`golang.org/x/crypto/bcrypt`** | User store is host-owned; sample uses bcrypt + constant-time compare. |
| HTML | **`html/template`** (stdlib) | Login, logout-confirm, admin pages. Server-rendered; admin can use a tiny vanilla-JS SPA fetching the admin JSON API. |
| Config | **env vars** via `github.com/caarlos0/env/v11` (or stdlib) | 12-factor; see Config section. |
| Tests | stdlib `testing` + `net/http/httptest` | Integration tests hit the real router. Use SQLite in-memory or `testcontainers-go` for Postgres if desired. |

**Language rule (strict):** all code identifiers, comments, log messages, error strings, user-facing protocol error responses, commit messages, and `.md` docs are **English only**.

---

## Repository layout

Single Go module. Standalone server under `cmd/`, everything else `internal/` (this is an application, not a library — keep the surface private).

```text
go-authserver/
  go.mod
  cmd/
    authserver/
      main.go                # wires config, db, stores, router; serves
  internal/
    config/                  # Config struct + env loading + validation
    domain/                  # models (structs): Client, AuthorizationCode, RefreshToken,
                             #   Session, SigningKey, Scope, AuditLog, UserInfo, paging types
    store/
      store.go               # store interfaces (ports)
      memory/                # in-memory implementations (build & prove the flow first)
      gormstore/             # GORM implementations + gorm entity types + AutoMigrate
    token/
      hasher.go              # SHA-256 + base64url hashing; secure random opaque tokens
      pkce.go                # S256 verification, constant-time compare
      keys.go                # RSA-2048 keygen, PEM <-> jwk, active-key selection
      issuer.go              # access / id token JWT issuance, at_hash, nonce, auth_time
      clientassertion.go     # private_key_jwt validation + jti replay cache
    session/
      cookie.go              # encrypted SSO session cookie (securecookie), __Host- prefixing
    oidc/
      discovery.go           # GET /.well-known/openid-configuration
      jwks.go                # GET /.well-known/jwks.json
      authorize.go           # GET /connect/authorize
      token.go               # POST /connect/token (dispatcher)
      grants/
        authcode.go          # authorization_code grant handler
        refresh.go           # refresh_token grant handler (rotation + reuse detection)
        clientcreds.go       # client_credentials grant handler
      userinfo.go            # GET+POST /connect/userinfo
      revoke.go              # POST /connect/revoke (RFC 7009)
      login.go               # GET (render) + POST (validate) /login
      logout.go              # GET+POST /connect/logout (RP-initiated)
      errors.go              # OAuth error JSON + no-store helpers + redirect-error helper
      clientauth.go          # client authentication at token endpoint (none / private_key_jwt)
    admin/
      api.go                 # client/scope/session/refresh-token/key/audit JSON CRUD
      ui.go                  # serves the admin SPA (auth-required group)
    server/
      router.go              # chi router, route table, middleware order
      middleware.go          # request id, recover, rate limit, security headers
  web/
    templates/               # login.html, logout_confirm.html, admin/index.html
    static/                  # admin SPA assets (alpine/vanilla JS + minimal CSS)
  test/
    integration_test.go      # end-to-end flow tests
```

---

## Domain models (`internal/domain`)

Plain structs. Times are `time.Time` (UTC). Use a `Clock` interface (`Now() time.Time`) injected everywhere instead of calling `time.Now()` directly, so tests can use a fake clock (parity with the C# `TimeProvider` rule).

- **Client**
  - `ClientID string` (PK), `DisplayName string`
  - `RedirectURIs []string`, `PostLogoutRedirectURIs []string`, `AllowedScopes []string`
  - `RequirePKCE bool` (default true), `AllowRefreshTokens bool` (default true), `AllowClientCredentials bool` (default false)
  - `TokenEndpointAuthMethod` enum: `none` | `private_key_jwt` (default `none`)
  - `JWKSJSON string` (inline public JWKS for `private_key_jwt`; no remote `jwks_uri` fetching in v1)
  - `AccessTokenLifetimeSeconds int` (default 3600), `RefreshTokenLifetimeSeconds int` (default 2592000), `RefreshTokenAbsoluteLifetimeSeconds int` (default 2592000)
  - `Properties map[string]string` (free-form extensibility bag — persisted as one JSON column)
  - **Constraint:** if `AllowRefreshTokens`, `AllowedScopes` must include `offline_access`.

- **AuthorizationCode**
  - `ID uuid.UUID`, `CodeHash string`, `ClientID string`, `UserID string`, `SessionID *uuid.UUID`
  - `RedirectURI string`, `CodeChallenge *string`, `CodeChallengeMethod *string` (S256 only)
  - `Scope string`, `Nonce *string`
  - `ExpiresAt time.Time`, `ConsumedAt *time.Time`, `CreatedAt time.Time`
  - Raw code is **never** stored — only its hash.

- **RefreshToken**
  - `ID uuid.UUID`, `TokenHash string`, `ClientID string`, `UserID string`
  - `SessionID *uuid.UUID`, `ParentTokenID *uuid.UUID` (rotation chain)
  - `Scope string`
  - `ExpiresAt time.Time` (sliding), `AbsoluteExpiresAt time.Time` (hard ceiling)
  - `ConsumedAt *time.Time`, `RevokedAt *time.Time`, `CreatedAt time.Time`
  - Opaque random value, stored as hash only.

- **Session** (SSO)
  - `ID uuid.UUID` (this is what the encrypted cookie carries), `UserID string`
  - `CreatedAt time.Time`, `ExpiresAt time.Time`, `RevokedAt *time.Time`
  - `Properties map[string]string` (acr/amr/device binding extensibility)

- **SigningKey**
  - `KeyID string` (`kid`), `Algorithm string` (default `RS256`)
  - `PrivateKeyPEM string`, `PublicKeyPEM string`
  - `CreatedAt time.Time`, `RetiredAt *time.Time`, `IsActive bool`
  - Private material never leaves the server; only public JWK is exposed.

- **Scope**: `Name string` (PK), `DisplayName`, `Description`, `Required bool`, `Emphasize bool`, `Properties map[string]string`.
- **AuditLog**: `ID uuid.UUID`, `Action string`, `ActorUserID string`, `TargetType`, `TargetID`, `Timestamp time.Time`, `IPAddress`, `UserAgent`, `Metadata string` (JSON). Never log raw tokens/codes/passwords/PII.
- **UserInfo** (returned by user store): `UserID string`, `Claims map[string]any` (e.g. `name`, `preferred_username`, `email`, `email_verified`).
- **PagedRequest{Page, PageSize}**, **PagedResult[T]{Items, TotalCount, Page, PageSize}**.

---

## Store interfaces (`internal/store`)

Ports only. Two implementations: `memory` (first) and `gormstore` (second). All methods take `context.Context`.

```go
type ClientStore interface {
    FindByClientID(ctx, clientID string) (*domain.Client, error)
    GetPaged(ctx, req PagedRequest) (PagedResult[domain.Client], error)
    Store(ctx, c *domain.Client) error
    Delete(ctx, clientID string) error
}

type AuthorizationCodeStore interface {
    Store(ctx, code *domain.AuthorizationCode) error
    FindByHash(ctx, codeHash string) (*domain.AuthorizationCode, error)
    // Atomic CAS: transitions ConsumedAt null -> consumedAt. Returns true ONLY if it won.
    MarkConsumed(ctx, id uuid.UUID, consumedAt time.Time) (bool, error)
}

type RefreshTokenStore interface {
    Store(ctx, t *domain.RefreshToken) error
    FindByHash(ctx, tokenHash string) (*domain.RefreshToken, error)
    GetPaged(ctx, req PagedRequest) (PagedResult[domain.RefreshToken], error)
    MarkConsumed(ctx, id uuid.UUID, consumedAt time.Time) (bool, error) // atomic CAS
    Revoke(ctx, id uuid.UUID, revokedAt time.Time) error
    RevokeBySessionID(ctx, sessionID uuid.UUID, revokedAt time.Time) error
}

type SessionStore interface {
    Find(ctx, id uuid.UUID) (*domain.Session, error)
    GetPaged(ctx, req PagedRequest) (PagedResult[domain.Session], error)
    Store(ctx, s *domain.Session) error
    Revoke(ctx, id uuid.UUID, revokedAt time.Time) error
}

type SigningKeyStore interface {
    GetActive(ctx) (*domain.SigningKey, error)
    GetAll(ctx) ([]domain.SigningKey, error)
    Store(ctx, k *domain.SigningKey) error
}

type ScopeStore interface {
    FindByName(ctx, name string) (*domain.Scope, error)
    GetAll(ctx) ([]domain.Scope, error)
    Store(ctx, s *domain.Scope) error
    Delete(ctx, name string) error
}

type UserStore interface { // host-owned credential directory
    ValidateCredentials(ctx, username, password string) (*domain.UserInfo, error) // nil if invalid
    FindByID(ctx, userID string) (*domain.UserInfo, error)
}

type AuditLogStore interface {
    Store(ctx, l *domain.AuditLog) error
    GetPaged(ctx, req PagedRequest) (PagedResult[domain.AuditLog], error)
}

type LoginAttemptTracker interface { // brute-force lockout extension point
    IsLockedOut(ctx, key string) (bool, error)
    RecordFailure(ctx, key string) error
    Reset(ctx, key string) error
}
```

### Atomicity requirements (security-critical)
`MarkConsumed` for both auth codes and refresh tokens **must** be a single conditional write — `UPDATE ... SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`, returning true only when one row changed. In GORM use `db.Model(&X{}).Where("id = ? AND consumed_at IS NULL", id).Update("consumed_at", t)` and check `RowsAffected == 1`. In the memory store, guard with a per-entity mutex. This is what makes auth-code single-use and refresh-token reuse detection race-safe — do not implement it as read-then-write.

---

## Endpoints & behavior (`internal/oidc`)

All token-endpoint responses (success and error) set `Cache-Control: no-store` and `Pragma: no-cache`. OAuth errors use the standard JSON shape `{"error": "...", "error_description": "..."}`.

### `GET /.well-known/openid-configuration`
Return discovery JSON: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `end_session_endpoint`, `revocation_endpoint`, `response_types_supported: ["code"]`, `grant_types_supported: ["authorization_code","refresh_token","client_credentials"]`, `subject_types_supported: ["public"]`, `id_token_signing_alg_values_supported: ["RS256"]`, `code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["none","private_key_jwt"]`, `token_endpoint_auth_signing_alg_values_supported`, `scopes_supported` (from scope store).

### `GET /.well-known/jwks.json`
Public JWK set from **all** signing keys (active + retired) so clients can validate tokens across rotations. Never include private material. Build with `jwk.Set` from the public PEMs.

### `GET /connect/authorize`
Authorization Code Flow entry. **Validate `redirect_uri` BEFORE anything else** (RFC 6749 §4.1.2.1):
1. Parse `client_id`; unknown client → HTML/JSON error (do **not** redirect).
2. Validate `redirect_uri` exact-match against `client.RedirectURIs` (scheme/host/port/path/trailing-slash — no prefix/wildcard). Invalid → HTML/JSON error (do **not** redirect to an unvalidated URI).
3. From here on, **all** errors 302-redirect back to the validated `redirect_uri` with `error`, `error_description`, `state`.
4. Validate `response_type=code`, `scope` ⊆ `client.AllowedScopes`, PKCE (`code_challenge` required when `RequirePKCE`; `code_challenge_method` must be `S256` — reject `plain`).
5. Parse optional `nonce`, `prompt`, `max_age`, `state`.
6. Resolve SSO session from the cookie. Re-auth logic:
   - `prompt=none` + no valid session → redirect with `error=login_required`.
   - `prompt=login` → ignore existing session, force login.
   - `max_age` exceeded vs session/auth time → force login.
   - No session and no `prompt=none` → 302 to `LoginPath` with a `returnUrl` (the original authorize URL).
7. With a valid session: mint a short-lived auth code (default **60s**), store its hash bound to `client_id`/`user_id`/`redirect_uri`/`code_challenge`/`scope`/`nonce`/`session_id`, 302 back to `redirect_uri` with `code` + `state`.

### `POST /connect/token`
Dispatcher: parse `application/x-www-form-urlencoded`, authenticate the client (see Client Authentication), then route by `grant_type` to a handler. Unknown grant → `unsupported_grant_type`.

- **authorization_code** (`grants/authcode.go`): look up code by hash; verify not expired; verify `client_id` + `redirect_uri` match; verify PKCE (`S256(code_verifier) == code_challenge`, constant-time); **`MarkConsumed` BEFORE issuing tokens** (CAS; if it returns false → already used → `invalid_grant`); resolve user via `UserStore.FindByID`; issue access + id (+ refresh if allowed & `offline_access` granted). ID token carries `nonce`, `at_hash`, `auth_time`.
- **refresh_token** (`grants/refresh.go`): look up by hash; if `RevokedAt`/expired → `invalid_grant`; check sliding `ExpiresAt` and `AbsoluteExpiresAt`; **`MarkConsumed` (CAS)** — if it returns false → **reuse detected**: when `DetectRefreshTokenReuse`, revoke the whole chain via `RevokeBySessionID` (or walk `ParentTokenID`), write a `RefreshTokenReuseDetected` audit log, return `invalid_grant`; otherwise mint a new refresh token with `ParentTokenID` set and `AbsoluteExpiresAt` carried forward (rotation never extends the hard ceiling). Re-check user is still active.
- **client_credentials** (`grants/clientcreds.go`): require confidential client (`TokenEndpointAuthMethod != none`) **and** `AllowClientCredentials`. Issue access token only, `sub = client_id`, no id/refresh token.

### `GET+POST /connect/userinfo`
Bearer token from `Authorization` header (GET/POST) or POST form `access_token`. Validate signature/issuer/expiry against JWKS. Return claims as JSON, **filtered by granted scope**: `profile` → name/preferred_username; `email` → email/email_verified; always `sub`. Invalid token → 401 with `WWW-Authenticate: Bearer error="invalid_token"`.

### `POST /connect/revoke` (RFC 7009)
POST form: `token`, optional `token_type_hint`. Authenticate the client. Find refresh token by hash; **only revoke if it belongs to the requesting client**. Revoke the chain. **Always return 200** regardless of whether the token existed (don't leak existence).

### `GET+POST /login`
- **GET**: render `login.html` with a CSRF token, surfacing an `?error=` code if present (`invalid_credentials`, `missing_credentials`, `account_locked`, `antiforgery_failed`), and carrying `returnUrl`.
- **POST**: validate CSRF; check `LoginAttemptTracker.IsLockedOut`; `UserStore.ValidateCredentials` (constant-time / bcrypt). On success: create a `Session`, set the encrypted session cookie, `Reset` the attempt tracker, 302 to a **validated** `returnUrl` (must be a local/relative path or a known authorize URL — reject open redirects). On failure: `RecordFailure`, 302 back to `/login?error=...&returnUrl=...`.

### `GET+POST /connect/logout` (RP-initiated)
- **GET**: if a cryptographically valid `id_token_hint` is present, proceed; otherwise 302 to `LogoutPath` (logout confirmation page), forwarding `post_logout_redirect_uri`/`state`/`client_id`.
- **POST**: validate CSRF; revoke the session; clear the cookie; revoke the session's refresh-token chain; 302 to `post_logout_redirect_uri` **only if** it matches the client's `PostLogoutRedirectURIs`, else to the configured `PostLogoutRedirectURI` fallback.

---

## Token issuance (`internal/token`)

- **hasher.go**: `HashToken(raw) string` = base64url(SHA-256(raw)); `NewOpaqueToken()` = base64url of 32 secure-random bytes (`crypto/rand`).
- **pkce.go**: `VerifyS256(verifier, challenge) bool` — compute base64url(SHA-256(verifier)), compare with `subtle.ConstantTimeCompare`. Only S256; plain is unsupported.
- **keys.go**: generate RSA-2048; export/import PEM; convert public PEM → `jwk.Key` with `kid`, `use=sig`, `alg=RS256`. Provide `EnsureActiveKey()` that bootstraps one signing key on first run if the store is empty (parity with C# auto-bootstrap).
- **issuer.go**:
  - **Access token (JWT)** claims: `sub`, `iss`, `aud` (= client_id), `exp`, `iat`, `nbf`, `jti`, `scope`, `client_id` + optional profile claims. Signed with active key (`kid` in header).
  - **ID token (JWT)** claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `auth_time`, `nonce` (if present), `at_hash`, plus scope-appropriate `name`/`email`. **`at_hash`** = base64url(leftmost half of SHA-256(access_token)) for RS256.
  - **Refresh token**: opaque (from hasher); caller persists the hash + metadata; raw returned to client once.
- **clientassertion.go** (`private_key_jwt`): verify the `client_assertion` JWT with `jws` against the client's inline JWKS; require asymmetric alg (reject `none`/HMAC); `aud` ∈ {issuer, token endpoint URL}; `iss == sub == client_id`; `exp` present and within `ClientAssertionClockSkew`; `jti` present and unseen (replay cache, default in-memory `map`+mutex with TTL; swap for distributed later).

---

## Session cookie (`internal/session`)

- Value = `securecookie`-encrypted+signed `Session.ID`. Keys (hash key + block key) from config so instances share them.
- Attributes: `HttpOnly`, `SameSite=Lax`, `Path=/`. `Secure` when `RequireHTTPS`. Cookie name: when `RequireHTTPS`, prefix with `__Host-` (and then no Domain, Path=/, Secure — satisfy the prefix rules); otherwise plain `CookieName`.
- On each request that needs SSO, decrypt → load session → check not revoked / not expired.

---

## Client authentication (`internal/oidc/clientauth.go`)
At the token endpoint: `none` (public) clients are allowed only with PKCE on the auth-code path. `private_key_jwt` clients must present a valid `client_assertion` (validated as above). Failure → **401** with `WWW-Authenticate: Basic realm="auth-server"` and an opaque `invalid_client` body; log precise reason server-side only.

---

## Admin UI & API (`internal/admin`)
- Mount under a chi route **group that requires authentication** (so every admin route is covered, not just the index). Provide a config flag `AdminAllowAnonymous` (default false) for local dev, and a configurable required role/policy.
- JSON CRUD for: clients, scopes, sessions (list + revoke), refresh tokens (list + revoke; never expose token values), signing keys (list; **strip private PEM**), audit logs (paged search).
- All mutating endpoints (POST/PUT/DELETE) require a CSRF token (gorilla/csrf), surfaced to the SPA via a meta tag / cookie and sent back in a header.
- The SPA is a small vanilla-JS/Alpine page served from `web/`. Keep it minimal; the JSON API is the real contract.

---

## Configuration (`internal/config`)
Load from env, validate at startup (fail fast). Suggested keys:

```text
AUTH_ISSUER                       (required, absolute URL)
AUTH_LISTEN_ADDR                  (default :5175)
AUTH_REQUIRE_HTTPS                (default true)
AUTH_DB_DRIVER                    (postgres|sqlite, default sqlite)
AUTH_DB_DSN                       (connection string / file path)
AUTH_COOKIE_NAME                  (default .auth.session)
AUTH_COOKIE_HASH_KEY              (base64, securecookie HMAC key)
AUTH_COOKIE_BLOCK_KEY             (base64, securecookie AES key)
AUTH_LOGIN_PATH                   (default /login)
AUTH_LOGOUT_PATH                  (default /logout)
AUTH_POST_LOGOUT_REDIRECT_URI     (default /)
AUTH_AUTH_CODE_LIFETIME           (default 60s)
AUTH_ACCESS_TOKEN_LIFETIME        (default 1h)
AUTH_ID_TOKEN_LIFETIME            (default 1h)
AUTH_REFRESH_TOKEN_LIFETIME       (default 720h)   # 30d sliding
AUTH_REFRESH_TOKEN_ABS_LIFETIME   (default 720h)   # 30d absolute
AUTH_DETECT_REFRESH_REUSE         (default true)
AUTH_CLIENT_ASSERTION_CLOCK_SKEW  (default 60s)
AUTH_REQUIRE_PKCE                 (default true)
AUTH_LOGIN_RATE_LIMIT             (default 10/min per IP)
AUTH_ADMIN_ALLOW_ANONYMOUS        (default false)
```

Validation: issuer must be absolute (and HTTPS when `AUTH_REQUIRE_HTTPS`); cookie keys must be present and correct length; abs lifetime ≥ sliding lifetime; auth-code lifetime ≤ 2m.

---

## Security checklist (must hold at the end)
- PKCE required by default; **S256 only**, constant-time verify; `plain` rejected and not advertised.
- `redirect_uri` exact match; errors before validation never redirect; errors after validation redirect with `error`/`state`.
- Auth codes: single-use via atomic CAS, ≤2m lifetime, hash-only storage, bound to client/redirect/PKCE/user/session/nonce.
- Refresh tokens: opaque, hash-only, rotated on use, `ParentTokenID` chain, sliding + absolute expiry, reuse detection revokes the chain, issuance requires `AllowRefreshTokens` + granted `offline_access`.
- ID token: `at_hash` + `nonce` + `auth_time`.
- Token endpoint: `no-store`; `invalid_client` → 401 + `WWW-Authenticate`.
- Login: CSRF + lockout + rate limit; returnUrl open-redirect prevention.
- Logout: state-changing only via POST + CSRF; `id_token_hint` cryptographically validated.
- Session cookie: encrypted+signed, `__Host-` prefix under HTTPS, HttpOnly/Secure/SameSite=Lax.
- `private_key_jwt`: asymmetric only, `aud`/`iss`/`sub`/`exp` checks, `jti` replay cache.
- Signing private keys never exposed; JWKS exposes public keys for active + retired.
- Never log secrets, raw tokens, codes, passwords, or PII.

---

## Verification (how to prove it works)

- **Unit:** `go test ./internal/token/...` for PKCE/at_hash/hashing/key round-trip.
- **Integration (`test/`):** spin the real router with `httptest.NewServer`, in-memory or SQLite stores, and exercise the full flow:
  1. `GET /connect/authorize` (no session) → 302 to `/login`.
  2. `POST /login` (valid creds + CSRF) → cookie set, 302 back to authorize → 302 to `redirect_uri` with `code`.
  3. `POST /connect/token` (code + verifier) → access + id + refresh tokens; assert `id_token` has `nonce`/`at_hash`/`auth_time` and verifies against `/.well-known/jwks.json`.
  4. `POST /connect/token` with the **same code again** → `invalid_grant` (single-use).
  5. Refresh once → new tokens; refresh with the **old** refresh token → `invalid_grant` + chain revoked (reuse detection).
  6. `GET /connect/userinfo` with the access token → scope-filtered claims.
  7. `POST /connect/revoke` → 200; the revoked refresh token no longer works.
  8. Wrong PKCE verifier, mismatched `redirect_uri`, expired code → all rejected.
- **Real client smoke test:** point `coreos/go-oidc` + `golang.org/x/oauth2` at the running server with a seeded public client and confirm login + token + userinfo work against an off-the-shelf OIDC client (this is the parity goal).
- **Confidential:** generate an RSA keypair, register a `private_key_jwt` client with its public JWKS, perform a client_credentials exchange; assert forged-key and replayed-`jti` assertions are rejected.

---

## Notes for the implementing model
- Build the protocol with in-memory stores and prove it (M3) **before** introducing GORM — do not start with database schema design.
- The atomic `MarkConsumed` CAS is the single most important security primitive; get it right in both store implementations and call it **before** issuing tokens.
- Validate `redirect_uri` first in `/connect/authorize`; never 302 to an unvalidated URI.
- Inject a `Clock`; never call `time.Now()` directly in protocol code.
- Keep everything `internal/` — this is an application, not a library. Keep files focused and named after their primary type/function.
- English only in all repo content.
- Work one task at a time from `TASKS.md`; keep `go build ./...` and `go vet ./...` clean after each.
