# TASKS — Go OAuth2 / OIDC Auth Server

Build order. **Do one task per session.** After each: `go build ./...` and `go vet ./...`
must be clean; run `go test ./...` where the task adds tests. Don't start the next task
until **Done when** holds. Full spec lives in `BUILD_PROMPT.md`; this file is the checklist.

## M1 — Module + domain + memory stores
- [x] **T1.1 Init module** — `go.mod` (`module go-authserver`, go 1.26), `cmd/authserver/main.go` trivial main, `.gitignore`. **Done when** build succeeds and the binary runs.
- [x] **T1.2 Clock** — `internal/clock`: `Clock` interface (`Now()`), `SystemClock`, `FakeClock`. **Done when** a test advances the fake clock.
- [x] **T1.3 Domain models** — `internal/domain`: Client, AuthorizationCode, RefreshToken, Session, SigningKey, Scope, AuditLog, UserInfo, PagedRequest, PagedResult[T], auth-method enum (`google/uuid`). **Done when** it builds.
- [x] **T1.4 Store interfaces** — `internal/store/store.go`: all interfaces incl. `LoginAttemptTracker`. **Done when** it builds.
- [x] **T1.5 Memory stores** — `internal/store/memory`: map+RWMutex impls for every store. **Done when** a test stores/retrieves a client and a scope.
- [x] **T1.6 Atomic MarkConsumed** — per-entity mutex so only the first caller gets `true` (auth code + refresh token). **Done when** 50 goroutines on one id → exactly one `true`.

## M2 — Token core
- [x] **T2.1 Hasher** — `internal/token/hasher.go`: `HashToken` (base64url SHA-256), `NewOpaqueToken` (32 random bytes). **Done when** test asserts hash determinism + token uniqueness.
- [x] **T2.2 PKCE** — `internal/token/pkce.go`: `VerifyS256` constant-time. **Done when** passes known pair, rejects wrong verifier.
- [x] **T2.3 Keys** — `internal/token/keys.go`: RSA-2048 keygen, PEM import/export, public PEM → `jwk.Key`, `EnsureActiveKey(store)`. **Done when** test round-trips PEM and produces a JWK with `kid`.
- [x] **T2.4 Issuer** — `internal/token/issuer.go`: access + id JWT with full claim sets incl. `at_hash`, `nonce`, `auth_time`. **Done when** test verifies both against JWKS and `at_hash` matches.

## M3 — Core OIDC flow, in-memory (prove Auth Code + PKCE)
- [x] **T3.1 Config** — `internal/config`: struct + env load + fail-fast validation. **Done when** invalid config errors clearly; valid loads.
- [x] **T3.2 Errors + responses** — `internal/oidc/errors.go`: OAuth error JSON, `no-store` helper, redirect-error helper. **Done when** unit test on JSON shape.
- [x] **T3.3 Session cookie** — `internal/session/cookie.go`: securecookie encrypt/decrypt, `__Host-` prefix under HTTPS. **Done when** test round-trips and rejects a tampered cookie.
- [x] **T3.4 Discovery + JWKS** — `internal/oidc/discovery.go`, `jwks.go`. **Done when** httptest asserts discovery fields + active public key in JWKS.
- [x] **T3.5 Login GET/POST** — `internal/oidc/login.go`: CSRF, returnUrl open-redirect guard, lockout + rate-limit hooks, session on success. **Done when** GET renders CSRF form; valid POST sets cookie + 302s safely; no-CSRF rejected.
- [x] **T3.6 Authorize** — `internal/oidc/authorize.go`: redirect_uri-first validation, response_type/scope/PKCE, session + prompt/max_age, code minting. **Done when** no session → /login; bad redirect_uri → error w/o redirect; valid → code+state.
- [x] **T3.7 Token + authcode grant** — `internal/oidc/token.go` + `grants/authcode.go`, `MarkConsumed` **before** issuing. **Done when** httptest exchanges code → access+id(+refresh).
- [x] **T3.8 Router + first E2E** — `internal/server/{router,middleware}.go`, wire `cmd/authserver` with memory stores + seed; `test/integration_test.go` happy path (authorize→login→authorize→code→token→verify id_token vs JWKS). **Done when** E2E passes.

## M4 — Refresh + remaining endpoints
- [x] **T4.1 Refresh grant** — `grants/refresh.go`: rotation, sliding+absolute expiry, atomic consume, reuse → chain revoke + audit. **Done when** rotate works; reuse → `invalid_grant` + chain revoked.
- [x] **T4.2 UserInfo** — `internal/oidc/userinfo.go` GET+POST, bearer validation, scope-filtered claims. **Done when** returns scope-appropriate claims, 401s invalid token.
- [x] **T4.3 Revoke** — `internal/oidc/revoke.go` (RFC 7009): client-bound, chain revoke, always 200. **Done when** foreign client can't revoke; always 200.
- [x] **T4.4 Logout** — `internal/oidc/logout.go` GET+POST: id_token_hint validation, confirm-page redirect, CSRF on POST, post_logout_redirect_uri validation. **Done when** POST revokes session + clears cookie + redirects to registered URI.
- [x] **T4.5 Negative-path tests** — code reuse, expired code, wrong PKCE verifier, mismatched redirect_uri. **Done when** all four rejected.

## M5 — GORM persistence
- [x] **T5.1 Entities + AutoMigrate** — `internal/store/gormstore`: GORM entities (Properties/[]string → JSON or child tables), `Migrate`, DB open from config (postgres|sqlite). **Done when** AutoMigrate builds schema on SQLite.
- [x] **T5.2 GORM stores (non-atomic)** — all methods except CAS. **Done when** store/load a client and page refresh tokens on SQLite.
- [x] **T5.3 GORM atomic CAS** — `MarkConsumed` via conditional `Update ... WHERE consumed_at IS NULL`, check `RowsAffected`. **Done when** concurrent test → exactly one `true`.
- [x] **T5.4 Swap server to GORM** — driver from config, memory kept for unit tests; re-run M3+M4 suite on SQLite. **Done when** full suite passes with GORM.

## M6 — Confidential clients
- [x] **T6.1 client_credentials grant** — `grants/clientcreds.go`: confidential-only, `AllowClientCredentials`, access token only (`sub=client_id`). **Done when** test asserts no id/refresh token.
- [x] **T6.2 private_key_jwt** — `internal/token/clientassertion.go` + `internal/oidc/clientauth.go`: verify vs client JWKS, asymmetric-only, aud/iss/sub/exp, jti replay cache; discovery advertises methods. **Done when** valid authenticates; forged-key + replayed-jti rejected (401 invalid_client).

## M7 — Admin UI / API
- [x] **T7.1 Admin auth group** — chi group + auth middleware + `AdminAllowAnonymous`. **Done when** anonymous rejected unless flag set.
- [x] **T7.2 Admin JSON CRUD** — clients/scopes/sessions(+revoke)/refresh-tokens(+revoke)/keys(private stripped)/audit, CSRF on mutations. **Done when** client create/list/delete tested + key responses omit private PEM.
- [x] **T7.3 Admin SPA** — minimal `web/` page consuming the API. **Done when** index renders and lists clients via the API.

## M8 — Hardening
- [x] **T8.1 Rate limit + lockout + headers** — per-IP limiter on /login, wire `LoginAttemptTracker`, security-headers middleware. **Done when** over-limit → 429; repeated failures lock out.
- [x] **T8.2 Security checklist sweep** — map every checklist item to a passing test or code reference. **Done when** each line is covered. See `SECURITY.md`.
- [x] **T8.3 Seed + one-command run** — demo public client, confidential client, scopes, sample user; document `go run ./cmd/authserver`. **Done when** a real OIDC client (`coreos/go-oidc`) completes login+token+userinfo. See `test/smoke_test.go` (build tag `m8smoke`).
