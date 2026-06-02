# Security Checklist

The server is hardened against the formal threat model in
`BUILD_PROMPT.md §Security checklist`. Every line below is backed by
either a passing test or a specific code reference. The T8.2 task
in `TASKS.md` requires this mapping; it is the canonical source of
truth for "is this property still enforced?".

## PKCE

- **PKCE required by default; S256 only, constant-time verify; `plain`
  rejected and not advertised.**
  - Implementation: `internal/oidc/authorize.go` (`PKCEMethod` check;
    rejects anything other than `S256`).
  - PKCE constant-time verify: `internal/token/pkce.go` (`VerifyS256`).
  - Tests:
    - `internal/oidc/grants/authcode_test.go` —
      `TestAuthCode_Handle_RejectsBadPKCE`
    - `internal/oidc/grants/authcode_test.go` —
      `TestAuthCode_Handle_IssuesAccessAndIDToken` (asserts code
      challenge is honoured)
    - `test/integration_test.go` — `TestE2E_BadPKCEVerifier`
    - Discovery excludes `plain` from
      `code_challenge_methods_supported` —
      `internal/oidc/discovery.go`.

## redirect_uri

- **Exact match; errors before validation never redirect; errors after
  validation redirect with `error`/`state`.**
  - Implementation: `internal/oidc/authorize.go` — `redirect_uri`
    validated as the *first* action after the client lookup; pre-
    validation errors return JSON without `Location`.
  - Tests:
    - `test/integration_test.go` —
      `TestE2E_InvalidRedirectURIOnAuthorize_NotRedirected`
    - `test/integration_test.go` — `TestE2E_MismatchedRedirectURI`

## Authorization codes

- **Single-use via atomic CAS.**
  - Implementation: `internal/oidc/grants/authcode.go` —
    `MarkConsumed` is called *before* any token is issued.
  - CAS implementations:
    - `internal/store/memory/authcode.go` (per-entity mutex)
    - `internal/store/gormstore/authcode.go` (conditional `Update`)
  - Tests:
    - `internal/store/memory/cas_test.go` — 50 goroutines, exactly
      one `true`.
    - `internal/store/gormstore/gormstore_test.go` — 16 goroutines,
      exactly one `true`.
    - `internal/oidc/grants/authcode_test.go` —
      `TestAuthCode_Handle_RejectsReplay`
    - `test/integration_test.go` — replay step inside
      `TestE2E_HappyPath`.

- **≤2 minute lifetime, hash-only storage.**
  - Config validation: `internal/config/config.go` — `AuthCodeLifetime
    > 2*time.Minute` returns an error.
  - Hash-only: `internal/oidc/authorize.go` — `token.NewOpaqueToken`
    + `token.HashToken`; the raw code is never stored.
  - Tests:
    - `internal/config/config_test.go` —
      `TestLoad_RejectsAuthCodeLifetimeOver2m`
    - `test/integration_test.go` — `TestE2E_ExpiredCode_Rejected`

- **Bound to client/redirect/PKCE/user/session/nonce.**
  - Implementation: `internal/oidc/authorize.go` `mintCode` records
    every field; the authcode grant re-checks all of them at the
    token endpoint.

## Refresh tokens

- **Opaque, hash-only, rotated on use, `ParentTokenID` chain, sliding +
  absolute expiry, reuse detection revokes the chain, issuance
  requires `AllowRefreshTokens` + granted `offline_access`.**
  - Implementation: `internal/oidc/grants/refresh.go` and
    `internal/oidc/grants/authcode.go` (issuance).
  - Hash-only: `internal/oidc/grants/refresh.go` + `authcode.go` —
    `token.NewOpaqueToken` + `token.HashToken`.
  - `ParentTokenID` chain: `internal/oidc/grants/refresh.go` sets it
    on every rotation.
  - Reuse detection: `internal/oidc/grants/refresh.go`
    `handleReuse` calls `RevokeBySessionID` and writes the
    `RefreshTokenReuseDetected` audit log.
  - Tests:
    - `internal/oidc/grants/refresh_test.go` —
      `TestRefresh_Handle_DetectsReuseAndRevokesChain`,
      `TestRefresh_Handle_RotatesAndMintsNewTokens`,
      `TestRefresh_Handle_OnlyOneWinnerOnConcurrentUse`
    - `test/integration_test.go` —
      `TestE2E_RefreshGrant_ReuseRevokesChain`,
      `TestE2E_RefreshGrant_Rotates`

## ID token

- **`at_hash` + `nonce` + `auth_time`.**
  - Implementation: `internal/token/issuer.go` `IssueIDToken` writes
    all three claims; `HashAccessToken` produces `at_hash`.
  - Tests:
    - `test/integration_test.go` — `TestE2E_HappyPath` asserts
      `nonce` + `at_hash` + `auth_time`.

## Token endpoint

- **`no-store`; `invalid_client` → 401 + `WWW-Authenticate`.**
  - Implementation: `internal/oidc/errors.go` — `SetNoStore` +
    `WriteInvalidClient` (sets `WWW-Authenticate: Basic`).
  - Tests:
    - `test/integration_test.go` — `TestE2E_HappyPath` asserts
      `Cache-Control: no-store` on token responses.
    - `internal/oidc/grants/refresh_test.go` —
      `TestRefresh_Handle_RejectsForeignClient`
    - `test/integration_test.go` — `TestE2E_ClientCredentials_ForgedKeyRejected`
      asserts `WWW-Authenticate: Basic`.

## Login

- **CSRF + lockout + rate limit.**
  - CSRF: `internal/oidc/login.go` — double-submit token + constant-
    time compare; no GET ever mutates state.
  - Lockout: `internal/store/memory/loginattempt.go` —
    `LoginAttemptTracker` (5 failures → 15 minute lockout).
  - Rate limit: `internal/server/ratelimit.go` — per-IP token
    bucket; over-limit → 429 with `Retry-After`.
  - Tests:
    - `test/integration_test.go` — `TestE2E_Login_LockoutAfterRepeatedFailures`
    - `test/integration_test.go` — `TestE2E_LoginRateLimit_Over429`

- **returnUrl open-redirect prevention.**
  - Implementation: `internal/oidc/login.go` `validateReturnURL`
    (only same-origin or paths under `/connect/...` or `/logout`).
  - Test: covered implicitly by every happy-path test (the
    `Location` after a successful login is always the original
    authorize URL).

## Logout

- **State-changing only via POST + CSRF; `id_token_hint`
  cryptographically validated.**
  - Implementation: `internal/oidc/logout.go` — `handlePost` is
    CSRF-protected; `handleEntry` validates the `id_token_hint`
    via `Issuer.VerifyToken` before honouring it.
  - Tests:
    - `test/integration_test.go` — `TestE2E_Logout_PostRejectsBadCSRF`
    - `test/integration_test.go` — `TestE2E_Logout_PostRevokesAndClears`
    - `test/integration_test.go` — `TestE2E_Logout_PostCancelDoesNotRevoke`

## Session cookie

- **Encrypted + signed, `__Host-` prefix under HTTPS, HttpOnly /
  Secure / SameSite=Lax.**
  - Implementation: `internal/session/cookie.go` — `SetCookie`
    applies all four attributes; `EffectiveCookieName` adds the
    `__Host-` prefix when `RequireHTTPS` is true.
  - Test: `internal/config/config_test.go` —
    `TestEffectiveCookieName` asserts the prefix.

## private_key_jwt

- **Asymmetric only, `aud`/`iss`/`sub`/`exp` checks, jti replay cache.**
  - Implementation: `internal/token/clientassertion.go` —
    `VerifyClientAssertion` + `MemAssertionCache`. The JWS
    envelope is parsed first so the `alg` header is checked
    BEFORE the signature verification, giving a clean error
    message for `alg=none` / HMAC.
  - Tests:
    - `internal/token/clientassertion_test.go` —
      `TestVerifyClientAssertion_Valid`,
      `TestVerifyClientAssertion_ForgedKey`,
      `TestVerifyClientAssertion_ReplayedJTI`,
      `TestVerifyClientAssertion_HMACRejected`,
      `TestVerifyClientAssertion_WrongIssuer`,
      `TestVerifyClientAssertion_WrongAudience`,
      `TestVerifyClientAssertion_Expired`
    - `test/integration_test.go` —
      `TestE2E_ClientCredentials_*` and the GORM mirrors.

## Signing keys

- **Private material never exposed; JWKS exposes public keys for
  active + retired.**
  - Implementation: `internal/token/issuer.go` `JWKSForEndpoint`
    walks every signing key and projects only the public side via
    `jwkKeyToMap` (which deletes the `d` field if present).
  - Admin API: `internal/admin/api.go` `toKeyView` returns only
    `Kid` + `Alg` + `PublicPEM`; `PrivateKeyPEM` is never
    serialised.
  - Tests:
    - `test/integration_test.go` — `TestE2E_Admin_Keys_StripPrivatePEM`
    - `internal/admin/admin_test.go` — `TestAPI_Keys_StripPrivatePEM`

## Logging discipline

- **Never log secrets, raw tokens, codes, passwords, or PII.**
  - Every `slog` call site in the project is reviewed to log
    *metadata* (client_id, error message) and never the secret
    itself. See e.g. `internal/oidc/clientauth.go` (logs
    `client_id` and the verifier's error message, never the JWT
    or the assertion contents).
  - Spot checks: `internal/oidc/logout.go`,
    `internal/oidc/login.go`, `internal/oidc/grants/refresh.go`.

## Hardening additions (M8)

- **Security headers on every response.** Implementation:
  `internal/server/router.go` `securityHeadersMiddleware`. Sets
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy:
  same-origin`, `Cross-Origin-Resource-Policy: same-origin`,
  `Permissions-Policy: …`, and (over HTTPS only)
  `Strict-Transport-Security`.
  Tests: `test/integration_test.go` —
  `TestE2E_SecurityHeaders_PresentOnDiscovery`,
  `TestE2E_StrictTransportSecurity_HTTPSOnly`.
