# AGENTS.md

Operating rules for any AI agent working on **go-authserver** — a standalone OAuth2 / OpenID
Connect authorization server written in Go. Read this fully before touching code.

## What this project is

- A **deployable auth server** (single binary + config), **not** a reusable library/package.
- A Go port of an existing, production-hardened C# OIDC server. Functional + security parity is the goal.
- Two companion docs are the source of truth:
  - **`BUILD_PROMPT.md`** — the full technical spec (architecture, models, endpoints, security). Read the relevant section before each task.
  - **`TASKS.md`** — the ordered, checkbox build plan (T1.1 → T8.3). One task per session.

## How to work

- Do **one task at a time** from `TASKS.md`, in order. Don't jump ahead.
- Before a task: re-read the matching section of `BUILD_PROMPT.md`.
- After every task: run `go build ./...` and `go vet ./...`; both must be clean. Run `go test ./...` for any task that adds tests, and don't move on until **Done when** holds.
- Tick the checkbox in `TASKS.md` when a task is complete.
- Build the protocol with **in-memory stores first** and prove the flow end-to-end (through M3) **before** introducing GORM. Do not start with database schema design.

## Language rules (strict)

Everything shipped in the repo is **English only**:
- Code identifiers, comments, doc comments.
- Log messages and structured log fields.
- Error strings and user-facing protocol error responses (OAuth `error`/`error_description`).
- Commit messages and PR descriptions.
- All `.md` files and any config/sample values (except where a test explicitly verifies non-ASCII handling).

Turkish is allowed only in chat replies to the author, never in repo content.

## Code style (Go)

- Target **Go 1.23+**. Run `gofmt`/`goimports`; code must be `gofmt`-clean.
- Keep `go vet ./...` clean. Prefer `golangci-lint` if configured.
- Use `log/slog` for logging. No `fmt.Println` for diagnostics in non-`main` code.
- Errors: wrap with `fmt.Errorf("...: %w", err)`; never discard an error silently. Sentinel errors via `errors.New` + `errors.Is`.
- Use `context.Context` as the first parameter on all store and I/O methods.
- Inject a `Clock` interface (`Now() time.Time`); **never call `time.Now()` directly** in protocol code (tests use a fake clock).
- Use `crypto/rand` for all token/secret generation, `crypto/subtle.ConstantTimeCompare` for secret comparisons.
- One primary type/concern per file; file name matches its main type/function. Package layout follows folders.
- Keep everything under `internal/` — this is an application, not a library. Only `cmd/authserver` is `main`.
- Prefer the standard library and the locked dependencies (see `BUILD_PROMPT.md`); do not add new dependencies without a clear need.

## Architecture rules

- `internal/domain` — plain model structs only. No HTTP, no GORM, no JOSE imports.
- `internal/store` — interfaces (ports) only. Implementations live in `store/memory` and `store/gormstore`.
- `internal/token` — hashing, PKCE, RSA keys, JWT issuance, client-assertion validation. Depends on `domain` + `store` + `jwx`.
- `internal/oidc` — HTTP handlers (minimal `net/http` + chi). Depends on `token`, `session`, `store`, `domain`.
- `internal/session` — encrypted SSO cookie only.
- `internal/admin` — admin JSON API + SPA, mounted behind an auth-required chi group.
- `internal/server` — router wiring + middleware. `cmd/authserver` — composition root.
- Handlers are **minimal API style** (chi `http.HandlerFunc`), not a heavy framework.
- The user directory is host-owned behind `store.UserStore`; never hardcode a user table.

## Security rules (non-negotiable)

- PKCE required by default; **S256 only**, constant-time verify. `plain` is rejected and not advertised.
- `redirect_uri` exact match — no prefix, no wildcard. In `/connect/authorize`, validate `redirect_uri` **before** anything else and never 302 to an unvalidated URI.
- Authorization codes: single-use via **atomic CAS** (`MarkConsumed` returns true only for the winner), ≤2 min lifetime, **hash-only** storage, bound to client/redirect/PKCE/user/session/nonce. Call `MarkConsumed` **before** issuing tokens.
- Refresh tokens: opaque, hash-only, rotated on use, `ParentTokenID` chain, sliding + absolute expiry, reuse detection revokes the chain. Issuance requires `AllowRefreshTokens` + granted `offline_access`.
- ID token carries `at_hash`, `nonce` (when supplied), `auth_time`.
- Token endpoint sets `Cache-Control: no-store`; `invalid_client` → 401 + `WWW-Authenticate`.
- Session cookie is encrypted + signed, `__Host-` prefixed under HTTPS, `HttpOnly`/`Secure`/`SameSite=Lax`.
- `private_key_jwt`: asymmetric algorithms only (reject `none`/HMAC), validate `aud`/`iss`/`sub`/`exp`, enforce `jti` replay protection.
- Signing private keys never leave the server; only public JWK is exposed via JWKS (active + retired keys).
- **Never log** secrets, raw tokens, authorization codes, passwords, or PII.

The `MarkConsumed` atomic CAS is the single most important security primitive — implement it as one conditional write in both the memory and GORM stores, never read-then-write.

## Workflow rules

- After meaningful changes, run `go build ./...`, `go vet ./...`, and (where relevant) `go test ./...` before reporting done.
- **LLM agents must never commit.** Do not run `git commit` (or push, force-push, amend, rebase, or any history-changing git command) under any circumstances — not even when explicitly asked. Leave all changes staged or unstaged in the working tree for the human author to commit. If a request implies committing, do everything up to the commit and stop.
- End commit messages with the project's standard trailer if one is configured; keep them in English.
- Don't edit generated files or vendored code by hand; fix the source.
