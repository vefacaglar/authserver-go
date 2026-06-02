# CLAUDE.md

Project rules for Claude Code working on **go-authserver** (a standalone Go OAuth2 / OpenID
Connect authorization server).

**Read [`AGENTS.md`](AGENTS.md) first — it is the canonical rule set.** This file only adds
Claude-specific pointers; everything in `AGENTS.md` applies.

## Quick orientation

- This is a **deployable auth server**, not a library/package. A Go port of a hardened C# OIDC server; parity is the goal.
- Source-of-truth docs:
  - **`BUILD_PROMPT.md`** — full technical spec. Read the relevant section before each task.
  - **`TASKS.md`** — ordered, checkbox build plan (T1.1 → T8.3). Do **one task per session**, in order.

## Non-negotiables (see AGENTS.md for the full list)

- English only in all repo content (code, comments, logs, errors, docs, commits).
- In-memory stores first; prove the flow end-to-end through M3 **before** GORM.
- After each task: `go build ./...` and `go vet ./...` clean, `go test ./...` where tests are added; satisfy the task's **Done when** before moving on.
- PKCE S256-only, exact `redirect_uri` match, atomic `MarkConsumed` CAS called before token issuance, hash-only code/refresh storage, refresh rotation + reuse detection. Never log secrets/tokens/codes/PII.
- Inject a `Clock`; never call `time.Now()` directly in protocol code.
- **Never commit.** LLM agents must not run `git commit`/push/amend/rebase under any circumstances, even when explicitly asked. Leave changes in the working tree for the human author.
