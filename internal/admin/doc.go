// Package admin owns the auth-server's administrative API and the
// single-page admin console. The package is mounted under /admin and
// gated by an auth middleware plus gorilla/csrf for state-changing
// requests. The JSON contract is the real surface; the SPA is a thin
// vanilla-JS shell that consumes it.
package admin
