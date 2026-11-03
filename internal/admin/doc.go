// Package admin owns the auth-server's administrative JSON API. It is
// mounted under /admin/api and gated by an auth middleware (an
// admin-role SSO session, or a static Bearer token for scripts) plus a
// double-submit CSRF check for cookie-authenticated, state-changing
// requests. The admin console itself is the separate SPA in web/; this
// package serves no HTML.
package admin
