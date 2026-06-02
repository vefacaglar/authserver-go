// Package admin owns the auth-server's administrative API and the
// single-page admin console. The package is mounted under /admin and
// gated by an auth middleware plus gorilla/csrf for state-changing
// requests. The JSON contract is the real surface; the SPA is a thin
// vanilla-JS shell that consumes it.
package admin

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// AuthConfig captures the policy inputs for the admin auth middleware.
type AuthConfig struct {
	// Token is the static bearer shared with admin operators. The
	// client sends it as `Authorization: Bearer <token>` (preferred)
	// or `X-Admin-Token: <token>` (legacy convenience).
	Token string
	// AllowAnonymous bypasses the check. Intended for local dev
	// only; production must set Token and leave AllowAnonymous
	// false.
	AllowAnonymous bool
}

// AuthMiddleware returns the HTTP middleware that gates the /admin
// route group. On any failure it writes a 401 with a Bearer
// challenge so curl/scripts fail loudly.
func AuthMiddleware(cfg AuthConfig, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	if !cfg.AllowAnonymous {
		if strings.TrimSpace(cfg.Token) == "" {
			return nil, errors.New("admin: AUTH_ADMIN_TOKEN must be set unless AUTH_ADMIN_ALLOW_ANONYMOUS=true")
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.AllowAnonymous {
				w.Header().Set("X-Admin-Auth", "anonymous")
				next.ServeHTTP(w, r)
				return
			}
			provided := extractAdminToken(r)
			if subtle.ConstantTimeCompare([]byte(provided), []byte(cfg.Token)) != 1 {
				if logger != nil {
					logger.Warn("admin auth failed", "remote", r.RemoteAddr, "path", r.URL.Path)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server-admin"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// extractAdminToken reads the token from the request. Authorization:
// Bearer is preferred; X-Admin-Token is the legacy convenience header.
func extractAdminToken(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(a[len("Bearer "):])
	}
	return r.Header.Get("X-Admin-Token")
}
