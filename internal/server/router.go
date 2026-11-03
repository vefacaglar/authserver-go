// Package server wires the HTTP router, middleware chain, and the concrete
// handlers defined in internal/oidc. The package is the composition target
// for cmd/authserver: it builds a fully-wired http.Handler from a Config
// and a set of store implementations.
//
// The server is API-only: it serves the OIDC protocol endpoints, the
// JSON APIs under /api that the browser SPA consumes, and the admin API
// under /admin/api. All HTML pages live in the SPA (web/), which is
// served separately on the same origin.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// RouterConfig captures the route paths the router mounts. It is the
// smallest surface the cmd binary needs to provide; all the lower-level
// dependencies (stores, issuer) are plumbed through the handler structs.
type RouterConfig struct {
	RequireHTTPS  bool
	AuthorizePath string
	TokenPath     string
	UserInfoPath  string
	RevokePath    string
	JWKSPath      string
	DiscoveryPath string
	HealthPath    string

	// LoginRateLimitRPS is the per-IP rate applied to the credential
	// endpoints. 0 disables the limiter.
	LoginRateLimitRPS int
	// LoginRateBurst is the per-IP burst for the login limiter.
	LoginRateBurst int
}

// Handlers is the bundle of ready-to-mount handlers. A nil entry means
// the route is not exposed (e.g. during a partial integration test).
type Handlers struct {
	// Browser SPA APIs. The caller wraps the session-required ones
	// (Home, Profile) in the session guard.
	CSRF           http.Handler
	Session        http.Handler
	Login          http.Handler
	Register       http.Handler
	ForgotPassword http.Handler
	ResetPassword  http.Handler
	Home           http.Handler
	Profile        http.Handler

	// OIDC protocol endpoints.
	Logout    http.Handler
	Authorize http.Handler
	Token     http.Handler
	UserInfo  http.Handler
	Revoke    http.Handler
	Discovery http.Handler
	JWKS      http.Handler
	Health    http.Handler

	// Admin is the admin API handler (auth + CSRF already applied by
	// the caller), mounted under /admin/api/.
	Admin http.Handler
}

// NewRouter assembles the production route table and middleware chain.
func NewRouter(cfg RouterConfig, opts RouterOptions, h Handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(requestIDMiddleware)
	r.Use(recovererMiddleware(opts.Logger))
	r.Use(securityHeadersMiddleware(cfg.RequireHTTPS))

	limiter := func(next http.Handler) http.Handler {
		return NewLoginRateLimiter(cfg.LoginRateLimitRPS, cfg.LoginRateBurst).Middleware(next)
	}

	// Browser SPA APIs. Credential endpoints are rate limited per IP
	// before any other work, so a flood of attempts cannot even reach
	// the user store.
	if h.CSRF != nil {
		r.Method(http.MethodGet, "/api/csrf", h.CSRF)
	}
	if h.Session != nil {
		r.Method(http.MethodGet, "/api/auth/session", h.Session)
	}
	if h.Login != nil {
		r.Method(http.MethodPost, "/api/auth/login", limiter(h.Login))
	}
	if h.Register != nil {
		r.Method(http.MethodPost, "/api/auth/register", limiter(h.Register))
	}
	if h.ForgotPassword != nil {
		r.Method(http.MethodPost, "/api/auth/forgot-password", limiter(h.ForgotPassword))
	}
	if h.ResetPassword != nil {
		r.Handle("/api/auth/reset-password", limiter(h.ResetPassword))
	}
	if h.Home != nil {
		r.Method(http.MethodGet, "/api/account/home", h.Home)
	}
	if h.Profile != nil {
		r.Handle("/api/account/profile", h.Profile)
		r.Handle("/api/account/profile/sessions/revoke", h.Profile)
		r.Handle("/api/account/profile/sessions/revoke-others", h.Profile)
		// Password changes are throttled per IP like the login form: the
		// current-password check is a credential oracle.
		r.Handle("/api/account/profile/password", limiter(h.Profile))
	}

	if h.Logout != nil {
		r.Handle("/connect/logout", h.Logout)
	}
	if h.Authorize != nil && cfg.AuthorizePath != "" {
		r.Method(http.MethodGet, cfg.AuthorizePath, h.Authorize)
	}
	if h.Token != nil && cfg.TokenPath != "" {
		r.Method(http.MethodPost, cfg.TokenPath, h.Token)
	}
	if h.UserInfo != nil && cfg.UserInfoPath != "" {
		r.Method(http.MethodGet, cfg.UserInfoPath, h.UserInfo)
		r.Method(http.MethodPost, cfg.UserInfoPath, h.UserInfo)
	}
	if h.Revoke != nil && cfg.RevokePath != "" {
		r.Method(http.MethodPost, cfg.RevokePath, h.Revoke)
	}
	if h.Discovery != nil && cfg.DiscoveryPath != "" {
		r.Method(http.MethodGet, cfg.DiscoveryPath, h.Discovery)
	}
	if h.JWKS != nil && cfg.JWKSPath != "" {
		r.Method(http.MethodGet, cfg.JWKSPath, h.JWKS)
	}
	if h.Health != nil && cfg.HealthPath != "" {
		r.Method(http.MethodGet, cfg.HealthPath, h.Health)
	}

	// Admin API: the inner mux uses stdlib patterns like
	// "GET /api/clients", so strip the /admin prefix and let it see
	// /api/... paths.
	if h.Admin != nil {
		r.Mount("/admin/api/", http.StripPrefix("/admin", h.Admin))
	}

	return r
}

// RouterOptions controls the middleware behaviour.
type RouterOptions struct {
	Logger *slog.Logger
}

// requestIDMiddleware stamps an X-Request-Id header on every response so
// operators can correlate a single request across logs.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r)
	})
}

// recovererMiddleware turns panics into 500s with a structured log entry
// rather than the default net/http behaviour (which closes the connection).
func recovererMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil {
					logger.Error("panic in handler",
						"err", rv,
						"path", r.URL.Path,
						"method", r.Method,
						"stack", string(debug.Stack()),
					)
					if w.Header().Get("Content-Type") == "" {
						http.Error(w, "internal server error", http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware sets a baseline of defensive HTTP headers on
// every response.
func securityHeadersMiddleware(requireHTTPS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			if requireHTTPS {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewHealth returns a ready-to-mount health handler.
func NewHealth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
}

// AccessLogMiddleware emits one structured log line per request. Optional
// but recommended in production; not mounted by NewRouter so tests stay
// quiet. Enable by wrapping NewRouter's output:
//
//	server.NewRouter(...).Use(server.AccessLogMiddleware(logger))
func AccessLogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
			)
		})
	}
}

// newRequestID returns a short random id without pulling in another
// dependency. Format: 16 hex chars.
func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
