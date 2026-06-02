// Package server wires the HTTP router, middleware chain, and the concrete
// handlers defined in internal/oidc. The package is the composition target
// for cmd/authserver: it builds a fully-wired http.Handler from a Config
// and a set of store implementations.
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
	IssuerURL     string
	RequireHTTPS  bool
	LoginPath     string
	LogoutPath    string
	AuthorizePath string
	TokenPath     string
	UserInfoPath  string
	RevokePath    string
	JWKSPath      string
	DiscoveryPath string
	HealthPath    string

	// LoginRateLimitRPS is the per-IP rate applied to the login
	// POST. 0 disables the limiter.
	LoginRateLimitRPS int
	// LoginRateBurst is the per-IP burst for the login limiter.
	LoginRateBurst int
}

// Handlers is the bundle of ready-to-mount handlers. A nil entry means
// the route is not exposed (e.g. during a partial integration test).
type Handlers struct {
	Login     http.Handler
	Logout    http.Handler
	Authorize http.Handler
	Token     http.Handler
	UserInfo  http.Handler
	Revoke    http.Handler
	Discovery http.Handler
	JWKS      http.Handler
	Health    http.Handler

	// Admin is the bundle of admin API + SPA. Mounted under /admin/
	// as a separate chi group so the middleware (auth + CSRF) only
	// applies to that subtree.
	Admin *AdminMount
}

// AdminMount is the set of handlers the /admin group needs. The
// router mounts whatever it finds at /admin/ and /admin/api/.
// Both fields are typically the same handler (the wrapped
// admin mux that combines auth + CSRF + API + index).
type AdminMount struct {
	// Root serves requests at /admin/ (the SPA index). When nil,
	// /admin/ returns 404.
	Root http.Handler
	// API serves requests under /admin/api/. When nil, /admin/api/
	// returns 404.
	API http.Handler
}

// NewRouter assembles the production route table and middleware chain.
func NewRouter(cfg RouterConfig, opts RouterOptions, h Handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(requestIDMiddleware)
	r.Use(recovererMiddleware(opts.Logger))
	r.Use(securityHeadersMiddleware(cfg.RequireHTTPS))

	if h.Login != nil && cfg.LoginPath != "" {
		// Per-IP rate limit on the login endpoint, before any other
		// middleware, so that a flood of failed attempts cannot
		// even reach the user store.
		limiter := NewLoginRateLimiter(cfg.LoginRateLimitRPS, cfg.LoginRateBurst)
		loginChain := limiter.Middleware(h.Login)
		r.Handle(cfg.LoginPath, loginChain)
	}
	if h.Logout != nil {
		// Logout owns both /connect/logout and the confirm page at
		// cfg.LogoutPath; the handler dispatches internally.
		r.Handle("/connect/logout", h.Logout)
		if cfg.LogoutPath != "" && cfg.LogoutPath != "/connect/logout" {
			r.Handle(cfg.LogoutPath, h.Logout)
		}
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

	// Admin group: everything under /admin/ goes through the auth
	// middleware supplied by main.go. The admin mount is plain
	// stdlib net/http so the SPA can call any path the admin.API
	// ServeMux registered. We use chi.Mount for prefix routing —
	// chi's Handle does not treat a trailing slash as a prefix
	// match. StripPrefix("/admin") lets the inner mux see paths
	// like /api/clients instead of /admin/api/clients.
	if h.Admin != nil {
		adminRoot := http.StripPrefix("/admin", h.Admin.Root)
		adminAPI := http.StripPrefix("/admin", h.Admin.API)
		// Redirect /admin to /admin/ for developer convenience.
		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		})
		// /admin/  — SPA index (serves the same handler; the
		// inner CombineMux dispatches /api/... to the API mux).
		r.Mount("/admin/", adminRoot)
		// /admin/api/...  — explicit API mount so chi knows it's
		// a sub-tree.
		r.Mount("/admin/api/", adminAPI)
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
// every response. The OAuth/OIDC endpoints return JSON, but the login
// page is HTML — both benefit from these defaults.
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
