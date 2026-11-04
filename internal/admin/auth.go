package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
)

// SessionResolver identifies the signed-in browser session on a
// request. The oidc package's SessionResolver satisfies it.
type SessionResolver interface {
	Resolve(r *http.Request) (*domain.Session, error)
}

// authMethod records how a request passed AuthMiddleware. The CSRF
// middleware needs it: cookie-authenticated requests carry ambient
// authority and require the double-submit check, Bearer requests do
// not.
type authMethod int

const (
	authAnonymous authMethod = iota
	authToken
	authSession
)

type authMethodCtxKey struct{}

func withAuthMethod(r *http.Request, m authMethod) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authMethodCtxKey{}, m))
}

func authMethodFrom(r *http.Request) authMethod {
	m, _ := r.Context().Value(authMethodCtxKey{}).(authMethod)
	return m
}

type actorCtxKey struct{}

func withActor(r *http.Request, userID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), actorCtxKey{}, userID))
}

// actorFrom returns the user ID of the signed-in admin, or "" when the
// request was authorized by the static token or anonymous mode.
func actorFrom(r *http.Request) string {
	id, _ := r.Context().Value(actorCtxKey{}).(string)
	return id
}

// AuthConfig captures the policy inputs for the admin auth middleware.
type AuthConfig struct {
	// Token is the static Bearer token shared with admin scripts. The
	// client sends it as `Authorization: Bearer <token>` (preferred)
	// or `X-Admin-Token: <token>` (legacy convenience). Browser users
	// do not use it; they sign in normally (see Sessions).
	Token string
	// AllowAnonymous bypasses the check. Intended for local dev
	// only; production must leave AllowAnonymous false.
	AllowAnonymous bool
	// AdminRole is the role name that grants a signed-in user access
	// to the admin API. Empty means "admin".
	AdminRole string
	// Sessions resolves the SSO session cookie. When set (with
	// Users), a signed-in user holding AdminRole is authorized.
	Sessions SessionResolver
	// Users is used to look up the session user's roles.
	Users store.UserStore
}

// AuthMiddleware returns the HTTP middleware that gates the admin API.
// A request passes when any of these holds, in order: anonymous mode is
// on (dev only), a valid Bearer token is presented, or the SSO session
// belongs to a user with the admin role. Signed-in non-admins get 403;
// everyone else gets 401.
func AuthMiddleware(cfg AuthConfig, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	if !cfg.AllowAnonymous && strings.TrimSpace(cfg.Token) == "" && cfg.Sessions == nil {
		return nil, errors.New("admin: AUTH_ADMIN_TOKEN must be set unless AUTH_ADMIN_ALLOW_ANONYMOUS=true")
	}
	adminRole := cfg.AdminRole
	if adminRole == "" {
		adminRole = "admin"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.AllowAnonymous {
				w.Header().Set("X-Admin-Auth", "anonymous")
				next.ServeHTTP(w, withAuthMethod(r, authAnonymous))
				return
			}
			if provided := extractAdminToken(r); provided != "" && cfg.Token != "" &&
				subtle.ConstantTimeCompare([]byte(provided), []byte(cfg.Token)) == 1 {
				w.Header().Set("X-Admin-Auth", "token")
				next.ServeHTTP(w, withAuthMethod(r, authToken))
				return
			}
			if cfg.Sessions != nil && cfg.Users != nil {
				sess, err := cfg.Sessions.Resolve(r)
				if err != nil && !isNoSessionError(err) {
					// A store failure is not a missing login: answering 401
					// would hide the outage and bounce a signed-in admin.
					if logger != nil {
						logger.ErrorContext(r.Context(), "admin auth: session lookup failed", "err", err)
					}
					writeAuthError(w, http.StatusInternalServerError, "server_error")
					return
				}
				if err == nil && sess != nil {
					roles, err := cfg.Users.GetUserRoles(r.Context(), sess.UserID)
					if err != nil {
						if logger != nil {
							logger.WarnContext(r.Context(), "admin auth: role lookup failed", "err", err)
						}
						writeAuthError(w, http.StatusInternalServerError, "server_error")
						return
					}
					if containsString(roles, adminRole) {
						w.Header().Set("X-Admin-Auth", "session")
						next.ServeHTTP(w, withActor(withAuthMethod(r, authSession), sess.UserID))
						return
					}
					if logger != nil {
						logger.WarnContext(r.Context(), "admin auth: non-admin session")
					}
					writeAuthError(w, http.StatusForbidden, "admin role required")
					return
				}
			}
			if logger != nil {
				logger.WarnContext(r.Context(), "admin auth failed")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server-admin"`)
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
		})
	}, nil
}

// isNoSessionError reports whether a Resolve error means the request
// simply carries no usable session (missing, bad, or unknown cookie)
// rather than a failure to look it up.
func isNoSessionError(err error) bool {
	return errors.Is(err, session.ErrNoSession) ||
		errors.Is(err, session.ErrInvalidCookie) ||
		errors.Is(err, store.ErrNotFound)
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// extractAdminToken reads the token from the request. Authorization:
// Bearer is preferred; X-Admin-Token is the legacy convenience header.
func extractAdminToken(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(a[len("Bearer "):])
	}
	return r.Header.Get("X-Admin-Token")
}
