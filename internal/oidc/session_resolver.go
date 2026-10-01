package oidc

import (
	"context"
	"net/http"
	"net/url"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
)

// SessionResolver identifies the signed-in user on browser pages from the
// SSO session cookie. It is the single place that decides whether a
// session is usable (exists, not revoked, not expired).
type SessionResolver struct {
	Cookies  *session.CookieManager
	Sessions store.SessionStore
	Clock    clock.Clock
}

// Resolve returns the active session for the request. It returns
// (nil, nil) when the session exists but is revoked or expired, and an
// error (session.ErrNoSession or a store error) when there is no usable
// cookie or the lookup fails.
func (s *SessionResolver) Resolve(r *http.Request) (*domain.Session, error) {
	id, err := s.Cookies.FromRequest(r)
	if err != nil {
		return nil, err
	}
	sess, err := s.Sessions.Find(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if sess.RevokedAt != nil || s.Clock.Now().After(sess.ExpiresAt) {
		return nil, nil
	}
	return sess, nil
}

type sessionCtxKey struct{}

// SessionFromContext returns the session placed by RequireSession.
func SessionFromContext(ctx context.Context) (*domain.Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey{}).(*domain.Session)
	return sess, ok && sess != nil
}

// RequireSession wraps next so it only runs for a signed-in user and
// stores the session in the request context. Anonymous requests are
// redirected to loginPath; GET requests carry their own path and query
// as returnUrl (the login handler still validates it).
func (s *SessionResolver) RequireSession(loginPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Resolve(r)
		if err != nil || sess == nil {
			if err != nil && err != session.ErrNoSession {
				s.Cookies.ClearCookie(w)
			}
			target := loginPath
			if r.Method == http.MethodGet {
				target += "?returnUrl=" + url.QueryEscape(r.URL.RequestURI())
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess)))
	})
}
