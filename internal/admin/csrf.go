package admin

import (
	"crypto/subtle"
	"net/http"
)

// csrfCookieName and csrfHeaderName must match the oidc package's
// shared API guard: GET /api/csrf issues the cookie, the SPA echoes
// the token in the header. Duplicated as constants so this package
// does not import the HTTP handlers it sits beside.
const (
	csrfCookieName = "_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

// CSRFMiddleware enforces the double-submit check on state-changing
// admin API requests. Bearer-token requests are exempt: the token is
// not ambient authority, so a cross-origin form cannot ride on it.
// Session- and anonymous-mode requests must present an X-CSRF-Token
// header matching the _csrf cookie. Safe methods are never checked.
func CSRFMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if authMethodFrom(r) == authToken {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(csrfCookieName)
			got := r.Header.Get(csrfHeaderName)
			if err != nil || c.Value == "" || got == "" ||
				subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) != 1 {
				writeAuthError(w, http.StatusForbidden, "antiforgery_failed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
