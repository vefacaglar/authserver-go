package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
)

// CSRFGuard is the double-submit CSRF check shared by the account pages.
// The cookie is path-scoped, so each page group builds its own guard.
type CSRFGuard struct {
	CookieName   string
	Path         string
	RequireHTTPS bool
}

// Issue sets a fresh token cookie and returns the value to render into
// the form's csrf_token field.
func (g CSRFGuard) Issue(w http.ResponseWriter) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("csrf token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieName,
		Value:    tok,
		Path:     g.Path,
		HttpOnly: true,
		Secure:   g.RequireHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
	return tok, nil
}

// Verify compares the cookie with the form field (or header) in constant
// time. A missing value on either side fails.
func (g CSRFGuard) Verify(r *http.Request) bool {
	c, err := r.Cookie(g.CookieName)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue(csrfFieldName)
	if got == "" {
		got = r.Header.Get(csrfHeaderName)
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}
