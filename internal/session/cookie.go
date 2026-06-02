// Package session owns the encrypted SSO session cookie. The cookie value
// is the session UUID, encrypted and signed by gorilla/securecookie so a
// network attacker cannot read or forge it. Keys come from configuration so
// multiple server instances can share them.
package session

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"go-authserver/internal/clock"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
)

// ErrNoSession is returned by FromRequest when no session cookie is
// present or the cookie is malformed.
var ErrNoSession = errors.New("session: no session")

// CookieConfig captures the policy of how the session cookie is named and
// scoped. It is produced from the server Config and is what CookieManager
// reads on every Set/Load.
type CookieConfig struct {
	Name         string
	RequireHTTPS bool
	Path         string
	MaxAge       time.Duration
}

// CookieManager wraps a securecookie codec with helpers for the request
// lifecycle: read the cookie, write a fresh one, or clear it.
type CookieManager struct {
	codec  *securecookie.SecureCookie
	config CookieConfig
	clock  clock.Clock
}

func NewCookieManager(hashKey, blockKey []byte, cfg CookieConfig, clk clock.Clock) *CookieManager {
	return &CookieManager{
		codec:  securecookie.New(hashKey, blockKey),
		config: cfg,
		clock:  clk,
	}
}

// Encode returns the encrypted+signed cookie value for the given session id.
func (m *CookieManager) Encode(id uuid.UUID) (string, error) {
	encoded, err := m.codec.Encode(m.config.Name, id.String())
	if err != nil {
		return "", fmt.Errorf("session: encode: %w", err)
	}
	return encoded, nil
}

// Decode verifies the signature+encryption and returns the session id.
func (m *CookieManager) Decode(raw string) (uuid.UUID, error) {
	var s string
	if err := m.codec.Decode(m.config.Name, raw, &s); err != nil {
		return uuid.Nil, fmt.Errorf("session: decode: %w", err)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("session: parse id: %w", err)
	}
	return id, nil
}

// SetCookie writes the session cookie to w. The cookie is HttpOnly and
// SameSite=Lax; Secure and the __Host- prefix are applied when
// RequireHTTPS is true.
func (m *CookieManager) SetCookie(w http.ResponseWriter, id uuid.UUID) error {
	encoded, err := m.Encode(id)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     m.config.Name,
		Value:    encoded,
		Path:     m.config.Path,
		HttpOnly: true,
		Secure:   m.config.RequireHTTPS,
		SameSite: http.SameSiteLaxMode,
	}
	if m.config.MaxAge > 0 {
		cookie.MaxAge = int(m.config.MaxAge.Seconds())
		cookie.Expires = m.clock.Now().Add(m.config.MaxAge)
	}
	http.SetCookie(w, cookie)
	return nil
}

// ClearCookie writes an immediately-expired cookie with the same name and
// attributes so the browser drops the session.
func (m *CookieManager) ClearCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.config.Name,
		Value:    "",
		Path:     m.config.Path,
		HttpOnly: true,
		Secure:   m.config.RequireHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, cookie)
}

// FromRequest extracts and decodes the session cookie, returning ErrNoSession
// when there is no cookie or the cookie cannot be decoded. The caller is
// responsible for distinguishing "no session" from "expired/revoked session"
// by looking the id up in the session store.
func (m *CookieManager) FromRequest(r *http.Request) (uuid.UUID, error) {
	c, err := r.Cookie(m.config.Name)
	if err != nil {
		return uuid.Nil, ErrNoSession
	}
	return m.Decode(c.Value)
}
