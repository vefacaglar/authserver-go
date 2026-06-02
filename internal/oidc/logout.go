package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"go-authserver/internal/clock"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// LogoutConfig bundles the policy inputs the logout handler reads.
type LogoutConfig struct {
	IssuerURL             string
	AuthorizePath         string
	LogoutPath            string
	PostLogoutRedirectURI string
}

// LogoutHandler implements RP-initiated logout.
//
//   - GET on /connect/logout: if a cryptographically valid id_token_hint
//     is supplied AND a registered post_logout_redirect_uri is requested,
//     proceed straight to that target. Otherwise 302 to the configured
//     LogoutPath (the confirm page) carrying the original parameters.
//   - GET on LogoutPath: render the confirm page with a fresh CSRF
//     cookie + token.
//   - POST on /connect/logout: validate CSRF, revoke the session, clear
//     the cookie, revoke the session's refresh-token chain, redirect to
//     a validated post_logout_redirect_uri (or the configured fallback).
//
// The CSRF cookie is HttpOnly, path = /, SameSite=Lax. The double-submit
// pattern: the server sets the cookie, reads it on POST, and compares
// the value to the form field. A cross-origin attacker can read neither.
type LogoutHandler struct {
	Cfg           LogoutConfig
	Cookies       *session.CookieManager
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	Clients       store.ClientStore
	Issuer        *token.Issuer
	Clock         clock.Clock
	Logger        *slog.Logger
	Confirm       *template.Template
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case h.Cfg.LogoutPath:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
			return
		}
		h.renderConfirm(w, r)
	default:
		// /connect/logout
		switch r.Method {
		case http.MethodGet:
			h.handleEntry(w, r)
		case http.MethodPost:
			h.handleConfirm(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		}
	}
}

// handleEntry is the GET /connect/logout dispatcher.
func (h *LogoutHandler) handleEntry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint := q.Get("id_token_hint")
	target := q.Get("post_logout_redirect_uri")
	state := q.Get("state")
	clientID := q.Get("client_id")

	if hint != "" {
		tok, err := h.Issuer.VerifyToken(r.Context(), hint)
		if err == nil {
			aud := tok.Audience()
			if len(aud) > 0 {
				clientID = aud[0]
			}
			if target != "" {
				if ok, _ := h.validatePostLogoutURI(r.Context(), clientID, target); ok {
					http.Redirect(w, r, appendState(target, state), http.StatusFound)
					return
				}
			}
		}
	}

	// No valid hint or no validated target → confirmation page.
	q2 := url.Values{}
	if target != "" {
		q2.Set("post_logout_redirect_uri", target)
	}
	if state != "" {
		q2.Set("state", state)
	}
	if clientID != "" {
		q2.Set("client_id", clientID)
	}
	dest := h.Cfg.LogoutPath
	if encoded := q2.Encode(); encoded != "" {
		dest += "?" + encoded
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// renderConfirm is the GET /logout handler. It issues a CSRF cookie and
// renders the confirm template.
func (h *LogoutHandler) renderConfirm(w http.ResponseWriter, r *http.Request) {
	if h.Confirm == nil {
		writeJSONError(w, http.StatusInternalServerError, ErrServerError, "logout confirm template not configured")
		return
	}
	q := r.URL.Query()
	csrf, _ := h.issueCSRF(w)
	data := struct {
		Action                string
		CSRFToken             string
		PostLogoutRedirectURI string
		State                 string
		ClientID              string
	}{
		Action:                "/connect/logout",
		CSRFToken:             csrf,
		PostLogoutRedirectURI: q.Get("post_logout_redirect_uri"),
		State:                 q.Get("state"),
		ClientID:              q.Get("client_id"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = h.Confirm.Execute(w, data)
}

// handleConfirm is the POST /connect/logout handler. State change.
func (h *LogoutHandler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, h.Cfg.LogoutPath+"?error="+url.QueryEscape("malformed form"), http.StatusFound)
		return
	}
	if !h.verifyCSRF(r) {
		http.Redirect(w, r, h.Cfg.LogoutPath+"?error="+url.QueryEscape("antiforgery check failed"), http.StatusFound)
		return
	}
	// Cancel button: skip revocation, just bounce back.
	if r.FormValue("confirm") == "no" {
		http.Redirect(w, r, h.Cfg.PostLogoutRedirectURI, http.StatusFound)
		return
	}

	target := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")

	// Resolve + revoke the session if any.
	sid, err := h.Cookies.FromRequest(r)
	switch {
	case err == nil:
		sess, sErr := h.Sessions.Find(r.Context(), sid)
		if sErr == nil {
			if sess.RevokedAt == nil {
				_ = h.Sessions.Revoke(r.Context(), sess.ID, h.Clock.Now().UTC())
			}
			if sess.ID != uuid.Nil {
				_ = h.RefreshTokens.RevokeBySessionID(r.Context(), sess.ID, h.Clock.Now().UTC())
			}
		}
	case errors.Is(err, session.ErrNoSession):
		// No cookie: nothing to revoke, still clear it.
	default:
		if h.Logger != nil {
			h.Logger.Warn("session decode failed on logout", "err", err)
		}
	}
	h.Cookies.ClearCookie(w)

	// Validate the post_logout_redirect_uri.
	allowed := h.Cfg.PostLogoutRedirectURI
	if target != "" {
		if ok, _ := h.validatePostLogoutURI(r.Context(), clientID, target); ok {
			allowed = target
		} else if h.Logger != nil {
			h.Logger.Warn("post_logout_redirect_uri not allowed", "client_id", clientID, "target", target)
		}
	}
	http.Redirect(w, r, appendState(allowed, state), http.StatusFound)
}

// validatePostLogoutURI returns true when target is acceptable for the
// given client. The target must be an absolute URL whose host matches
// the issuer's AND whose path is in the client's PostLogoutRedirectURIs.
func (h *LogoutHandler) validatePostLogoutURI(ctx context.Context, clientID, target string) (bool, error) {
	if target == "" {
		return false, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return false, err
	}
	if !u.IsAbs() {
		return false, nil
	}
	iss, err := url.Parse(h.Cfg.IssuerURL)
	if err != nil {
		return false, err
	}
	if u.Scheme != iss.Scheme || u.Host != iss.Host {
		return false, nil
	}
	if clientID == "" {
		return false, nil
	}
	client, err := h.Clients.FindByClientID(ctx, clientID)
	if err != nil || len(client.PostLogoutRedirectURIs) == 0 {
		return false, nil
	}
	return slices.Contains(client.PostLogoutRedirectURIs, target), nil
}

func appendState(target, state string) string {
	if state == "" {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// --- CSRF ---

const (
	logoutCSRFCookie = "_logout_csrf"
	logoutCSRFHeader = "X-CSRF-Token"
	logoutCSRFField  = "csrf_token"
)

func (h *LogoutHandler) issueCSRF(w http.ResponseWriter) (string, *http.Cookie) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		if h.Logger != nil {
			h.Logger.Error("csrf rand", "err", err)
		}
		return "", nil
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	c := &http.Cookie{
		Name:     logoutCSRFCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.Cfg.IssuerURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
	return tok, c
}

func (h *LogoutHandler) verifyCSRF(r *http.Request) bool {
	c, err := r.Cookie(logoutCSRFCookie)
	if err != nil {
		return false
	}
	got := r.FormValue(logoutCSRFField)
	if got == "" {
		got = r.Header.Get(logoutCSRFHeader)
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}

// LogoutTemplate is the minimal confirm page. Exported so the
// composition root in cmd/authserver and the integration tests can
// share the same form definition.
func LogoutTemplate() string { return logoutHTML }

const logoutHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign out</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; }
  label { display: block; margin: 0.75rem 0 0.25rem; }
  button { margin-top: 1rem; padding: 0.5rem 1rem; margin-right: 0.5rem; }
</style>
</head>
<body>
<h1>Sign out</h1>
<p>Are you sure you want to sign out?</p>
<form method="post" action="{{ .Action }}">
  <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
  <input type="hidden" name="post_logout_redirect_uri" value="{{ .PostLogoutRedirectURI }}">
  <input type="hidden" name="state" value="{{ .State }}">
  <input type="hidden" name="client_id" value="{{ .ClientID }}">
  <button type="submit" name="confirm" value="yes">Sign out</button>
  <button type="submit" name="confirm" value="no">Cancel</button>
</form>
</body>
</html>`
