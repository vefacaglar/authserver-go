package oidc

import (
	"context"
	"errors"
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
//   - GET on /connect/logout: 302 to the configured LogoutPath — the
//     SPA's confirm page — carrying the original parameters.
//   - POST on /connect/logout: the SPA confirm page submits a classic
//     form POST here (so the final redirect can leave the origin).
//     Validate CSRF, revoke the session, clear the cookie, revoke the
//     session's refresh-token chain, redirect to a validated
//     post_logout_redirect_uri (or the configured fallback).
//
// CSRF uses the shared API double-submit cookie (see GET /api/csrf):
// the SPA mirrors the token in the form's csrf_token field. A
// cross-origin attacker can read neither the HttpOnly cookie nor the
// token endpoint's body.
type LogoutHandler struct {
	Cfg           LogoutConfig
	Cookies       *session.CookieManager
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	Clients       store.ClientStore
	Issuer        *token.Issuer
	Clock         clock.Clock
	Logger        *slog.Logger
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// handleEntry is the GET /connect/logout dispatcher.
//
// id_token_hint is parsed and the aud is used to recover clientID, but
// it is never used to short-circuit the confirmation step. Earlier
// versions of this code skipped straight to terminateSession+redirect
// when a valid hint matched a registered post_logout_redirect_uri; that
// path was a logout-CSRF vector — a third party could trigger
// <img src="https://auth/connect/logout?id_token_hint=...&post_logout_redirect_uri=...">
// and the user's session would be destroyed and redirected without any
// user interaction. We now always go through the confirm page; the
// actual session revocation happens on POST after CSRF is validated.
func (h *LogoutHandler) handleEntry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint := q.Get("id_token_hint")
	target := q.Get("post_logout_redirect_uri")
	state := q.Get("state")
	clientID := q.Get("client_id")

	// If the RP supplied an id_token_hint, use its aud to recover
	// clientID so the confirm form carries the right value into POST.
	// The hint is otherwise discarded — it is not a substitute for the
	// user explicitly clicking "Sign out".
	if clientID == "" && hint != "" {
		if tok, err := h.Issuer.VerifyToken(r.Context(), hint); err == nil {
			aud := tok.Audience()
			if len(aud) > 0 {
				clientID = aud[0]
			}
		}
	}

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
	h.terminateSession(w, r)

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

func (h *LogoutHandler) terminateSession(w http.ResponseWriter, r *http.Request) {
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

// verifyCSRF checks the shared API double-submit cookie against the
// confirm form's csrf_token field (or the X-CSRF-Token header).
func (h *LogoutHandler) verifyCSRF(r *http.Request) bool {
	return APICSRFGuard(strings.HasPrefix(h.Cfg.IssuerURL, "https://")).Verify(r)
}
