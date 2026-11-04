package oidc

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"go-authserver/internal/store"
)

// This file holds the shared plumbing for the JSON APIs the browser SPA
// consumes: the CSRF token endpoint, the session "whoami" endpoint, and
// small encode/decode helpers. The SPA is served separately (same
// origin); these endpoints are its only view of the auth server besides
// the OIDC protocol endpoints.

// maxJSONBody caps JSON request bodies on the browser APIs. The payloads
// are tiny credential forms; anything larger is a client bug or abuse.
const maxJSONBody = 1 << 20

// writeJSON writes a JSON response with no-store caching, matching the
// admin API's conventions.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	SetNoStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads one JSON value from the request body into v.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxJSONBody)).Decode(v)
}

// CSRFHandler serves GET /api/csrf. It sets the shared _csrf cookie and
// returns the token in the body so the SPA can echo it back in the
// X-CSRF-Token header on state-changing requests. A cross-origin
// attacker can trigger neither the read of this body (same-origin
// policy) nor the cookie (HttpOnly), which is what makes the
// double-submit check meaningful.
type CSRFHandler struct {
	RequireHTTPS bool
	Logger       *slog.Logger
}

func (h *CSRFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	tok, err := APICSRFGuard(h.RequireHTTPS).Issue(w)
	if err != nil {
		if h.Logger != nil {
			h.Logger.ErrorContext(r.Context(), "csrf issue failed", "err", err)
		}
		writeJSONError(w, http.StatusInternalServerError, ErrServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": tok})
}

// SessionHandler serves GET /api/auth/session, the SPA's whoami check.
// Anonymous requests get {"authenticated": false} with a 200 so the SPA
// can probe on every page load without treating it as an error.
type SessionHandler struct {
	Resolver *SessionResolver
	Users    store.UserStore
	// AdminRole is the role name that grants admin-console access.
	AdminRole string
	Logger    *slog.Logger
}

type sessionView struct {
	Authenticated bool     `json:"authenticated"`
	UserID        string   `json:"user_id,omitempty"`
	Username      string   `json:"username,omitempty"`
	Email         string   `json:"email,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	IsAdmin       bool     `json:"is_admin"`
}

func (h *SessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	sess, err := h.Resolver.Resolve(r)
	if err != nil || sess == nil {
		writeJSON(w, http.StatusOK, sessionView{Authenticated: false})
		return
	}
	ctx := r.Context()
	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		if h.Logger != nil {
			h.Logger.ErrorContext(r.Context(), "session: user lookup failed", "err", err)
		}
		writeJSONError(w, http.StatusInternalServerError, ErrServerError, "internal error")
		return
	}
	roles, err := h.Users.GetUserRoles(ctx, sess.UserID)
	if err != nil {
		if h.Logger != nil {
			h.Logger.WarnContext(r.Context(), "session: role lookup failed", "err", err)
		}
		roles = nil
	}
	adminRole := h.AdminRole
	if adminRole == "" {
		adminRole = "admin"
	}
	writeJSON(w, http.StatusOK, sessionView{
		Authenticated: true,
		UserID:        user.ID,
		Username:      user.Username,
		Email:         user.Email,
		Roles:         roles,
		IsAdmin:       slices.ContainsFunc(roles, func(r string) bool { return strings.EqualFold(r, adminRole) }),
	})
}
