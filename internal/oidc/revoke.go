package oidc

import (
	"log/slog"
	"net/http"
	"time"

	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

// RevokeHandler serves POST /connect/revoke (RFC 7009). The endpoint is
// intentionally quiet: it always returns 200 OK regardless of whether
// the token existed, was already revoked, or was foreign to this
// client. Information-leak prevention is the dominant concern here.
//
// Only refresh tokens are stored locally and can be acted on. Access
// tokens are JWTs the resource server already validated; there is
// nothing to delete server-side. The handler still returns 200 for
// them so the client cannot probe the server for which token type it
// knows about.
type RevokeHandler struct {
	RefreshTokens store.RefreshTokenStore
	Clients       store.ClientStore
	Now           func() time.Time
	Logger        *slog.Logger
}

// ServeHTTP processes a single revocation request.
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		// Malformed form is a transport error, not a token-state
		// question, so 400 is the only honest response.
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "could not parse form body")
		return
	}
	raw := r.PostForm.Get("token")
	clientID := r.PostForm.Get("client_id")
	if raw == "" || clientID == "" {
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "token and client_id are required")
		return
	}

	client, err := h.Clients.FindByClientID(r.Context(), clientID)
	if err != nil {
		// Unknown client is a usage error, not a token-state question.
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeJSONError(w, http.StatusUnauthorized, ErrInvalidClient, "unknown client")
		return
	}

	existing, err := h.RefreshTokens.FindByHash(r.Context(), token.HashToken(raw))
	if err != nil {
		// Token doesn't exist (or is an access token, which the server
		// doesn't keep). 200 anyway per the spec.
		w.WriteHeader(http.StatusOK)
		return
	}
	if existing.ClientID != client.ClientID {
		// Foreign token: 200 anyway. The spec forbids revealing
		// existence to a non-owning client.
		w.WriteHeader(http.StatusOK)
		return
	}
	now := h.Now().UTC()
	if existing.SessionID != nil {
		_ = h.RefreshTokens.RevokeBySessionID(r.Context(), *existing.SessionID, now)
	} else {
		_ = h.RefreshTokens.Revoke(r.Context(), existing.ID, now)
	}
	w.WriteHeader(http.StatusOK)
}
