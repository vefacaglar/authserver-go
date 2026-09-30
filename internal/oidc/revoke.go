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
//
// Client authentication (RFC 7009 §2.1): confidential clients MUST
// authenticate. Public clients authenticate by presenting their
// client_id. The same AuthenticateClient used by the token endpoint
// runs here, so the same set of client auth methods (none,
// private_key_jwt) is enforced consistently. The authenticated
// client's identity is the source of truth; the form's client_id is
// only used to find the registered client record before
// authentication, never trusted on its own.
package oidc

import (
	"log/slog"
	"net/http"
	"time"

	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

type RevokeHandler struct {
	RefreshTokens store.RefreshTokenStore
	Clients       store.ClientStore
	// ClientAuth is the same configuration passed to the token
	// endpoint's AuthenticateClient. We share the assertion cache,
	// skew, and audience set so confidential clients authenticate
	// identically at both endpoints.
	ClientAuth ClientAuthConfig
	Now        func() time.Time
	Logger     *slog.Logger
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
	if raw == "" {
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "token is required")
		return
	}

	// Authenticate the client. Confidential clients must present
	// their credentials (e.g. private_key_jwt assertion); public
	// clients identify themselves by client_id. The same opaque
	// invalid_client error is returned on any failure so we don't
	// leak the specific reason.
	client, err := AuthenticateClient(r.Context(), h.ClientAuth, h.Clients, r.PostForm)
	if err != nil {
		cae := asClientAuthError(err)
		if h.Logger != nil && cae.Cause != nil {
			h.Logger.Warn("revoke: client auth failed", "err", cae.Cause)
		}
		writeClientAuthError(w, cae)
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
