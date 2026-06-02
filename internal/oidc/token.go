package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/oidc/grants"
	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

// TokenHandler dispatches POST /connect/token by grant_type. It
// authenticates the client first (see AuthenticateClient), then
// hands the verified *domain.Client to the per-grant handler. The
// grant handlers still re-check the form's client_id against the
// authenticated client as defence-in-depth; if the two ever
// diverge, AuthenticateClient is the source of truth.
type TokenHandler struct {
	AuthCode          *grants.AuthCodeGrant
	Refresh           *grants.RefreshGrant
	ClientCredentials *grants.ClientCredentialsGrant

	// ClientAuth is the configuration block passed to
	// AuthenticateClient.
	ClientAuth ClientAuthConfig
	Clients    store.ClientStore
	Clock      clock.Clock
	Logger     *slog.Logger
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "could not parse form body")
		return
	}
	form := r.PostForm

	// Authenticate the client BEFORE we know which grant is being
	// requested. AuthenticateClient is the single source of truth
	// for the client identity at the token endpoint.
	client, err := h.authenticate(r.Context(), form)
	if err != nil {
		cae := asClientAuthError(err)
		if h.Logger != nil && cae.Cause != nil {
			h.Logger.Warn("client auth failed", "err", cae.Cause)
		}
		writeClientAuthError(w, cae)
		return
	}

	grantType := form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		if h.AuthCode == nil {
			writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "authorization_code grant not enabled")
			return
		}
		h.AuthCode.Handle(r.Context(), w, client, form)
	case "refresh_token":
		if h.Refresh == nil {
			writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "refresh_token grant not enabled")
			return
		}
		h.Refresh.Handle(r.Context(), w, client, form)
	case "client_credentials":
		if h.ClientCredentials == nil {
			writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "client_credentials grant not enabled")
			return
		}
		h.ClientCredentials.Handle(r.Context(), w, client, form)
	default:
		writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "unsupported grant_type")
	}
}

// authenticate is a small wrapper that fills in the dispatcher
// fields and delegates to AuthenticateClient.
func (h *TokenHandler) authenticate(ctx context.Context, form url.Values) (*domain.Client, error) {
	return AuthenticateClient(ctx, h.ClientAuth, h.Clients, form)
}

// Compile-time guard so token.ClientAssertionCache remains satisfied
// by the in-memory cache the main wiring installs.
var _ = fmt.Sprintf
var _ token.ClientAssertionCache = (*token.MemAssertionCache)(nil)
