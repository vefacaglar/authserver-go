package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/token"
)

// ClientCredentialsConfig bundles the lifetime policy the
// client_credentials grant reads.
type ClientCredentialsConfig struct {
	AccessTokenLifetime time.Duration
}

// ClientCredentialsGrant handles grant_type=client_credentials. Per
// RFC 6749 §4.4 and OIDC Core:
//
//   - caller MUST be a confidential client (TokenEndpointAuthMethod
//     != none)
//   - caller MUST have AllowClientCredentials enabled
//   - the issued access token's sub is the client_id (not a user)
//   - no id_token, no refresh_token (the client can re-authenticate
//     with a fresh assertion to get a new access token)
//
// The handler assumes the dispatcher has already authenticated the
// client; it only validates the client is permitted to use the
// grant and then mints the access token.
type ClientCredentialsGrant struct {
	Clients storeClientLister
	Issuer  *token.Issuer
	Clock   clock.Clock
	Cfg     ClientCredentialsConfig
}

// storeClientLister is the slice of the ClientStore interface the
// grant needs. Keeping it narrow here lets the test suite inject a
// lightweight fake.
type storeClientLister interface {
	FindByClientID(ctx context.Context, id string) (*domain.Client, error)
}

// Handle is invoked by the token dispatcher after the client is
// authenticated. The caller is responsible for surfacing the
// returned errors as 4xx responses.
func (g *ClientCredentialsGrant) Handle(ctx context.Context, w http.ResponseWriter, client *domain.Client, form url.Values) {
	if client == nil {
		g.writeError(w, http.StatusUnauthorized, "invalid_client", "client is required")
		return
	}
	if client.TokenEndpointAuthMethod == domain.TokenEndpointAuthMethodNone {
		g.writeError(w, http.StatusUnauthorized, "unauthorized_client", "client_credentials requires a confidential client")
		return
	}
	if !client.AllowClientCredentials {
		g.writeError(w, http.StatusUnauthorized, "unauthorized_client", "client is not allowed to use client_credentials")
		return
	}

	// Optional scope: subset of client.AllowedScopes. Empty form
	// value → no scope on the access token (machine-to-machine
	// callers often want a scope-less token).
	requested := strings.Fields(form.Get("scope"))
	for _, s := range requested {
		if !slices.Contains(client.AllowedScopes, s) {
			g.writeError(w, http.StatusBadRequest, "invalid_scope", fmt.Sprintf("scope %q is not allowed for this client", s))
			return
		}
	}

	access, err := g.Issuer.IssueAccessToken(ctx, token.AccessTokenClaims{
		Subject:   client.ClientID, // sub == client_id per the spec
		ClientID:  client.ClientID,
		Scope:     strings.Join(requested, " "),
		ExpiresIn: g.Cfg.AccessTokenLifetime,
	})
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "access token issuance failed")
		return
	}

	resp := TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(g.Cfg.AccessTokenLifetime.Seconds()),
		Scope:       strings.Join(requested, " "),
		// No refresh_token, no id_token.
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

func (g *ClientCredentialsGrant) writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: code, ErrorDescription: desc})
}
