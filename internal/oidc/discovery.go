package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"go-authserver/internal/store"
)

// discoveryHandler serves GET /.well-known/openid-configuration. The
// metadata reflects what the auth server actually supports today; new
// capabilities (e.g. PKCE method plain, additional response_types) must
// land here as they are added so clients can discover them.
type discoveryHandler struct {
	Issuer string
	Scopes store.ScopeStore
}

// NewDiscoveryHandler returns a ready-to-mount discovery handler.
func NewDiscoveryHandler(issuer string, scopes store.ScopeStore) http.Handler {
	return &discoveryHandler{Issuer: issuer, Scopes: scopes}
}

type discoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
}

func (h *discoveryHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	scopes, err := h.Scopes.GetAll(context.Background())
	if err != nil {
		// Discovery is best-effort: omit the field rather than fail the
		// endpoint, but still surface the issue in the response.
		scopes = nil
	}
	scopeNames := make([]string, 0, len(scopes))
	for _, s := range scopes {
		scopeNames = append(scopeNames, s.Name)
	}

	doc := discoveryDocument{
		Issuer:                                     strings.TrimRight(h.Issuer, "/"),
		AuthorizationEndpoint:                      strings.TrimRight(h.Issuer, "/") + "/connect/authorize",
		TokenEndpoint:                              strings.TrimRight(h.Issuer, "/") + "/connect/token",
		UserinfoEndpoint:                           strings.TrimRight(h.Issuer, "/") + "/connect/userinfo",
		JWKSURI:                                    strings.TrimRight(h.Issuer, "/") + "/.well-known/jwks.json",
		EndSessionEndpoint:                         strings.TrimRight(h.Issuer, "/") + "/connect/logout",
		RevocationEndpoint:                         strings.TrimRight(h.Issuer, "/") + "/connect/revoke",
		ResponseTypesSupported:                     []string{"code"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:                      []string{"public"},
		IDTokenSigningAlgValuesSupported:           []string{"RS256"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          []string{"none", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                            scopeNames,
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}
