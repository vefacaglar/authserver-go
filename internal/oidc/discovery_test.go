package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"
)

func newTestIssuerForDiscovery(t *testing.T) *token.Issuer {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	km := token.NewKeyManager(memory.NewSigningKeyStore(), clk)
	return token.NewIssuer("https://auth.example.com", km, clk)
}

func TestDiscovery_AllRequiredFields(t *testing.T) {
	scopes := memory.NewScopeStore()
	_ = scopes.Store(context.Background(), &domain.Scope{Name: "openid", DisplayName: "OpenID"})
	_ = scopes.Store(context.Background(), &domain.Scope{Name: "profile", DisplayName: "Profile"})

	iss := newTestIssuerForDiscovery(t)
	h := &discoveryHandler{Issuer: iss.Issuer, Scopes: scopes}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var doc discoveryDocument
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != "https://auth.example.com" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if !strings.HasSuffix(doc.AuthorizationEndpoint, "/connect/authorize") {
		t.Errorf("authorization_endpoint = %q", doc.AuthorizationEndpoint)
	}
	if !strings.HasSuffix(doc.TokenEndpoint, "/connect/token") {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}
	if !strings.HasSuffix(doc.UserinfoEndpoint, "/connect/userinfo") {
		t.Errorf("userinfo_endpoint = %q", doc.UserinfoEndpoint)
	}
	if !strings.HasSuffix(doc.JWKSURI, "/.well-known/jwks.json") {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
	if !strings.HasSuffix(doc.EndSessionEndpoint, "/connect/logout") {
		t.Errorf("end_session_endpoint = %q", doc.EndSessionEndpoint)
	}
	if !strings.HasSuffix(doc.RevocationEndpoint, "/connect/revoke") {
		t.Errorf("revocation_endpoint = %q", doc.RevocationEndpoint)
	}
	if !slices.Contains(doc.ResponseTypesSupported, "code") {
		t.Errorf("response_types_supported = %v", doc.ResponseTypesSupported)
	}
	if !slices.Contains(doc.GrantTypesSupported, "authorization_code") {
		t.Errorf("grant_types_supported = %v", doc.GrantTypesSupported)
	}
	if !slices.Contains(doc.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("code_challenge_methods_supported = %v", doc.CodeChallengeMethodsSupported)
	}
	if !slices.Contains(doc.TokenEndpointAuthMethodsSupported, "none") {
		t.Errorf("token_endpoint_auth_methods_supported = %v", doc.TokenEndpointAuthMethodsSupported)
	}
	if !slices.Contains(doc.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("id_token_signing_alg_values_supported = %v", doc.IDTokenSigningAlgValuesSupported)
	}
	if !slices.Contains(doc.ScopesSupported, "openid") || !slices.Contains(doc.ScopesSupported, "profile") {
		t.Errorf("scopes_supported = %v", doc.ScopesSupported)
	}
}

func TestJWKS_ReturnsPublicKeys(t *testing.T) {
	iss := newTestIssuerForDiscovery(t)
	// Force a key to exist by issuing any token.
	_, _ = iss.IssueAccessToken(context.Background(), token.AccessTokenClaims{Subject: "u", ClientID: "c"})

	h := &jwksHandler{Issuer: iss}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"kty":"RSA"`) {
		t.Errorf("body missing kty=RSA: %s", body)
	}
	if strings.Contains(body, `"d":`) {
		t.Errorf("JWKS leaked private exponent: %s", body)
	}
	if !strings.Contains(body, `"use":"sig"`) {
		t.Errorf("JWKS missing use=sig: %s", body)
	}
}
