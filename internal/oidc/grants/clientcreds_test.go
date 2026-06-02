package grants

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"
)

func newTestClientCreds(t *testing.T) (*ClientCredentialsGrant, *memory.ClientStore) {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	clients := memory.NewClientStore()
	keys := token.NewKeyManager(memory.NewSigningKeyStore(), clk)
	issuer := token.NewIssuer("https://auth.example.com", keys, clk)
	return &ClientCredentialsGrant{
		Clients: clients,
		Issuer:  issuer,
		Clock:   clk,
		Cfg:     ClientCredentialsConfig{AccessTokenLifetime: time.Hour},
	}, clients
}

func mustClientCreds(t *testing.T, clients *memory.ClientStore, c *domain.Client) *domain.Client {
	t.Helper()
	if err := clients.Store(context.Background(), c); err != nil {
		t.Fatalf("store client: %v", err)
	}
	return c
}

func TestClientCreds_Handle_ConfidentialIssuesAccessToken(t *testing.T) {
	g, clients := newTestClientCreds(t)
	c := mustClientCreds(t, clients, &domain.Client{
		ClientID:                "confidential-1",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  true,
		AllowedScopes:           []string{"read", "write"},
	})

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, c, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !contains(rr.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control missing no-store")
	}
	var resp TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if resp.RefreshToken != "" {
		t.Errorf("refresh_token must NOT be issued; got %q", resp.RefreshToken)
	}
	if resp.IDToken != "" {
		t.Errorf("id_token must NOT be issued; got %q", resp.IDToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q, want read", resp.Scope)
	}

	// sub of the issued access token must be the client_id.
	tok, err := g.Issuer.VerifyToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if tok.Subject() != "confidential-1" {
		t.Errorf("sub = %q, want confidential-1", tok.Subject())
	}
}

func TestClientCreds_Handle_PublicClientRejected(t *testing.T) {
	g, clients := newTestClientCreds(t)
	c := mustClientCreds(t, clients, &domain.Client{
		ClientID:                "public-1",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
		AllowClientCredentials:  true,
	})

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, c, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", body.Error)
	}
}

func TestClientCreds_Handle_AllowClientCredentialsFalse(t *testing.T) {
	g, clients := newTestClientCreds(t)
	c := mustClientCreds(t, clients, &domain.Client{
		ClientID:                "confidential-2",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  false,
	})

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, c, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", body.Error)
	}
}

func TestClientCreds_Handle_DisallowedScopeRejected(t *testing.T) {
	g, clients := newTestClientCreds(t)
	c := mustClientCreds(t, clients, &domain.Client{
		ClientID:                "confidential-3",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  true,
		AllowedScopes:           []string{"read"},
	})

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read admin") // admin is not in AllowedScopes
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, c, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", body.Error)
	}
}

func TestClientCreds_Handle_NoScopeIsAllowed(t *testing.T) {
	g, clients := newTestClientCreds(t)
	c := mustClientCreds(t, clients, &domain.Client{
		ClientID:                "confidential-4",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  true,
		AllowedScopes:           []string{"read"},
	})

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	// no scope: machine-to-machine callers often want a scope-less
	// access token.
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, c, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp TokenResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if resp.Scope != "" {
		t.Errorf("scope = %q, want empty", resp.Scope)
	}
}

func TestClientCreds_Handle_NilClientRejected(t *testing.T) {
	g, _ := newTestClientCreds(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, nil, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
