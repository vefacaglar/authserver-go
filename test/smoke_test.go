//go:build m8smoke

// Package smoke spins up the full auth server in-process, points
// coreos/go-oidc + golang.org/x/oauth2 at it as if it were any other
// OIDC provider, and verifies that the discovery + JWKS + token
// contracts are honoured. The full browser-driven login flow is
// covered by the always-on integration tests; here we focus on the
// parts a real OIDC client relies on first contact.
//
// Run with:
//
//	RUN_SMOKE=1 go test -tags m8smoke -count=1 -run TestSmoke_RealOIDCClient ./test/...
package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// jsonDecode is a tiny helper to keep the imports tight.
func jsonDecode(b []byte, v any) error { return json.Unmarshal(b, v) }

// TestSmoke_RealOIDCClient exercises the parts of the OIDC contract
// that any off-the-shelf client library depends on first contact:
//
//  1. /.well-known/openid-configuration returns a valid document.
//  2. /.well-known/jwks.json returns a parseable JWKS.
//  3. The ID token returned by the token endpoint verifies under
//     the JWKS (real coreos/go-oidc v3 verifier).
//  4. The /connect/userinfo endpoint returns claims for a valid
//     access token.
func TestSmoke_RealOIDCClient(t *testing.T) {
	if os.Getenv("RUN_SMOKE") != "1" {
		t.Skip("set RUN_SMOKE=1 to run the real-client smoke test")
	}

	// coreos/go-oidc v3 compares the issuer passed to
	// NewProvider against the one returned in the discovery
	// document and refuses to proceed if they differ. The
	// default test server's issuer is
	// "https://auth.example.com" which doesn't match the
	// httptest base URL. Spin up a dedicated server with the
	// issuer set to the test base URL so the OIDC client
	// accepts it.
	ts := newSmokeTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Discovery. The OIDC client must find the endpoints via
	// the well-known URI; coreos/go-oidc fetches and validates
	// the metadata document.
	provider, err := oidc.NewProvider(ctx, ts.URL(""))
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	if provider.Endpoint().AuthURL == "" {
		t.Errorf("provider auth URL empty")
	}
	if provider.Endpoint().TokenURL == "" {
		t.Errorf("provider token URL empty")
	}
	if provider.UserInfoEndpoint() == "" {
		t.Errorf("provider userinfo URL empty")
	}
	t.Logf("discovered endpoints: auth=%s token=%s userinfo=%s",
		provider.Endpoint().AuthURL,
		provider.Endpoint().TokenURL,
		provider.UserInfoEndpoint())

	// 2. JWKS. The provider already fetched and parsed the JWKS
	// during NewProvider. We also do a raw GET to confirm the
	// shape is what an OIDC client expects.
	jwksResp, err := http.Get(ts.URL("/.well-known/jwks.json"))
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	jwksBody, _ := io.ReadAll(jwksResp.Body)
	jwksResp.Body.Close()
	if !contains(string(jwksBody), `"kty":"RSA"`) {
		t.Errorf("JWKS missing RSA key: %s", jwksBody)
	}
	if contains(string(jwksBody), `"d":`) {
		t.Errorf("JWKS leaked private exponent: %s", jwksBody)
	}

	// 3. ID-token verification. Drive the full happy path
	// through the test server to obtain a real id_token, then
	// verify it with coreos/go-oidc — the same library
	// Kubernetes / Terraform use. This is the moment of truth.
	tr, _ := exchangeCodeForTokens(t, ts)
	if tr.IDToken == "" {
		t.Fatal("id_token empty")
	}

	idTok, err := provider.Verifier(&oidc.Config{ClientID: testClientID}).Verify(ctx, tr.IDToken)
	if err != nil {
		t.Fatalf("ID token verify: %v", err)
	}
	if idTok.Subject != "u-demo" {
		t.Errorf("id sub = %q, want u-demo", idTok.Subject)
	}
	t.Logf("ID token verified: sub=%s iss=%s aud=%v", idTok.Subject, idTok.Issuer, idTok.Audience)

	// 4. UserInfo via the real client's endpoint.
	ts2 := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tr.AccessToken, TokenType: "Bearer"})
	ui, err := provider.UserInfo(ctx, ts2)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if ui.Subject != "u-demo" {
		t.Errorf("userinfo sub = %q, want u-demo", ui.Subject)
	}
	if ui.Email != "demo@example.com" {
		t.Errorf("userinfo email = %q, want demo@example.com", ui.Email)
	}
	t.Logf("userinfo OK: sub=%s email=%s", ui.Subject, ui.Email)
}
