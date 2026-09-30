package grants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func testChallenge(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestGrant(t *testing.T) (*AuthCodeGrant, *memory.AuthorizationCodeStore, *memory.RefreshTokenStore, *memory.ClientStore, *memory.UserStore, *token.Issuer, *domain.Client) {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	ac := memory.NewAuthorizationCodeStore()
	rt := memory.NewRefreshTokenStore()
	cl := memory.NewClientStore()
	us := memory.NewUserStore()
	keys := token.NewKeyManager(memory.NewSigningKeyStore(), clk)
	issuer := token.NewIssuer("https://auth.example.com", keys, clk)

	now := clk.Now()
	_ = us.CreateUser(context.Background(), &domain.User{
		ID:        "u-1",
		Username:  "alice",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}, "ignored")
	_ = us.AddUserClaims(context.Background(), "u-1", []domain.UserClaim{
		{Type: "preferred_username", Value: "alice"},
		{Type: "name", Value: "Alice"},
		{Type: "email", Value: "alice@example.com"},
		{Type: "email_verified", Value: "true"},
	})

	testClient := &domain.Client{
		ClientID:                "client-1",
		DisplayName:             "Test Client",
		RedirectURIs:            []string{"https://app.example/cb"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}
	_ = cl.Store(context.Background(), testClient)

	g := &AuthCodeGrant{
		AuthCodes:     ac,
		RefreshTokens: rt,
		Clients:       cl,
		Users:         us,
		Issuer:        issuer,
		Clock:         clk,
		Cfg: AuthCodeConfig{
			AccessTokenLifetime:          time.Hour,
			IDTokenLifetime:              time.Hour,
			RefreshTokenLifetime:         24 * time.Hour,
			RefreshTokenAbsoluteLifetime: 24 * time.Hour,
		},
	}
	return g, ac, rt, cl, us, issuer, testClient
}

func mintAuthCode(t *testing.T, ac *memory.AuthorizationCodeStore, cl *memory.ClientStore, clk clock.Clock) string {
	t.Helper()
	raw, hash, err := token.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	now := clk.Now().UTC()
	sid := id1()
	err = ac.Store(context.Background(), &domain.AuthorizationCode{
		ID:                  id1(),
		CodeHash:            hash,
		ClientID:            "client-1",
		UserID:              "u-1",
		SessionID:           &sid,
		RedirectURI:         "https://app.example/cb",
		CodeChallenge:       strPtr(testChallenge(t)),
		CodeChallengeMethod: strPtr("S256"),
		Scope:               "openid profile email offline_access",
		Nonce:               strPtr("nonce-abc"),
		ExpiresAt:           now.Add(time.Minute),
		CreatedAt:           now,
	})
	if err != nil {
		t.Fatalf("Store auth code: %v", err)
	}
	_ = cl
	return raw
}

func TestAuthCode_Handle_IssuesAccessAndIDToken(t *testing.T) {
	g, ac, rt, _, _, issuer, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", "client-1")
	form.Set("code_verifier", testVerifier)

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control missing no-store")
	}
	var resp TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if resp.IDToken == "" {
		t.Errorf("id_token missing")
	}
	if resp.RefreshToken == "" {
		t.Errorf("refresh_token missing (offline_access was granted)")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if !strings.Contains(resp.Scope, "openid") {
		t.Errorf("scope = %q", resp.Scope)
	}

	// access token must verify against JWKS
	tok, err := issuer.VerifyToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken(access): %v", err)
	}
	if tok.Subject() != "u-1" {
		t.Errorf("sub = %q", tok.Subject())
	}

	// id token carries nonce, at_hash, auth_time
	idTok, err := issuer.VerifyToken(context.Background(), resp.IDToken)
	if err != nil {
		t.Fatalf("VerifyToken(id): %v", err)
	}
	if nonce, _ := idTok.Get("nonce"); nonce != "nonce-abc" {
		t.Errorf("nonce = %v, want nonce-abc", nonce)
	}
	atHash, _ := idTok.Get("at_hash")
	if atHash == nil {
		t.Fatalf("id_token missing at_hash")
	}
	if atHash.(string) != token.HashAccessToken(resp.AccessToken) {
		t.Errorf("at_hash mismatch: %v vs %v", atHash, token.HashAccessToken(resp.AccessToken))
	}
	if _, ok := idTok.Get("auth_time"); !ok {
		t.Errorf("id_token missing auth_time")
	}

	// Refresh token must be stored
	all, _ := rt.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if all.TotalCount != 1 {
		t.Errorf("refresh tokens in store = %d, want 1", all.TotalCount)
	}
}

func TestAuthCode_Handle_RejectsReplay(t *testing.T) {
	g, ac, _, _, _, _, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", "client-1")
	form.Set("code_verifier", testVerifier)

	rr1 := httptest.NewRecorder()
	g.Handle(context.Background(), rr1, client, form)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first exchange: status = %d, want 200", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	g.Handle(context.Background(), rr2, client, form)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400", rr2.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr2.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("replay error = %q", body.Error)
	}
}

func TestAuthCode_Handle_RejectsBadPKCE(t *testing.T) {
	g, ac, _, _, _, _, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", "client-1")
	form.Set("code_verifier", "wrong-verifier-12345678901234567890123456789012")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

func TestAuthCode_Handle_RejectsRedirectMismatch(t *testing.T) {
	g, ac, _, _, _, _, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://attacker.example/cb")
	form.Set("client_id", "client-1")
	form.Set("code_verifier", testVerifier)

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

// TestAuthCode_Handle_ClientIDMismatch_ReturnsInvalidClient401: when
// the form's client_id does not match the client the dispatcher
// authenticated, the response must be 401 invalid_client, not
// 400 invalid_grant. The cause is a client identity mismatch
// (RFC 6749 §5.2), not a grant problem. The dispatcher normally
// prevents this path, but the grant keeps a defensive check.
func TestAuthCode_Handle_ClientIDMismatch_ReturnsInvalidClient401(t *testing.T) {
	g, ac, _, _, _, _, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", "different-client")
	form.Set("code_verifier", testVerifier)

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", body.Error)
	}
}

func TestAuthCode_Handle_RejectsExpiredCode(t *testing.T) {
	g, ac, _, _, _, _, client := newTestGrant(t)
	code := mintAuthCode(t, ac, &memory.ClientStore{}, g.Clock)

	// Advance the clock past the code's expiry.
	if fc, ok := g.Clock.(*clock.FakeClock); ok {
		fc.Advance(2 * time.Minute)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", "client-1")
	form.Set("code_verifier", testVerifier)

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if !strings.Contains(body.ErrorDescription, "expired") {
		t.Errorf("error_description = %q, want 'expired'", body.ErrorDescription)
	}
}
