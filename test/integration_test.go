// Package test contains end-to-end integration tests that exercise the
// real router with in-memory stores. The tests follow the verification
// scenario in BUILD_PROMPT.md §"Verification".
package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/oidc"
	"go-authserver/internal/oidc/grants"
	"go-authserver/internal/server"
	"go-authserver/internal/session"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"
)

const (
	testIssuer      = "https://auth.example.com"
	testClientID    = "demo-public"
	testRedirectURI = "https://app.example/callback"
	testUser        = "demo"
	testPassword    = "demo"
	testVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testState       = "state-xyz"
	testNonce       = "nonce-from-client"
)

func testChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// testServer is a fully-wired router against in-memory stores, ready to
// serve httptest requests.
type testServer struct {
	srv           *httptest.Server
	clk           *clock.FakeClock
	clients       *memory.ClientStore
	refreshTokens *memory.RefreshTokenStore
	auditLogs     *memory.AuditLogStore
	issuer        *token.Issuer
	client        *http.Client
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	scopes := memory.NewScopeStore()
	clients := memory.NewClientStore()
	sessions := memory.NewSessionStore()
	authCodes := memory.NewAuthorizationCodeStore()
	refreshTokens := memory.NewRefreshTokenStore()
	users := memory.NewUserStore()
	auditLogs := memory.NewAuditLogStore()
	keys := memory.NewSigningKeyStore()
	tracker := memory.NewLoginAttemptTracker(clk.Now)

	for _, s := range []domain.Scope{
		{Name: "openid"}, {Name: "profile"}, {Name: "email"}, {Name: "offline_access"},
	} {
		_ = scopes.Store(context.Background(), &s)
	}
	_ = clients.Store(context.Background(), &domain.Client{
		ClientID:                testClientID,
		DisplayName:             "Demo Public Client",
		RedirectURIs:            []string{testRedirectURI},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	})
	_ = users.Add(domain.UserInfo{
		UserID: "u-demo",
		Claims: map[string]any{
			"preferred_username": testUser,
			"name":               "Demo User",
			"email":              "demo@example.com",
			"email_verified":     true,
		},
	}, testPassword)

	km := token.NewKeyManager(keys, clk)
	issuer := token.NewIssuer(testIssuer, km, clk)
	issuer.DefaultAccessTokenLifetime = time.Hour
	issuer.DefaultIDTokenLifetime = time.Hour

	cookieMgr := session.NewCookieManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		session.CookieConfig{Name: ".auth.session", Path: "/"},
	)

	loginTmpl := template.Must(template.New("login").Parse(oidc.LoginTemplate()))
	logoutTmpl := template.Must(template.New("logout").Parse(oidc.LogoutTemplate()))

	loginHandler := &oidc.LoginHandler{
		Cfg: oidc.LoginConfig{
			IssuerURL:       testIssuer,
			LoginPath:       "/login",
			AuthorizePath:   "/connect/authorize",
			SessionLifetime: time.Hour,
		},
		Users:    users,
		Sessions: sessions,
		Cookies:  cookieMgr,
		Tracker:  tracker,
		Clock:    clk,
		Logger:   logger,
		Template: loginTmpl,
	}
	authorizeHandler := &oidc.AuthorizeHandler{
		Cfg: oidc.AuthorizeConfig{
			IssuerURL:        testIssuer,
			LoginPath:        "/login",
			AuthorizePath:    "/connect/authorize",
			AuthCodeLifetime: time.Minute,
			RequirePKCE:      true,
		},
		Clients:   clients,
		AuthCodes: authCodes,
		Sessions:  sessions,
		Users:     users,
		Cookies:   cookieMgr,
		Issuer:    issuer,
		Clock:     clk,
		Logger:    logger,
	}
	tokenHandler := &oidc.TokenHandler{
		AuthCode: &grants.AuthCodeGrant{
			AuthCodes:     authCodes,
			RefreshTokens: refreshTokens,
			Clients:       clients,
			Users:         users,
			Issuer:        issuer,
			Clock:         clk,
			Cfg: grants.AuthCodeConfig{
				AccessTokenLifetime:          time.Hour,
				IDTokenLifetime:              time.Hour,
				RefreshTokenLifetime:         24 * time.Hour,
				RefreshTokenAbsoluteLifetime: 24 * time.Hour,
			},
		},
		Refresh: &grants.RefreshGrant{
			RefreshTokens: refreshTokens,
			Sessions:      sessions,
			Clients:       clients,
			Users:         users,
			AuditLogs:     auditLogs,
			Issuer:        issuer,
			Clock:         clk,
			Logger:        logger,
			Cfg: grants.RefreshConfig{
				AccessTokenLifetime:          time.Hour,
				IDTokenLifetime:              time.Hour,
				RefreshTokenLifetime:         24 * time.Hour,
				RefreshTokenAbsoluteLifetime: 24 * time.Hour,
				DetectReuse:                  true,
			},
		},
	}
	logoutHandler := &oidc.LogoutHandler{
		Cfg: oidc.LogoutConfig{
			IssuerURL:             testIssuer,
			AuthorizePath:         "/connect/authorize",
			LogoutPath:            "/logout",
			PostLogoutRedirectURI: "/",
		},
		Cookies:       cookieMgr,
		Sessions:      sessions,
		RefreshTokens: refreshTokens,
		Clients:       clients,
		Issuer:        issuer,
		Clock:         clk,
		Logger:        logger,
		Confirm:       logoutTmpl,
	}

	handlers := server.Handlers{
		Login:     loginHandler,
		Logout:    logoutHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		UserInfo:  oidc.NewUserInfoHandler(issuer, users, logger),
		Revoke: &oidc.RevokeHandler{
			RefreshTokens: refreshTokens,
			Clients:       clients,
			Now:           clk.Now,
			Logger:        logger,
		},
		Discovery: oidc.NewDiscoveryHandler(testIssuer, scopes),
		JWKS:      oidc.NewJWKSHandler(issuer),
		Health:    server.NewHealth(),
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL:     testIssuer,
			RequireHTTPS:  false,
			LoginPath:     "/login",
			LogoutPath:    "/logout",
			AuthorizePath: "/connect/authorize",
			TokenPath:     "/connect/token",
			UserInfoPath:  "/connect/userinfo",
			RevokePath:    "/connect/revoke",
			JWKSPath:      "/.well-known/jwks.json",
			DiscoveryPath: "/.well-known/openid-configuration",
			HealthPath:    "/healthz",
		},
		server.RouterOptions{Logger: logger},
		handlers,
	)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// http.Client with redirects disabled so tests can inspect 302 responses
	// (e.g. login → /connect/authorize → /connect/token flow).
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &testServer{
		srv:           srv,
		clk:           clk,
		clients:       clients,
		refreshTokens: refreshTokens,
		auditLogs:     auditLogs,
		issuer:        issuer,
		client:        client,
	}
}

func (ts *testServer) URL(path string) string {
	return ts.srv.URL + path
}

// httpClient with a shared cookie jar would be nicer; for this test a
// single request/response pair is enough and we pluck the Set-Cookie
// header directly.
func (ts *testServer) do(t *testing.T, method, path string, form url.Values, cookies []*http.Cookie) (*http.Response, error) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, ts.URL(path), body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return ts.client.Do(req)
}

func TestE2E_HappyPath(t *testing.T) {
	ts := newTestServer(t)

	// 1. GET /connect/authorize without session → 302 to /login?returnUrl=...
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, nil)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?returnUrl=") {
		t.Fatalf("Location = %q, want /login?returnUrl=...", loc)
	}
	ru, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse login url: %v", err)
	}
	returnURL, _ := url.QueryUnescape(ru.Query().Get("returnUrl"))
	if !sameURL(returnURL, authorizeURL) {
		t.Errorf("returnURL = %q, want %q", returnURL, authorizeURL)
	}

	// 2. GET /login → form with csrf_token + csrf cookie.
	resp, err = ts.do(t, http.MethodGet, "/login", nil, nil)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login GET status = %d", resp.StatusCode)
	}
	csrfToken := extractInputValue(t, string(bodyBytes), `name="csrf_token"`)
	csrfCookie := findCookie(resp.Cookies(), "_csrf")

	// 3. POST /login with valid creds → 302 to returnUrl, session cookie set.
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("username", testUser)
	form.Set("password", testPassword)
	form.Set("returnUrl", returnURL)
	resp, err = ts.do(t, http.MethodPost, "/login", form, []*http.Cookie{csrfCookie})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	lb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login POST status = %d, want 302; body=%s; headers=%v", resp.StatusCode, lb, resp.Header)
	}
	if loc := resp.Header.Get("Location"); !sameURL(loc, authorizeURL) {
		t.Errorf("Location = %q, want %q", loc, authorizeURL)
	}
	sessionCookie := findCookie(resp.Cookies(), ".auth.session")
	if sessionCookie == nil {
		t.Fatalf("session cookie not set; headers=%v", resp.Header)
	}

	// 4. GET /connect/authorize with session → 302 to redirect_uri?code=...&state=...
	resp, err = ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("GET authorize (with session): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	cb := resp.Header.Get("Location")
	if !strings.HasPrefix(cb, testRedirectURI+"?") {
		t.Fatalf("Location = %q, want redirect_uri?...", cb)
	}
	cbURL, _ := url.Parse(cb)
	code := cbURL.Query().Get("code")
	state := cbURL.Query().Get("state")
	if code == "" {
		t.Fatalf("code missing in callback: %s", cb)
	}
	if state != testState {
		t.Errorf("state = %q, want %q", state, testState)
	}

	// 5. POST /connect/token with code + verifier → 200 access + id + refresh
	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testClientID)
	form.Set("code_verifier", testVerifier)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	tokenBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200; body=%s", resp.StatusCode, tokenBody)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokenBody, &tokenResp); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Errorf("access_token empty")
	}
	if tokenResp.IDToken == "" {
		t.Errorf("id_token empty")
	}
	if tokenResp.RefreshToken == "" {
		t.Errorf("refresh_token empty")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tokenResp.TokenType)
	}

	// 6. Verify id_token against JWKS + assertions.
	// Get JWKS
	jwksResp, err := ts.do(t, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	jwksBody, _ := io.ReadAll(jwksResp.Body)
	jwksResp.Body.Close()
	if !strings.Contains(string(jwksBody), `"kty":"RSA"`) {
		t.Errorf("JWKS missing RSA key: %s", jwksBody)
	}
	if strings.Contains(string(jwksBody), `"d":`) {
		t.Errorf("JWKS leaked private exponent: %s", jwksBody)
	}

	// Verify ID token
	idTok, err := ts.issuer.VerifyToken(context.Background(), tokenResp.IDToken)
	if err != nil {
		t.Fatalf("VerifyToken(id): %v", err)
	}
	if idTok.Subject() != "u-demo" {
		t.Errorf("sub = %q, want u-demo", idTok.Subject())
	}
	if nonce, _ := idTok.Get("nonce"); nonce != testNonce {
		t.Errorf("nonce = %v, want %q", nonce, testNonce)
	}
	atHash, _ := idTok.Get("at_hash")
	wantAtHash := token.HashAccessToken(tokenResp.AccessToken)
	if atHash != wantAtHash {
		t.Errorf("at_hash mismatch: got %v want %v", atHash, wantAtHash)
	}
	if _, ok := idTok.Get("auth_time"); !ok {
		t.Errorf("id_token missing auth_time")
	}

	// Verify access token
	accessTok, err := ts.issuer.VerifyToken(context.Background(), tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken(access): %v", err)
	}
	if accessTok.Subject() != "u-demo" {
		t.Errorf("access sub = %q", accessTok.Subject())
	}

	// 7. Replay attack: same code again → invalid_grant
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	replayBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400; body=%s", resp.StatusCode, replayBody)
	}
	var replayErr struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(replayBody, &replayErr)
	if replayErr.Error != "invalid_grant" {
		t.Errorf("replay error = %q, want invalid_grant", replayErr.Error)
	}
}

func TestE2E_BadPKCEVerifier(t *testing.T) {
	ts := newTestServer(t)
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, "", "", testChallenge())

	// login
	sessionCookie := loginAs(t, ts, "demo", "demo", authorizeURL)

	// authorize
	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	cb := resp.Header.Get("Location")
	resp.Body.Close()
	code := mustQuery(t, cb, "code")

	// token with WRONG verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testClientID)
	form.Set("code_verifier", "wrong-verifier-1234567890123456789012345678901X")
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var errBody struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errBody)
	if errBody.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errBody.Error)
	}
}

func TestE2E_MismatchedRedirectURI(t *testing.T) {
	ts := newTestServer(t)
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, "", "", testChallenge())
	sessionCookie := loginAs(t, ts, "demo", "demo", authorizeURL)

	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	cb := resp.Header.Get("Location")
	resp.Body.Close()
	code := mustQuery(t, cb, "code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://attacker.example/cb") // different from issued URI
	form.Set("client_id", testClientID)
	form.Set("code_verifier", testVerifier)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestE2E_InvalidRedirectURIOnAuthorize_NotRedirected(t *testing.T) {
	ts := newTestServer(t)
	// Redirect_uri not registered → must NOT 302 to the unvalidated URI.
	u := buildAuthorizeURLRaw(testClientID, "https://attacker.example/cb", testState, testNonce, testChallenge())
	resp, err := ts.do(t, http.MethodGet, u, nil, nil)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "https://attacker.example/") {
			t.Fatalf("authorize redirected to unvalidated URI: %s", loc)
		}
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestE2E_DiscoveryDocument(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		JWKSURI                       string   `json:"jwks_uri"`
		ResponseTypesSupported        []string `json:"response_types_supported"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != testIssuer {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.AuthorizationEndpoint != testIssuer+"/connect/authorize" {
		t.Errorf("authorization_endpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != testIssuer+"/connect/token" {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}
	if doc.JWKSURI != testIssuer+"/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
	for _, s := range []string{"code"} {
		if !sliceContains(doc.ResponseTypesSupported, s) {
			t.Errorf("response_types_supported missing %q", s)
		}
	}
	for _, s := range []string{"S256"} {
		if !sliceContains(doc.CodeChallengeMethodsSupported, s) {
			t.Errorf("code_challenge_methods_supported missing %q", s)
		}
	}
}

// --- M4: refresh, userinfo, revoke, logout, expired-code negative path ---

// tokenResponse mirrors the JSON shape of the /connect/token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// exchangeCodeForTokens runs the full happy path through the HTTP layer
// and returns the parsed token response + the session cookie. Centralised
// so the M4 tests can focus on what they exercise.
func exchangeCodeForTokens(t *testing.T, ts *testServer) (tokenResponse, *http.Cookie) {
	t.Helper()
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sessionCookie := loginAs(t, ts, testUser, testPassword, authorizeURL)

	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	code := mustQuery(t, resp.Header.Get("Location"), "code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testClientID)
	form.Set("code_verifier", testVerifier)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode token: %v; body=%s", err, body)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.IDToken == "" {
		t.Fatalf("token response missing fields: %+v", tr)
	}
	return tr, sessionCookie
}

func TestE2E_RefreshGrant_Rotates(t *testing.T) {
	ts := newTestServer(t)
	first, _ := exchangeCodeForTokens(t, ts)

	// Refresh once → new tokens.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", first.RefreshToken)
	form.Set("client_id", testClientID)
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("refresh missing no-store")
	}
	var second tokenResponse
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if second.AccessToken == "" || second.AccessToken == first.AccessToken {
		t.Errorf("access token not rotated")
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Errorf("refresh token not rotated")
	}
	if second.IDToken == "" {
		t.Errorf("id_token missing on refresh")
	}
	// The rotated refresh token works; the old one is consumed.
	form.Set("refresh_token", second.RefreshToken)
	resp, _ = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("rotated refresh status = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_RefreshGrant_ReuseRevokesChain(t *testing.T) {
	ts := newTestServer(t)
	first, _ := exchangeCodeForTokens(t, ts)

	// First refresh: ok.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", first.RefreshToken)
	form.Set("client_id", testClientID)
	resp, _ := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200", resp.StatusCode)
	}

	// Replay the ORIGINAL token: reuse detected.
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("reuse request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", er.Error)
	}
	if !strings.Contains(strings.ToLower(er.ErrorDescription), "reuse") {
		t.Errorf("error_description = %q, want it to mention reuse", er.ErrorDescription)
	}

	// The chain is revoked: an audit log entry exists.
	logs, _ := ts.auditLogs.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if logs.TotalCount < 1 {
		t.Errorf("expected at least 1 audit log entry, got %d", logs.TotalCount)
	} else if logs.Items[0].Action != grants.RefreshTokenReuseAudit {
		t.Errorf("audit action = %q, want %q", logs.Items[0].Action, grants.RefreshTokenReuseAudit)
	}
}

func TestE2E_UserInfo_BearerGET(t *testing.T) {
	ts := newTestServer(t)
	tr, _ := exchangeCodeForTokens(t, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL("/connect/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("userinfo GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("userinfo missing no-store")
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims["sub"] != "u-demo" {
		t.Errorf("sub = %v, want u-demo", claims["sub"])
	}
	// scope includes profile + email → those claims must be present.
	if _, ok := claims["email"]; !ok {
		t.Errorf("email claim missing")
	}
	if _, ok := claims["name"]; !ok {
		t.Errorf("name claim missing")
	}
}

func TestE2E_UserInfo_BearerPOST(t *testing.T) {
	ts := newTestServer(t)
	tr, _ := exchangeCodeForTokens(t, ts)

	form := url.Values{}
	form.Set("access_token", tr.AccessToken)
	resp, err := ts.do(t, http.MethodPost, "/connect/userinfo", form, nil)
	if err != nil {
		t.Fatalf("userinfo POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"sub":"u-demo"`) {
		t.Errorf("body missing sub: %s", body)
	}
}

func TestE2E_UserInfo_MissingToken401(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/connect/userinfo", nil, nil)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `Bearer`) {
		t.Errorf("WWW-Authenticate = %q, want Bearer", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestE2E_UserInfo_InvalidToken401(t *testing.T) {
	ts := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL("/connect/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestE2E_Revoke_OwnRefreshToken(t *testing.T) {
	ts := newTestServer(t)
	tr, _ := exchangeCodeForTokens(t, ts)

	form := url.Values{}
	form.Set("token", tr.RefreshToken)
	form.Set("client_id", testClientID)
	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Now refreshing with the revoked token must fail.
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", tr.RefreshToken)
	form2.Set("client_id", testClientID)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form2, nil)
	if err != nil {
		t.Fatalf("refresh after revoke: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh after revoke status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", er.Error)
	}
}

func TestE2E_Revoke_UnknownTokenStillReturns200(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{}
	form.Set("token", "definitely-not-a-real-token")
	form.Set("client_id", testClientID)
	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (spec: always 200)", resp.StatusCode)
	}
}

func TestE2E_Revoke_UnknownClientReturns401(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{}
	form.Set("token", "x")
	form.Set("client_id", "no-such-client")
	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `Basic`) {
		t.Errorf("WWW-Authenticate = %q, want Basic", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestE2E_Logout_GetRedirectsToConfirm(t *testing.T) {
	ts := newTestServer(t)
	tr, _ := exchangeCodeForTokens(t, ts)
	_ = tr

	resp, err := ts.do(t, http.MethodGet, "/connect/logout", nil, nil)
	if err != nil {
		t.Fatalf("logout GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/logout") {
		t.Errorf("Location = %q, want /logout...", loc)
	}
}

func TestE2E_Logout_ConfirmPage(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/logout", nil, nil)
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	csrfToken := extractInputValue(t, string(body), `name="csrf_token"`)
	if csrfToken == "" {
		t.Fatalf("csrf_token missing from confirm page: %s", body)
	}
	csrfCookie := findCookie(resp.Cookies(), "_logout_csrf")
	if csrfCookie == nil {
		t.Fatalf("logout CSRF cookie not set")
	}
}

func TestE2E_Logout_PostRevokesAndClears(t *testing.T) {
	ts := newTestServer(t)
	tr, sessionCookie := exchangeCodeForTokens(t, ts)

	// Load the confirm page to get a CSRF cookie + token.
	resp, err := ts.do(t, http.MethodGet, "/logout", nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrfToken := extractInputValue(t, string(body), `name="csrf_token"`)
	csrfCookie := findCookie(resp.Cookies(), "_logout_csrf")
	if csrfCookie == nil {
		t.Fatalf("logout CSRF cookie not set")
	}

	// POST /connect/logout with CSRF + confirm=yes.
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("post_logout_redirect_uri", "/")
	form.Set("client_id", testClientID)
	form.Set("confirm", "yes")
	form.Set("state", "abc")
	resp, err = ts.do(t, http.MethodPost, "/connect/logout", form, []*http.Cookie{sessionCookie, csrfCookie})
	if err != nil {
		t.Fatalf("POST logout: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", resp.StatusCode, rb)
	}
	// State must be appended to the redirect.
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "state=abc") {
		t.Errorf("Location = %q, want it to carry state=abc", loc)
	}
	// Session cookie cleared.
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == ".auth.session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("session cookie not cleared; cookies=%v", resp.Cookies())
	}

	// The refresh token from this session must now be revoked.
	rt, _ := ts.refreshTokens.FindByHash(context.Background(), token.HashToken(tr.RefreshToken))
	if rt == nil || rt.RevokedAt == nil {
		t.Errorf("refresh token not revoked after logout; rt=%+v", rt)
	}
}

func TestE2E_Logout_PostRejectsBadCSRF(t *testing.T) {
	ts := newTestServer(t)
	_, sessionCookie := exchangeCodeForTokens(t, ts)

	// No CSRF cookie at all → POST is rejected.
	form := url.Values{}
	form.Set("csrf_token", "totally-bogus")
	form.Set("confirm", "yes")
	resp, err := ts.do(t, http.MethodPost, "/connect/logout", form, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("POST logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (back to /logout)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/logout?error=") {
		t.Errorf("Location = %q, want /logout?error=...", loc)
	}
}

func TestE2E_Logout_PostCancelDoesNotRevoke(t *testing.T) {
	ts := newTestServer(t)
	tr, sessionCookie := exchangeCodeForTokens(t, ts)

	resp, err := ts.do(t, http.MethodGet, "/logout", nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	resp.Body.Close()
	csrfCookie := findCookie(resp.Cookies(), "_logout_csrf")

	form := url.Values{}
	form.Set("csrf_token", csrfCookie.Value)
	form.Set("confirm", "no")
	resp, err = ts.do(t, http.MethodPost, "/connect/logout", form, []*http.Cookie{sessionCookie, csrfCookie})
	if err != nil {
		t.Fatalf("POST logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	// Refresh token must still be valid (cancel did not revoke).
	rtForm := url.Values{}
	rtForm.Set("grant_type", "refresh_token")
	rtForm.Set("refresh_token", tr.RefreshToken)
	rtForm.Set("client_id", testClientID)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", rtForm, nil)
	if err != nil {
		t.Fatalf("refresh after cancel: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("refresh after cancel status = %d, want 200", resp.StatusCode)
	}
}

// TestE2E_ExpiredCode_Rejected: T4.5 negative-path coverage for the
// expired-code case through the real HTTP layer. The unit test in
// grants/authcode_test.go covers the same path against the grant
// directly; this is the integration-level mirror.
func TestE2E_ExpiredCode_Rejected(t *testing.T) {
	ts := newTestServer(t)
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sessionCookie := loginAs(t, ts, testUser, testPassword, authorizeURL)

	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	code := mustQuery(t, resp.Header.Get("Location"), "code")

	// Advance the clock past the auth-code lifetime (1 minute in the
	// test config). All subsequent tokens will be expired.
	ts.clk.Advance(2 * time.Minute)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testClientID)
	form.Set("code_verifier", testVerifier)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", er.Error)
	}
	if !strings.Contains(strings.ToLower(er.ErrorDescription), "expir") {
		t.Errorf("error_description = %q, want it to mention expiry", er.ErrorDescription)
	}
}

// --- helpers ---

func buildAuthorizeURL(clientID, redirectURI, state, nonce, challenge string) string {
	return buildAuthorizeURLRaw(clientID, redirectURI, state, nonce, challenge)
}

func buildAuthorizeURLRaw(clientID, redirectURI, state, nonce, challenge string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", "openid profile email offline_access")
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	if state != "" {
		v.Set("state", state)
	}
	if nonce != "" {
		v.Set("nonce", nonce)
	}
	return "/connect/authorize?" + v.Encode()
}

func loginAs(t *testing.T, ts *testServer, user, pass, returnURL string) *http.Cookie {
	t.Helper()
	resp, err := ts.do(t, http.MethodGet, "/login?returnUrl="+url.QueryEscape(returnURL), nil, nil)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrfToken := extractInputValue(t, string(body), `name="csrf_token"`)
	csrfCookie := findCookie(resp.Cookies(), "_csrf")

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("username", user)
	form.Set("password", pass)
	form.Set("returnUrl", returnURL)
	resp, err = ts.do(t, http.MethodPost, "/login", form, []*http.Cookie{csrfCookie})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login POST status = %d, want 302", resp.StatusCode)
	}
	sess := findCookie(resp.Cookies(), ".auth.session")
	if sess == nil {
		t.Fatalf("session cookie not set")
	}
	return sess
}

func extractInputValue(t *testing.T, body, attr string) string {
	t.Helper()
	i := strings.Index(body, attr)
	if i < 0 {
		t.Fatalf("attribute %q not found in body", attr)
	}
	rest := body[i:]
	j := strings.Index(rest, `value="`)
	if j < 0 {
		t.Fatalf("value attribute not found after %q", attr)
	}
	rest = rest[j+len(`value="`):]
	k := strings.Index(rest, `"`)
	if k < 0 {
		t.Fatalf("closing quote not found for value attribute")
	}
	return rest[:k]
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	v := u.Query().Get(key)
	if v == "" {
		t.Fatalf("query %q missing in %s", key, raw)
	}
	return v
}

func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// sameURL compares two URL strings by their parsed query params, so the
// test is not sensitive to whether the path was encoded with %20 or +.
func sameURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return a == b
	}
	if ua.Path != ub.Path {
		return false
	}
	qa := ua.Query()
	qb := ub.Query()
	if len(qa) != len(qb) {
		return false
	}
	for k, vs := range qa {
		vb := qb[k]
		if len(vb) != len(vs) {
			return false
		}
		for i := range vs {
			if vs[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

// touch unused import to keep formatting happy in case fmt is dropped.
var _ = fmt.Sprintf
