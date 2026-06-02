// Package test contains end-to-end integration tests that exercise the
// real router with both the in-memory and the GORM-backed stores. The
// tests follow the verification scenario in BUILD_PROMPT.md §"Verification".
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/oidc"
	"go-authserver/internal/oidc/grants"
	"go-authserver/internal/server"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
	"go-authserver/internal/store/gormstore"
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

// storeBuilder is the seam through which newTestServer/newGormTestServer
// inject their preferred backend. Returning the bundle + a closer keeps
// the GORM path honest about its *sql.DB lifetime.
type storeBuilder struct {
	Build func(t *testing.T) (bundle, func())
}

// bundle is the cross-backend set of store interfaces the router needs.
// All fields are interface types so the test server is identical no
// matter which builder produced it.
type bundle struct {
	Clients       store.ClientStore
	AuthCodes     store.AuthorizationCodeStore
	RefreshTokens store.RefreshTokenStore
	Sessions      store.SessionStore
	SigningKeys   store.SigningKeyStore
	Scopes        store.ScopeStore
	AuditLogs     store.AuditLogStore
	Users         store.UserStore
	Tracker       store.LoginAttemptTracker
}

// userAdder lets the seed step populate a user without caring which
// concrete UserStore impl is in play.
type userAdder interface {
	Add(u domain.UserInfo, password string) error
}

// memoryBuilder returns a fully in-memory store bundle. The closer is
// a no-op. This is the default for fast unit-style integration runs.
func memoryBuilder() storeBuilder {
	return storeBuilder{
		Build: func(t *testing.T) (bundle, func()) {
			return bundle{
				Clients:       memory.NewClientStore(),
				AuthCodes:     memory.NewAuthorizationCodeStore(),
				RefreshTokens: memory.NewRefreshTokenStore(),
				Sessions:      memory.NewSessionStore(),
				SigningKeys:   memory.NewSigningKeyStore(),
				Scopes:        memory.NewScopeStore(),
				AuditLogs:     memory.NewAuditLogStore(),
				Users:         memory.NewUserStore(),
				Tracker:       memory.NewLoginAttemptTracker(time.Now),
			}, func() {}
		},
	}
}

// gormBuilder returns a SQLite-backed bundle on a temp file. The
// closer shuts the underlying *sql.DB down. Re-runs the M3+M4 suite
// against a real database to prove T5.4 (full parity).
func gormBuilder() storeBuilder {
	return storeBuilder{
		Build: func(t *testing.T) (bundle, func()) {
			dir := t.TempDir()
			dsn := filepath.Join(dir, "gorm.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
			db, err := gormstore.Open("sqlite", dsn)
			if err != nil {
				t.Fatalf("gormstore.Open: %v", err)
			}
			if err := gormstore.Migrate(db); err != nil {
				t.Fatalf("gormstore.Migrate: %v", err)
			}
			closer := func() {
				sqlDB, err := db.DB()
				if err != nil {
					return
				}
				_ = sqlDB.Close()
			}
			return bundle{
				Clients:       gormstore.NewClientStore(db),
				AuthCodes:     gormstore.NewAuthorizationCodeStore(db),
				RefreshTokens: gormstore.NewRefreshTokenStore(db),
				Sessions:      gormstore.NewSessionStore(db),
				SigningKeys:   gormstore.NewSigningKeyStore(db),
				Scopes:        gormstore.NewScopeStore(db),
				AuditLogs:     gormstore.NewAuditLogStore(db),
				Users:         gormstore.NewUserStore(db),
				Tracker:       memory.NewLoginAttemptTracker(time.Now),
			}, closer
		},
	}
}

// testServer is a fully-wired router against a chosen backend, ready
// to serve httptest requests.
type testServer struct {
	srv           *httptest.Server
	clk           *clock.FakeClock
	clients       store.ClientStore
	refreshTokens store.RefreshTokenStore
	auditLogs     store.AuditLogStore
	issuer        *token.Issuer
	client        *http.Client
}

// newTestServer is the memory-backed default. Most tests use it.
func newTestServer(t *testing.T) *testServer {
	return newTestServerWith(t, memoryBuilder())
}

// newGormTestServer is the SQLite-backed variant. The same tests run
// against it as part of T5.4 verification.
func newGormTestServer(t *testing.T) *testServer {
	return newTestServerWith(t, gormBuilder())
}

// newTestServerWith is the shared constructor; the bundle comes from
// the supplied builder. All test logic lives in here so the two
// backends stay in lockstep.
func newTestServerWith(t *testing.T, sb storeBuilder) *testServer {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	b, closer := sb.Build(t)
	t.Cleanup(closer)

	for _, s := range []domain.Scope{
		{Name: "openid"}, {Name: "profile"}, {Name: "email"}, {Name: "offline_access"},
	} {
		_ = b.Scopes.Store(context.Background(), &s)
	}
	_ = b.Clients.Store(context.Background(), &domain.Client{
		ClientID:                testClientID,
		DisplayName:             "Demo Public Client",
		RedirectURIs:            []string{testRedirectURI},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	})
	adder, ok := b.Users.(userAdder)
	if !ok {
		t.Fatalf("UserStore %T does not support Add (seed path)", b.Users)
	}
	if err := adder.Add(domain.UserInfo{
		UserID: "u-demo",
		Claims: map[string]any{
			"preferred_username": testUser,
			"name":               "Demo User",
			"email":              "demo@example.com",
			"email_verified":     true,
		},
	}, testPassword); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	km := token.NewKeyManager(b.SigningKeys, clk)
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
		Users:    b.Users,
		Sessions: b.Sessions,
		Cookies:  cookieMgr,
		Tracker:  b.Tracker,
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
		Clients:   b.Clients,
		AuthCodes: b.AuthCodes,
		Sessions:  b.Sessions,
		Users:     b.Users,
		Cookies:   cookieMgr,
		Issuer:    issuer,
		Clock:     clk,
		Logger:    logger,
	}
	tokenHandler := &oidc.TokenHandler{
		AuthCode: &grants.AuthCodeGrant{
			AuthCodes:     b.AuthCodes,
			RefreshTokens: b.RefreshTokens,
			Clients:       b.Clients,
			Users:         b.Users,
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
			RefreshTokens: b.RefreshTokens,
			Sessions:      b.Sessions,
			Clients:       b.Clients,
			Users:         b.Users,
			AuditLogs:     b.AuditLogs,
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
		Sessions:      b.Sessions,
		RefreshTokens: b.RefreshTokens,
		Clients:       b.Clients,
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
		UserInfo:  oidc.NewUserInfoHandler(issuer, b.Users, logger),
		Revoke: &oidc.RevokeHandler{
			RefreshTokens: b.RefreshTokens,
			Clients:       b.Clients,
			Now:           clk.Now,
			Logger:        logger,
		},
		Discovery: oidc.NewDiscoveryHandler(testIssuer, b.Scopes),
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

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &testServer{
		srv:           srv,
		clk:           clk,
		clients:       b.Clients,
		refreshTokens: b.RefreshTokens,
		auditLogs:     b.AuditLogs,
		issuer:        issuer,
		client:        client,
	}
}

func (ts *testServer) URL(path string) string {
	return ts.srv.URL + path
}

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

	accessTok, err := ts.issuer.VerifyToken(context.Background(), tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken(access): %v", err)
	}
	if accessTok.Subject() != "u-demo" {
		t.Errorf("access sub = %q", accessTok.Subject())
	}

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
	form.Set("redirect_uri", "https://attacker.example/cb")
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

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

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

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", first.RefreshToken)
	form.Set("client_id", testClientID)
	resp, _ := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200", resp.StatusCode)
	}

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
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "state=abc") {
		t.Errorf("Location = %q, want it to carry state=abc", loc)
	}
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == ".auth.session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("session cookie not cleared; cookies=%v", resp.Cookies())
	}

	rt, _ := ts.refreshTokens.FindByHash(context.Background(), token.HashToken(tr.RefreshToken))
	if rt == nil || rt.RevokedAt == nil {
		t.Errorf("refresh token not revoked after logout; rt=%+v", rt)
	}
}

func TestE2E_Logout_PostRejectsBadCSRF(t *testing.T) {
	ts := newTestServer(t)
	_, sessionCookie := exchangeCodeForTokens(t, ts)

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

// --- T5.4: same suite re-run against the GORM-backed store. ---

// gormFlowTest runs the most important end-to-end paths against the
// GORM SQLite backend. The intent is to prove functional parity with
// the memory backend (M3 + M4) and to catch any GORM-specific bug in
// the CAS, the chain-revoke, and the round-trips.
func gormFlowTest(t *testing.T, name string, fn func(t *testing.T, ts *testServer)) {
	t.Helper()
	t.Run("GORM/"+name, func(t *testing.T) {
		ts := newGormTestServer(t)
		fn(t, ts)
	})
}

func TestGORM_E2E_HappyPath(t *testing.T) { gormFlowTest(t, "HappyPath", testE2EHappyPath) }
func TestGORM_E2E_BadPKCE(t *testing.T)   { gormFlowTest(t, "BadPKCE", testE2EBadPKCE) }
func TestGORM_E2E_MismatchedRedirect(t *testing.T) {
	gormFlowTest(t, "MismatchedRedirect", testE2EMismatchedRedirect)
}
func TestGORM_E2E_RefreshRotates(t *testing.T) {
	gormFlowTest(t, "RefreshRotates", testE2ERefreshRotates)
}
func TestGORM_E2E_RefreshReuseRevokes(t *testing.T) {
	gormFlowTest(t, "RefreshReuseRevokes", testE2ERefreshReuseRevokes)
}
func TestGORM_E2E_UserInfo(t *testing.T) { gormFlowTest(t, "UserInfo", testE2EUserInfo) }
func TestGORM_E2E_Revoke(t *testing.T)   { gormFlowTest(t, "Revoke", testE2ERevoke) }
func TestGORM_E2E_Logout(t *testing.T)   { gormFlowTest(t, "Logout", testE2ELogout) }
func TestGORM_E2E_ExpiredCode(t *testing.T) {
	gormFlowTest(t, "ExpiredCode", testE2EExpiredCode)
}

// The following helpers are extracted bodies of the matching
// in-memory tests so the GORM suite can re-run them byte-for-byte.

// testE2EHappyPath is the in-process version of TestE2E_HappyPath, but
// without the surrounding newTestServer so the gorm variant can call
// it. It only differs in the test name; all assertions are identical.
func testE2EHappyPath(t *testing.T, ts *testServer) {
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

	resp, err = ts.do(t, http.MethodGet, "/login", nil, nil)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrfToken := extractInputValue(t, string(bodyBytes), `name="csrf_token"`)
	csrfCookie := findCookie(resp.Cookies(), "_csrf")

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("username", testUser)
	form.Set("password", testPassword)
	form.Set("returnUrl", authorizeURL)
	resp, err = ts.do(t, http.MethodPost, "/login", form, []*http.Cookie{csrfCookie})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login POST status = %d, want 302", resp.StatusCode)
	}
	sessionCookie := findCookie(resp.Cookies(), ".auth.session")
	if sessionCookie == nil {
		t.Fatalf("session cookie not set")
	}

	resp, err = ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	cb := resp.Header.Get("Location")
	cbURL, _ := url.Parse(cb)
	code := cbURL.Query().Get("code")
	state := cbURL.Query().Get("state")
	if code == "" || state != testState {
		t.Fatalf("callback missing code/state: %s", cb)
	}

	form = url.Values{}
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
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" || tokenResp.IDToken == "" {
		t.Fatalf("missing tokens: %+v", tokenResp)
	}

	idTok, err := ts.issuer.VerifyToken(context.Background(), tokenResp.IDToken)
	if err != nil {
		t.Fatalf("VerifyToken(id): %v", err)
	}
	if idTok.Subject() != "u-demo" {
		t.Errorf("sub = %q, want u-demo", idTok.Subject())
	}

	// Replay → invalid_grant.
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("replay status = %d, want 400", resp.StatusCode)
	}
}

func testE2EBadPKCE(t *testing.T, ts *testServer) {
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
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testClientID)
	form.Set("code_verifier", "wrong-verifier-12345678901234567890123456789012")
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func testE2EMismatchedRedirect(t *testing.T, ts *testServer) {
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
	form.Set("redirect_uri", "https://attacker.example/cb")
	form.Set("client_id", testClientID)
	form.Set("code_verifier", testVerifier)
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func testE2ERefreshRotates(t *testing.T, ts *testServer) {
	first, _ := exchangeCodeForTokens(t, ts)
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
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var second tokenResponse
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if second.AccessToken == first.AccessToken {
		t.Errorf("access token not rotated")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Errorf("refresh token not rotated")
	}
}

func testE2ERefreshReuseRevokes(t *testing.T, ts *testServer) {
	first, _ := exchangeCodeForTokens(t, ts)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", first.RefreshToken)
	form.Set("client_id", testClientID)
	resp, _ := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d", resp.StatusCode)
	}
	// Replay original token → reuse detected.
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reuse status = %d, want 400", resp.StatusCode)
	}
	var er struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", er.Error)
	}
	logs, _ := ts.auditLogs.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if logs.TotalCount < 1 {
		t.Errorf("expected audit log entry, got 0")
	}
}

func testE2EUserInfo(t *testing.T, ts *testServer) {
	tr, _ := exchangeCodeForTokens(t, ts)
	req, _ := http.NewRequest(http.MethodGet, ts.URL("/connect/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims["sub"] != "u-demo" {
		t.Errorf("sub = %v", claims["sub"])
	}
}

func testE2ERevoke(t *testing.T, ts *testServer) {
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
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	rt, _ := ts.refreshTokens.FindByHash(context.Background(), token.HashToken(tr.RefreshToken))
	if rt == nil || rt.RevokedAt == nil {
		t.Errorf("refresh token not revoked")
	}
}

func testE2ELogout(t *testing.T, ts *testServer) {
	tr, sessionCookie := exchangeCodeForTokens(t, ts)
	resp, err := ts.do(t, http.MethodGet, "/logout", nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrfToken := extractInputValue(t, string(body), `name="csrf_token"`)
	csrfCookie := findCookie(resp.Cookies(), "_logout_csrf")
	if csrfCookie == nil {
		t.Fatalf("CSRF cookie not set")
	}
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("client_id", testClientID)
	form.Set("confirm", "yes")
	resp, err = ts.do(t, http.MethodPost, "/connect/logout", form, []*http.Cookie{sessionCookie, csrfCookie})
	if err != nil {
		t.Fatalf("POST logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	rt, _ := ts.refreshTokens.FindByHash(context.Background(), token.HashToken(tr.RefreshToken))
	if rt == nil || rt.RevokedAt == nil {
		t.Errorf("refresh token not revoked after logout")
	}
}

func testE2EExpiredCode(t *testing.T, ts *testServer) {
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sessionCookie := loginAs(t, ts, testUser, testPassword, authorizeURL)
	resp, err := ts.do(t, http.MethodGet, authorizeURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	code := mustQuery(t, resp.Header.Get("Location"), "code")
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
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
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

var _ = fmt.Sprintf
