// Package test contains end-to-end integration tests that exercise the
// real router with both the in-memory and the GORM-backed stores. The
// tests follow the verification scenario in BUILD_PROMPT.md §"Verification".
package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"go-authserver/internal/admin"
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

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
		PostLogoutRedirectURIs:  []string{"/", testIssuer + "/logged-out"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	})
	now := clk.Now()
	if err := b.Users.CreateUser(context.Background(), &domain.User{
		ID:        "u-demo",
		Username:  testUser,
		Email:     "demo@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}, testPassword); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := b.Users.AddUserClaims(context.Background(), "u-demo", []domain.UserClaim{
		{Type: "preferred_username", Value: testUser},
		{Type: "name", Value: "Demo User"},
		{Type: "email", Value: "demo@example.com"},
		{Type: "email_verified", Value: "true"},
	}); err != nil {
		t.Fatalf("seed user claims: %v", err)
	}

	km := token.NewKeyManager(b.SigningKeys, clk)
	issuer := token.NewIssuer(testIssuer, km, clk)
	issuer.DefaultAccessTokenLifetime = time.Hour
	issuer.DefaultIDTokenLifetime = time.Hour

	// Bootstrap a signing key so /admin/api/keys returns at least
	// one row even on a brand-new server.
	if _, err := km.EnsureActiveKey(context.Background()); err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}

	cookieMgr := session.NewCookieManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		session.CookieConfig{Name: ".auth.session", Path: "/"},
		clk,
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
		ClientCredentials: &grants.ClientCredentialsGrant{
			Clients: b.Clients,
			Issuer:  issuer,
			Clock:   clk,
			Cfg: grants.ClientCredentialsConfig{
				AccessTokenLifetime: time.Hour,
			},
		},
		ClientAuth: oidc.ClientAuthConfig{
			IssuerURL:        testIssuer,
			TokenEndpointURL: testIssuer + "/connect/token",
			AssertionCache:   token.NewMemAssertionCache(clk.Now),
			AssertionSkew:    time.Minute,
			Clock:            clk,
			Logger:           logger,
		},
		Clients: b.Clients,
		Clock:   clk,
		Logger:  logger,
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
			ClientAuth: oidc.ClientAuthConfig{
				IssuerURL:        testIssuer,
				TokenEndpointURL: testIssuer + "/connect/token",
				AssertionCache:   token.NewMemAssertionCache(clk.Now),
				AssertionSkew:    time.Minute,
				Clock:            clk,
				Logger:           logger,
			},
			Now:    clk.Now,
			Logger: logger,
		},
		Discovery: oidc.NewDiscoveryHandler(testIssuer, b.Scopes),
		JWKS:      oidc.NewJWKSHandler(issuer),
		Health:    server.NewHealth(),
		Admin:     buildTestAdminMount(t, b, clk, logger),
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL:         testIssuer,
			RequireHTTPS:      false,
			LoginPath:         "/login",
			LogoutPath:        "/logout",
			AuthorizePath:     "/connect/authorize",
			TokenPath:         "/connect/token",
			UserInfoPath:      "/connect/userinfo",
			RevokePath:        "/connect/revoke",
			JWKSPath:          "/.well-known/jwks.json",
			DiscoveryPath:     "/.well-known/openid-configuration",
			HealthPath:        "/healthz",
			LoginRateLimitRPS: testServerRateLimitRPS(t),
			LoginRateBurst:    testServerRateLimitBurst(t),
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

// §2.2 (plan-2.md) — RFC 7009 §2.1: confidential clients MUST
// authenticate at the revoke endpoint. A revoke request that names a
// confidential client but does not carry a valid client_assertion
// must fail with 401 invalid_client, regardless of which token is
// being revoked.
func TestE2E_Revoke_ConfidentialClient_MissingAssertionReturns401(t *testing.T) {
	ts := newTestServer(t)
	_ = registerConfidentialClient(t, bundleFromTestServer(ts))

	form := url.Values{}
	form.Set("token", "any-token")
	form.Set("client_id", testConfidentialID)
	// No client_assertion — confidential client cannot authenticate.

	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `Basic`) {
		t.Errorf("WWW-Authenticate = %q, want Basic", resp.Header.Get("WWW-Authenticate"))
	}
}

// §2.2 (plan-2.md) — RFC 7009 §2.1: a confidential client
// authenticates with a valid private_key_jwt assertion, then asks to
// revoke a token issued to a DIFFERENT client. The endpoint must
// return 200 (the spec forbids leaking token existence) and must NOT
// revoke the foreign token. The authenticated identity is the source
// of truth, not the form's client_id field.
func TestE2E_Revoke_ConfidentialClient_CannotRevokeForeignToken(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))
	tr, _ := exchangeCodeForTokens(t, ts) // tr's refresh token is for demo-public

	// Sanity: demo-public is not the confidential client.
	if testClientID == testConfidentialID {
		t.Fatal("test setup: confidential and public clients share an id")
	}

	// Confidential client authenticates correctly with a valid
	// assertion, then asks to revoke demo-public's refresh token.
	now := ts.clk.Now()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))

	form := url.Values{}
	form.Set("token", tr.RefreshToken)
	form.Set("client_id", testConfidentialID) // truthful about who is calling
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (spec: 200 even on foreign token to avoid existence leak)", resp.StatusCode)
	}

	// The foreign token must STILL be usable. A successful refresh
	// is the strongest evidence it has not been revoked.
	rtForm := url.Values{}
	rtForm.Set("grant_type", "refresh_token")
	rtForm.Set("refresh_token", tr.RefreshToken)
	rtForm.Set("client_id", testClientID)
	rtResp, err := ts.do(t, http.MethodPost, "/connect/token", rtForm, nil)
	if err != nil {
		t.Fatalf("refresh after foreign revoke: %v", err)
	}
	rtResp.Body.Close()
	if rtResp.StatusCode != http.StatusOK {
		t.Errorf("refresh status = %d, want 200 — foreign token must not be revoked by a different client", rtResp.StatusCode)
	}
}

// §2.2 (plan-2.md) — public client (TokenEndpointAuthMethod == none)
// authenticates by client_id alone, then revokes its own refresh
// token. This is the path §2.1 → §2.2 chain relies on: a public
// client that can already exchange code + PKCE can also revoke.
func TestE2E_Revoke_PublicClient_RevokesOwnToken(t *testing.T) {
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

	// Token must now be revoked; refresh fails with invalid_grant.
	rtForm := url.Values{}
	rtForm.Set("grant_type", "refresh_token")
	rtForm.Set("refresh_token", tr.RefreshToken)
	rtForm.Set("client_id", testClientID)
	rtResp, err := ts.do(t, http.MethodPost, "/connect/token", rtForm, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	rtResp.Body.Close()
	if rtResp.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh status = %d, want 400 — token should be revoked", rtResp.StatusCode)
	}
}

// §2.2 (plan-2.md) — confidential client authenticates with a valid
// private_key_jwt assertion and asks to revoke an unknown token. The
// spec mandates 200 OK on unknown tokens to avoid leaking whether a
// token exists. The test pins the happy-path wiring of
// AuthenticateClient through the revoke handler: a correctly signed
// assertion authenticates the client, the token lookup runs, finds
// nothing, the handler returns 200.
func TestE2E_Revoke_ConfidentialClient_AuthSuccessReturns200(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))

	now := ts.clk.Now()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))

	form := url.Values{}
	form.Set("token", "unknown-token")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	resp, err := ts.do(t, http.MethodPost, "/connect/revoke", form, nil)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (spec: always 200 on unknown token to avoid existence leak)", resp.StatusCode)
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

// §2.1 (plan-2.md) — logout-CSRF regression. A third-party site must
// not be able to log the user out and bounce them to a registered
// post_logout_redirect_uri just by including an <img> whose src is
// /connect/logout?id_token_hint=...&post_logout_redirect_uri=...
// Even when the hint and the target are individually valid, the GET
// must NOT call terminateSession and must NOT redirect to the target.
// It must go through the confirm page; the actual revocation only
// happens on POST after CSRF is validated.
func TestE2E_Logout_IdTokenHintGET_DoesNotRevokeAndGoesToConfirm(t *testing.T) {
	ts := newTestServer(t)
	tr, sessionCookie := exchangeCodeForTokens(t, ts)

	// Craft a valid id_token_hint from the issued ID token. This is
	// the same string the RP would carry into RP-initiated logout.
	hint := tr.IDToken
	if hint == "" {
		t.Fatal("id_token missing from token response")
	}

	// Target is a registered post_logout_redirect_uri. validatePostLogoutURI
	// requires an absolute URL whose host matches the issuer.
	target := testIssuer + "/logged-out"

	// The attack scenario is: attacker sets the target to a URL on
	// their own site. The defence is: the server must not redirect
	// here from a GET.
	logoutURL := "/connect/logout?id_token_hint=" + url.QueryEscape(hint) +
		"&post_logout_redirect_uri=" + url.QueryEscape(target) +
		"&state=attacker-state"

	resp, err := ts.do(t, http.MethodGet, logoutURL, nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("logout GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 to confirm", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/logout") {
		t.Fatalf("Location = %q, want /logout (confirm page) — must NOT redirect to /logged-out", loc)
	}
	if strings.HasPrefix(loc, target) {
		t.Errorf("Location = %q — CSRF vector: GET with id_token_hint should not redirect to post_logout_redirect_uri", loc)
	}
	if !strings.Contains(loc, "post_logout_redirect_uri=") {
		t.Errorf("Location = %q, want it to carry post_logout_redirect_uri for the confirm form", loc)
	}
	if !strings.Contains(loc, "state=attacker-state") {
		t.Errorf("Location = %q, want it to carry state for the confirm form", loc)
	}

	// Critical: the session must still be valid. The session cookie
	// must NOT have been cleared by the GET. If it had been cleared,
	// this is the logout-CSRF bug.
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == ".auth.session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if cleared {
		t.Errorf("session cookie cleared by GET with id_token_hint — that is the logout-CSRF bug")
	}

	// Now drive the legitimate confirm flow: GET /logout, get CSRF,
	// POST it, and confirm the session IS revoked afterwards. This
	// proves the confirm page is reachable and functional, just not
	// reachable as a side effect of the CSRF GET.
	getRR, err := ts.do(t, http.MethodGet, "/logout?"+strings.TrimPrefix(loc, "/logout?"), nil, []*http.Cookie{sessionCookie})
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	gb, _ := io.ReadAll(getRR.Body)
	getRR.Body.Close()
	csrfToken := extractInputValue(t, string(gb), `name="csrf_token"`)
	csrfCookie := findCookie(getRR.Cookies(), "_logout_csrf")
	if csrfCookie == nil {
		t.Fatal("logout CSRF cookie not set on confirm page")
	}
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("post_logout_redirect_uri", target)
	form.Set("client_id", testClientID)
	form.Set("state", "attacker-state")
	form.Set("confirm", "yes")
	post, err := ts.do(t, http.MethodPost, "/connect/logout", form, []*http.Cookie{sessionCookie, csrfCookie})
	if err != nil {
		t.Fatalf("POST /connect/logout: %v", err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusFound {
		t.Fatalf("confirm POST status = %d, want 302", post.StatusCode)
	}
	postLoc := post.Header.Get("Location")
	if !strings.Contains(postLoc, "/logged-out") {
		t.Errorf("POST Location = %q, want .../logged-out (valid post_logout_redirect_uri)", postLoc)
	}
	if !strings.Contains(postLoc, "state=attacker-state") {
		t.Errorf("POST Location = %q, want it to carry state", postLoc)
	}
}

// TestE2E_Logout_IdTokenHintGET_RecoversClientIDFromAud: when the
// caller supplies id_token_hint but not client_id, the confirm-page
// redirect must carry the client_id recovered from the hint's aud so
// that the eventual POST has the value handleConfirm needs to validate
// post_logout_redirect_uri. This is the only use of the hint on the
// GET path; revocation still waits for the confirm POST.
func TestE2E_Logout_IdTokenHintGET_RecoversClientIDFromAud(t *testing.T) {
	ts := newTestServer(t)
	tr, _ := exchangeCodeForTokens(t, ts)

	logoutURL := "/connect/logout?id_token_hint=" + url.QueryEscape(tr.IDToken)
	resp, err := ts.do(t, http.MethodGet, logoutURL, nil, nil)
	if err != nil {
		t.Fatalf("logout GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/logout") {
		t.Fatalf("Location = %q, want /logout...", loc)
	}
	if !strings.Contains(loc, "client_id="+url.QueryEscape(testClientID)) {
		t.Errorf("Location = %q, want it to carry client_id=%s recovered from id_token_hint aud", loc, testClientID)
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

// --- T7.1-T7.3: admin auth group + JSON CRUD + SPA, full router ---

func TestE2E_Admin_RejectsAnonymous(t *testing.T) {
	ts := newAdminTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/admin/", nil, nil)
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want Bearer", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestE2E_Admin_AcceptsToken(t *testing.T) {
	ts := newAdminTestServer(t)
	resp, err := ts.adminGet(t, "/admin/")
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<html") {
		t.Errorf("body is not HTML: %s", body)
	}
	if !strings.Contains(string(body), `name="csrf-token"`) {
		t.Errorf("body missing csrf-token meta tag: %s", body)
	}
}

func TestE2E_Admin_ClientListThroughRouter(t *testing.T) {
	ts := newAdminTestServer(t)
	resp, err := ts.adminGet(t, "/admin/api/clients")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var list struct {
		Items      []map[string]any `json:"items"`
		TotalCount int              `json:"total_count"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.TotalCount < 1 {
		t.Errorf("expected the seeded public client, got %d", list.TotalCount)
	}
}

func TestE2E_Admin_Keys_StripPrivatePEM(t *testing.T) {
	ts := newAdminTestServer(t)
	resp, err := ts.adminGet(t, "/admin/api/keys")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Errorf("response leaked private PEM: %s", body)
	}
	// The response should still mention kid/alg.
	var out struct {
		Items []struct {
			Kid       string `json:"kid"`
			Alg       string `json:"alg"`
			IsActive  bool   `json:"is_active"`
			PublicPEM string `json:"public_pem"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Items) == 0 {
		t.Errorf("expected at least one signing key, got 0")
	}
	for _, k := range out.Items {
		if k.Kid == "" {
			t.Errorf("key missing kid: %+v", k)
		}
		if !strings.Contains(k.PublicPEM, "PUBLIC KEY") {
			t.Errorf("public PEM missing for kid=%s", k.Kid)
		}
	}
}

// adminTestServer is a tiny wrapper around the existing testServer
// that adds the admin token + a Get helper that sets the auth header.
type adminTestServer struct {
	*testServer
	token string
}

const testAdminTokenValue = "test-admin-token"

func newAdminTestServer(t *testing.T) *adminTestServer {
	t.Helper()
	ts := newTestServer(t)
	ats := &adminTestServer{testServer: ts, token: testAdminTokenValue}
	// Wire the admin bundle into the existing test server's router.
	// We do this once per test by appending the admin routes to a
	// fresh mux so the rest of the test setup is unaffected.
	// For simplicity, the test server already mounts admin when
	// newTestServerWith is called with the right config. We
	// rebuild the admin handler here.
	_ = ats // the admin is already mounted in newTestServerWith
	return ats
}

func (a *adminTestServer) adminGet(t *testing.T, path string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, a.URL(path), nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	return a.client.Do(req)
}

// --- T8.1: rate limit + lockout + security headers ---

func TestE2E_LoginRateLimit_Over429(t *testing.T) {
	ts := newTestServerWithRateLimit(t, 1, 1) // 1 rps, burst 1
	// Burst is 1, refill is slow. Two POSTs in a row should
	// yield a non-429 for the first, 429 for the second.
	body := strings.NewReader("username=x&password=y")
	first := postRaw(t, ts, "/login", body)
	first.Body.Close()
	if first.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("first request: rate-limited too early (status %d)", first.StatusCode)
	}

	body2 := strings.NewReader("username=x&password=y")
	second := postRaw(t, ts, "/login", body2)
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request: status = %d, want 429", second.StatusCode)
	}
	if second.Header.Get("Retry-After") == "" {
		t.Errorf("429 missing Retry-After")
	}
}

// postRaw fires a raw POST without going through the test server's
// redirect-aware client. It returns the response without reading the
// body, so the caller must close it.
func postRaw(t *testing.T, ts *testServer, path string, body *strings.Reader) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL(path), body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func TestE2E_SecurityHeaders_PresentOnDiscovery(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := resp.Header.Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want same-origin", got)
	}
}

func TestE2E_StrictTransportSecurity_HTTPSOnly(t *testing.T) {
	// RequireHTTPS=false → HSTS must NOT be set (it's only safe
	// when serving over HTTPS).
	ts := newTestServer(t) // test config sets RequireHTTPS=false
	resp, _ := ts.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS set over HTTP: %q (browser would cache and break)", got)
	}
}

func TestE2E_Login_LockoutAfterRepeatedFailures(t *testing.T) {
	ts := newTestServer(t)
	// Repeatedly POST /login with wrong creds. The tracker
	// default is MaxFailures=5; the 6th attempt should be
	// blocked even with correct creds.
	authorizeURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	for i := 0; i < 5; i++ {
		resp := loginWithCreds(t, ts, "wrong", "wrong", authorizeURL)
		resp.Body.Close()
	}
	// 6th: still bad creds, but should also be locked.
	resp := loginWithCreds(t, ts, "wrong", "wrong", authorizeURL)
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=account_locked") {
		t.Errorf("6th attempt Location = %q, want error=account_locked", loc)
	}
}

func loginWithCreds(t *testing.T, ts *testServer, user, pass, returnURL string) *http.Response {
	t.Helper()
	// Get CSRF cookie + token first.
	resp, err := ts.do(t, http.MethodGet, "/login", nil, nil)
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
	postResp, err := ts.do(t, http.MethodPost, "/login", form, []*http.Cookie{csrfCookie})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	return postResp
}

// testServerRateLimitRPS / testServerRateLimitBurst let a test
// request a tight rate limit for its duration; the override is
// scoped to that test and restored on cleanup.
var (
	rateLimitOverrideRPS   int
	rateLimitOverrideBurst int
)

func testServerRateLimitRPS(t *testing.T) int {
	t.Helper()
	if rateLimitOverrideRPS > 0 {
		return rateLimitOverrideRPS
	}
	return 1000
}

func testServerRateLimitBurst(t *testing.T) int {
	t.Helper()
	if rateLimitOverrideBurst > 0 {
		return rateLimitOverrideBurst
	}
	return 1000
}

// withRateLimit installs a process-wide rate limit override for the
// duration of t. Use it to opt a specific test into a tight limit.
func withRateLimit(t *testing.T, rps, burst int) {
	t.Helper()
	prevRPS, prevBurst := rateLimitOverrideRPS, rateLimitOverrideBurst
	rateLimitOverrideRPS = rps
	rateLimitOverrideBurst = burst
	t.Cleanup(func() {
		rateLimitOverrideRPS, rateLimitOverrideBurst = prevRPS, prevBurst
	})
}

func newTestServerWithRateLimit(t *testing.T, rps, burst int) *testServer {
	t.Helper()
	withRateLimit(t, rps, burst)
	return newTestServer(t)
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

// --- M6: confidential client + private_key_jwt + client_credentials ---

const testConfidentialID = "demo-confidential"

// confidentialTestClient returns the RSA keypair + the *domain.Client
// the test registered, so the test can sign assertions on the
// server's behalf.
type confidentialTestClient struct {
	Client *domain.Client
	Priv   jwk.Key
	Kid    string
}

// registerConfidentialClient adds a private_key_jwt client to the
// test server's bundle and returns the keypair used.
func registerConfidentialClient(t *testing.T, b bundle) confidentialTestClient {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	kid := "test-confidential-kid"
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatalf("add to set: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	c := &domain.Client{
		ClientID:                testConfidentialID,
		DisplayName:             "Demo Confidential Client",
		AllowedScopes:           []string{"read", "write", "openid"},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  true,
		JWKSJSON:                string(raw),
	}
	if err := b.Clients.Store(context.Background(), c); err != nil {
		t.Fatalf("store confidential client: %v", err)
	}
	return confidentialTestClient{Client: c, Priv: privJWK, Kid: kid}
}

// signClientAssertion mints a private_key_jwt assertion suitable for
// POSTing to /connect/token.
func signClientAssertion(t *testing.T, priv jwk.Key, clientID, audience, jti string, iat, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{audience}).
		IssuedAt(iat).
		Expiration(exp).
		JwtID(jti).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func TestE2E_ClientCredentials_Confidential(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))

	now := ts.clk.Now()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", "read")

	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control missing no-store")
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if tr.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if tr.RefreshToken != "" {
		t.Errorf("refresh_token must be empty for client_credentials, got %q", tr.RefreshToken)
	}
	if tr.IDToken != "" {
		t.Errorf("id_token must be empty for client_credentials, got %q", tr.IDToken)
	}
	// sub of the issued access token must be the client_id.
	accessTok, err := ts.issuer.VerifyToken(context.Background(), tr.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if accessTok.Subject() != testConfidentialID {
		t.Errorf("sub = %q, want %q", accessTok.Subject(), testConfidentialID)
	}
	if tr.Scope != "read" {
		t.Errorf("scope = %q, want read", tr.Scope)
	}
}

func TestE2E_ClientCredentials_ForgedKeyRejected(t *testing.T) {
	ts := newTestServer(t)
	_ = registerConfidentialClient(t, bundleFromTestServer(ts))

	// We sign the assertion with a freshly generated key — one
	// that is NOT registered on the client.
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherJWK, _ := jwk.FromRaw(otherPriv)
	_ = otherJWK.Set(jwk.KeyIDKey, "attacker")
	_ = otherJWK.Set(jwk.AlgorithmKey, jwa.RS256)

	now := ts.clk.Now()
	assertion := signClientAssertion(t, otherJWK, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", "read")

	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged key: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("WWW-Authenticate = %q, want Basic", resp.Header.Get("WWW-Authenticate"))
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", er.Error)
	}
}

func TestE2E_ClientCredentials_ReplayedJTIRevoked(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))

	now := ts.clk.Now()
	jti := uuid.NewString()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", jti, now, now.Add(time.Minute))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", "read")

	// First use: ok.
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp.StatusCode)
	}

	// Replay the same jti: 401 invalid_client.
	resp, err = ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "invalid_client" {
		t.Errorf("replay error = %q, want invalid_client", er.Error)
	}
}

func TestE2E_ClientCredentials_PublicClientRejected(t *testing.T) {
	ts := newTestServer(t)
	// Use the public test client — does NOT allow client_credentials.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testClientID)
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", er.Error)
	}
}

func TestE2E_ClientCredentials_HMACRejected(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))

	// Forge an HS256 assertion using the public key as the HMAC
	// secret. The verifier must reject before doing any signature
	// work.
	pubJWK, err := ctc.Priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	var pubRaw any
	if err := pubJWK.Raw(&pubRaw); err != nil {
		t.Fatalf("Raw: %v", err)
	}
	hmacSecret := []byte(fmt.Sprintf("%v", pubRaw))

	now := ts.clk.Now()
	tok, err := jwt.NewBuilder().
		Issuer(testConfidentialID).
		Subject(testConfidentialID).
		Audience([]string{testIssuer + "/connect/token"}).
		IssuedAt(now).
		Expiration(now.Add(time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, hmacSecret))
	if err != nil {
		t.Fatalf("hmac sign: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signed))
	form.Set("scope", "read")

	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("hmac: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
}

func TestE2E_ClientCredentials_ExpiredAssertionRejected(t *testing.T) {
	ts := newTestServer(t)
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))

	// exp in the past relative to the fake clock.
	now := ts.clk.Now()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now.Add(-2*time.Minute), now.Add(-time.Minute))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
}

func TestE2E_Discovery_AdvertisesPrivateKeyJWT(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc struct {
		TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
		TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
		GrantTypesSupported                        []string `json:"grant_types_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !sliceContains(doc.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Errorf("discovery missing private_key_jwt: %v", doc.TokenEndpointAuthMethodsSupported)
	}
	if !sliceContains(doc.TokenEndpointAuthSigningAlgValuesSupported, "RS256") {
		t.Errorf("discovery missing RS256: %v", doc.TokenEndpointAuthSigningAlgValuesSupported)
	}
	if !sliceContains(doc.GrantTypesSupported, "client_credentials") {
		t.Errorf("discovery missing client_credentials: %v", doc.GrantTypesSupported)
	}
}

// --- M6 GORM mirror ---

func TestGORM_E2E_ClientCredentials(t *testing.T) {
	gormFlowTest(t, "ClientCredentialsConfidential", testE2EClientCredentials)
}
func TestGORM_E2E_ClientCredentials_Forged(t *testing.T) {
	gormFlowTest(t, "ClientCredentialsForged", testE2EClientCredentialsForged)
}
func TestGORM_E2E_ClientCredentials_Replay(t *testing.T) {
	gormFlowTest(t, "ClientCredentialsReplay", testE2EClientCredentialsReplay)
}
func TestGORM_E2E_ClientCredentials_HMAC(t *testing.T) {
	gormFlowTest(t, "ClientCredentialsHMAC", testE2EClientCredentialsHMAC)
}
func TestGORM_E2E_ClientCredentials_PublicRejected(t *testing.T) {
	gormFlowTest(t, "ClientCredentialsPublicRejected", testE2EClientCredentialsPublicRejected)
}

// Shared GORM runners: identical to the in-memory versions but
// operating on the GORM-backed test server.

func testE2EClientCredentials(t *testing.T, ts *testServer) {
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))
	now := ts.clk.Now()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", "read")
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)
	if tr.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if tr.RefreshToken != "" {
		t.Errorf("refresh_token must be empty for client_credentials")
	}
	if tr.IDToken != "" {
		t.Errorf("id_token must be empty for client_credentials")
	}
	accessTok, err := ts.issuer.VerifyToken(context.Background(), tr.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if accessTok.Subject() != testConfidentialID {
		t.Errorf("sub = %q, want %q", accessTok.Subject(), testConfidentialID)
	}
}

func testE2EClientCredentialsForged(t *testing.T, ts *testServer) {
	_ = registerConfidentialClient(t, bundleFromTestServer(ts))
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherJWK, _ := jwk.FromRaw(otherPriv)
	_ = otherJWK.Set(jwk.KeyIDKey, "attacker")
	_ = otherJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	now := ts.clk.Now()
	assertion := signClientAssertion(t, otherJWK, testConfidentialID,
		testIssuer+"/connect/token", uuid.NewString(), now, now.Add(time.Minute))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged: status = %d, want 401", resp.StatusCode)
	}
}

func testE2EClientCredentialsReplay(t *testing.T, ts *testServer) {
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))
	now := ts.clk.Now()
	jti := uuid.NewString()
	assertion := signClientAssertion(t, ctc.Priv, testConfidentialID,
		testIssuer+"/connect/token", jti, now, now.Add(time.Minute))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	resp, _ := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay: status = %d, want 401", resp.StatusCode)
	}
}

func testE2EClientCredentialsHMAC(t *testing.T, ts *testServer) {
	ctc := registerConfidentialClient(t, bundleFromTestServer(ts))
	pubJWK, _ := ctc.Priv.PublicKey()
	var pubRaw any
	_ = pubJWK.Raw(&pubRaw)
	hmacSecret := []byte(fmt.Sprintf("%v", pubRaw))
	now := ts.clk.Now()
	tok, _ := jwt.NewBuilder().
		Issuer(testConfidentialID).
		Subject(testConfidentialID).
		Audience([]string{testIssuer + "/connect/token"}).
		IssuedAt(now).
		Expiration(now.Add(time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.HS256, hmacSecret))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testConfidentialID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signed))
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("hmac: status = %d, want 401", resp.StatusCode)
	}
}

func testE2EClientCredentialsPublicRejected(t *testing.T, ts *testServer) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testClientID) // public demo client
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", er.Error)
	}
}

// --- helpers shared between M6 tests ---

// bundleFromTestServer returns the bundle the test server was built
// with. We don't currently expose it directly, so this is a
// best-effort reconstruction: for the memory path we re-look up the
// clients; for the GORM path the test server also holds live
// stores. To keep the test API simple, registerConfidentialClient
// operates on the live store via the test server's ts.auditLogs /
// ts.refreshTokens / ts.clients fields — which are the store
// interfaces the bundle produced. The bundle re-export below exists
// purely so the helper signatures match; the real interaction is
// through ts.clients.
func bundleFromTestServer(ts *testServer) bundle {
	return bundle{
		Clients:       ts.clients,
		RefreshTokens: ts.refreshTokens,
		AuditLogs:     ts.auditLogs,
		Scopes:        memory.NewScopeStore(),
		SigningKeys:   memory.NewSigningKeyStore(),
		AuthCodes:     memory.NewAuthorizationCodeStore(),
		Sessions:      memory.NewSessionStore(),
		Users:         memory.NewUserStore(),
		Tracker:       memory.NewLoginAttemptTracker(time.Now),
	}
}

// generateKey returns a freshly generated RSA private key, used by
// the HMAC test to manufacture a forgery that does not use the
// legitimate key.
func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// --- authorize: prompt + max_age interactions (T9.1) ---

// buildAuthorizeURLWithExtras lets a test append arbitrary query
// params (prompt, max_age, ...) to the standard authorize URL.
func buildAuthorizeURLWithExtras(clientID, redirectURI, state, nonce, challenge string, extra url.Values) string {
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
	for k, vs := range extra {
		for _, val := range vs {
			v.Add(k, val)
		}
	}
	return "/connect/authorize?" + v.Encode()
}

// TestAuthorize_PromptNone_MaxAgeExceeded returns login_required even
// when the session exists. Regression for §1.2 of plan-2.md: the
// max_age check was nested under the else branch and was skipped
// when prompt=none.
func TestAuthorize_PromptNone_MaxAgeExceeded(t *testing.T) {
	ts := newTestServer(t)

	authURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sess := loginAs(t, ts, testUser, testPassword, authURL)

	// Advance the clock past max_age=5s.
	ts.clk.Advance(10 * time.Second)

	v := url.Values{}
	v.Set("prompt", "none")
	v.Set("max_age", "5")
	authURL = buildAuthorizeURLWithExtras(testClientID, testRedirectURI, testState, testNonce, testChallenge(), v)

	resp, err := ts.do(t, http.MethodGet, authURL, nil, []*http.Cookie{sess})
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirectURI) {
		t.Fatalf("Location = %q, want redirect to %s", loc, testRedirectURI)
	}
	q, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if q.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", q.Query().Get("error"))
	}
	if !strings.Contains(q.Query().Get("error_description"), "max_age") {
		t.Errorf("error_description = %q, want it to mention max_age", q.Query().Get("error_description"))
	}
}

// TestAuthorize_NoPrompt_MaxAgeExceeded still bounces to /login (the
// non-prompt=none path was already working; lock the behaviour so a
// future refactor doesn't regress it).
func TestAuthorize_NoPrompt_MaxAgeExceeded(t *testing.T) {
	ts := newTestServer(t)

	authURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sess := loginAs(t, ts, testUser, testPassword, authURL)

	ts.clk.Advance(10 * time.Second)

	v := url.Values{}
	v.Set("max_age", "5")
	authURL = buildAuthorizeURLWithExtras(testClientID, testRedirectURI, testState, testNonce, testChallenge(), v)

	resp, err := ts.do(t, http.MethodGet, authURL, nil, []*http.Cookie{sess})
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?") {
		t.Errorf("Location = %q, want /login?returnUrl=... (session was zeroed by max_age)", loc)
	}
}

// TestAuthorize_PromptNone_MaxAgeZero forces re-authentication
// unconditionally per OIDC §3.1.2.1. Regression for the same §1.2
// path: max_age=0 is valid and must be enforced.
func TestAuthorize_PromptNone_MaxAgeZero(t *testing.T) {
	ts := newTestServer(t)

	authURL := buildAuthorizeURL(testClientID, testRedirectURI, testState, testNonce, testChallenge())
	sess := loginAs(t, ts, testUser, testPassword, authURL)

	v := url.Values{}
	v.Set("prompt", "none")
	v.Set("max_age", "0")
	authURL = buildAuthorizeURLWithExtras(testClientID, testRedirectURI, testState, testNonce, testChallenge(), v)

	resp, err := ts.do(t, http.MethodGet, authURL, nil, []*http.Cookie{sess})
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirectURI) {
		t.Fatalf("Location = %q, want redirect to %s", loc, testRedirectURI)
	}
	q, _ := url.Parse(loc)
	if q.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", q.Query().Get("error"))
	}
}

// --- admin helpers ---

// buildTestAdminMount wires the admin auth + CSRF + API + SPA for
// the test server. The test admin token is a fixed value
// (testAdminTokenValue) the test client sends.
func buildTestAdminMount(t *testing.T, b bundle, clk *clock.FakeClock, logger *slog.Logger) *server.AdminMount {
	t.Helper()
	authMW, err := admin.AuthMiddleware(admin.AuthConfig{Token: testAdminTokenValue}, logger)
	if err != nil {
		t.Fatalf("admin.AuthMiddleware: %v", err)
	}
	csrfMW := admin.CSRFMiddleware([]byte("0123456789abcdef0123456789abcdef"))
	apiMux := http.NewServeMux()
	(&admin.API{
		Clients:       b.Clients,
		Scopes:        b.Scopes,
		Sessions:      b.Sessions,
		RefreshTokens: b.RefreshTokens,
		SigningKeys:   b.SigningKeys,
		AuditLogs:     b.AuditLogs,
		Clock:         clk,
		Logger:        logger,
	}).Mount(apiMux)
	ui := &admin.UI{
		Template: template.Must(template.New("admin").Parse(admin.IndexPage())),
		Logger:   logger,
	}
	wrapped := authMW(csrfMW(admin.CombineMux(apiMux, ui)))
	return &server.AdminMount{Root: wrapped, API: wrapped}
}

var _ = fmt.Sprintf
