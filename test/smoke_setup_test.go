//go:build m8smoke

package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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

// newSmokeTestServer is the smoke variant of newTestServer. The
// default test server's issuer is "https://auth.example.com"
// which doesn't match the httptest base URL; coreos/go-oidc v3
// enforces issuer-URL equality. We pre-allocate a port with
// net.Listen, build the issuer string from it, then attach the
// httptest.Server to that same listener so the URL never changes.
func newSmokeTestServer(t *testing.T) *testServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	issuer := "http://" + addr
	ts := buildTestServerForIssuer(t, issuer)
	// Replace the httptest server with one bound to the same
	// listener so the URL we passed in is actually used.
	ts.srv.Close()
	ts.srv = startOnListener(t, ts.srv.Config.Handler, l)
	return ts
}

// startOnListener constructs a httptest.Server that uses the
// supplied listener. Go 1.18+ has httptest.NewUnstartedServer +
// Listener field assignment.
func startOnListener(t *testing.T, h http.Handler, l net.Listener) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	if err := srv.Listener.Close(); err != nil {
		// Likely the listener was already closed by NewUnstartedServer.
		// httptest.NewUnstartedServer calls t.Cleanup to close it.
		// We want to reuse the same port, so set it directly.
	}
	srv.Listener = l
	srv.Start()
	return srv
}

// buildTestServerForIssuer assembles a testServer whose issuer is
// the supplied string. Most existing tests use the
// https://auth.example.com constant; the smoke test needs the
// issuer to match the actual base URL.
//
// The smoke test uses the SystemClock (real time) because
// coreos/go-oidc v3 validates exp/nbf against real time. The
// always-on tests use a fake clock for determinism.
func buildTestServerForIssuer(t *testing.T, issuer string) *testServer {
	t.Helper()
	clk := clock.SystemClock{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	scopes := memory.NewScopeStore()
	clients := memory.NewClientStore()
	sessions := memory.NewSessionStore()
	authCodes := memory.NewAuthorizationCodeStore()
	refreshTokens := memory.NewRefreshTokenStore()
	users := memory.NewUserStore()
	keys := memory.NewSigningKeyStore()
	tracker := memory.NewLoginAttemptTracker(clk.Now)

	for _, s := range []domain.Scope{{Name: "openid"}, {Name: "profile"}, {Name: "email"}, {Name: "offline_access"}} {
		_ = scopes.Store(context.Background(), &s)
	}
	sum := sha256.Sum256([]byte(testVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	_ = clients.Store(context.Background(), &domain.Client{
		ClientID:                testClientID,
		RedirectURIs:            []string{issuer + "/callback", testRedirectURI},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
		Properties:              map[string]string{"_smoke_challenge": challenge},
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
	iss := token.NewIssuer(issuer, km, clk)
	iss.DefaultAccessTokenLifetime = time.Hour
	iss.DefaultIDTokenLifetime = time.Hour
	if _, err := km.EnsureActiveKey(context.Background()); err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}
	cookieMgr := session.NewCookieManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		session.CookieConfig{Name: ".auth.session", Path: "/"},
	)
	loginTmpl := template.Must(template.New("login").Parse(oidc.LoginTemplate()))
	loginHandler := &oidc.LoginHandler{
		Cfg: oidc.LoginConfig{
			IssuerURL: issuer, LoginPath: "/login", AuthorizePath: "/connect/authorize", SessionLifetime: time.Hour,
		},
		Users: users, Sessions: sessions, Cookies: cookieMgr, Tracker: tracker,
		Clock: clk, Logger: logger, Template: loginTmpl,
	}
	authorizeHandler := &oidc.AuthorizeHandler{
		Cfg: oidc.AuthorizeConfig{
			IssuerURL: issuer, LoginPath: "/login", AuthorizePath: "/connect/authorize",
			AuthCodeLifetime: time.Minute, RequirePKCE: true,
		},
		Clients: clients, AuthCodes: authCodes, Sessions: sessions, Users: users, Cookies: cookieMgr,
		Issuer: iss, Clock: clk, Logger: logger,
	}
	tokenHandler := &oidc.TokenHandler{
		AuthCode: &grants.AuthCodeGrant{
			AuthCodes: authCodes, RefreshTokens: refreshTokens, Clients: clients, Users: users, Issuer: iss, Clock: clk,
			Cfg: grants.AuthCodeConfig{
				AccessTokenLifetime: time.Hour, IDTokenLifetime: time.Hour,
				RefreshTokenLifetime: 24 * time.Hour, RefreshTokenAbsoluteLifetime: 24 * time.Hour,
			},
		},
		ClientAuth: oidc.ClientAuthConfig{
			IssuerURL: issuer, TokenEndpointURL: issuer + "/connect/token",
			AssertionCache: token.NewMemAssertionCache(clk.Now), AssertionSkew: time.Minute,
			Clock: clk, Logger: logger,
		},
		Clients: clients, Clock: clk, Logger: logger,
	}
	logoutTmpl := template.Must(template.New("logout").Parse(oidc.LogoutTemplate()))
	logoutHandler := &oidc.LogoutHandler{
		Cfg: oidc.LogoutConfig{
			IssuerURL: issuer, AuthorizePath: "/connect/authorize",
			LogoutPath: "/logout", PostLogoutRedirectURI: "/",
		},
		Cookies:       cookieMgr,
		Sessions:      sessions,
		RefreshTokens: refreshTokens,
		Clients:       clients,
		Issuer:        iss,
		Clock:         clk,
		Logger:        logger,
		Confirm:       logoutTmpl,
	}

	handlers := server.Handlers{
		Login:     loginHandler,
		Logout:    logoutHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		UserInfo:  oidc.NewUserInfoHandler(iss, users, logger),
		Revoke: &oidc.RevokeHandler{
			RefreshTokens: refreshTokens,
			Clients:       clients,
			Now:           clk.Now,
			Logger:        logger,
		},
		Discovery: oidc.NewDiscoveryHandler(issuer, scopes),
		JWKS:      oidc.NewJWKSHandler(iss),
		Health:    server.NewHealth(),
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL: issuer, RequireHTTPS: false,
			LoginPath: "/login", LogoutPath: "/logout",
			AuthorizePath: "/connect/authorize", TokenPath: "/connect/token",
			UserInfoPath: "/connect/userinfo", RevokePath: "/connect/revoke",
			JWKSPath: "/.well-known/jwks.json", DiscoveryPath: "/.well-known/openid-configuration",
			HealthPath: "/healthz", LoginRateLimitRPS: 1000, LoginRateBurst: 1000,
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
		clk:           clock.NewFakeClock(time.Now()),
		clients:       clients,
		refreshTokens: refreshTokens,
		auditLogs:     memory.NewAuditLogStore(),
		issuer:        iss,
		client:        client,
	}
}

func stringPtrSmoke(s string) *string { return &s }

// contains is the same substring check used by the unit tests; it
// lives here too so the smoke test is self-contained.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var _ = strings.Contains
