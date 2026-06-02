// Command authserver is the composition root for the OAuth2 / OIDC
// authorisation server. It loads config, wires stores + signing keys,
// constructs every HTTP handler, and serves the router until SIGINT.
package main

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/config"
	"go-authserver/internal/domain"
	"go-authserver/internal/oidc"
	"go-authserver/internal/oidc/grants"
	"go-authserver/internal/server"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	clk := clock.SystemClock{}
	keys := memory.NewSigningKeyStore()
	scopes := memory.NewScopeStore()
	clients := memory.NewClientStore()
	sessions := memory.NewSessionStore()
	authCodes := memory.NewAuthorizationCodeStore()
	refreshTokens := memory.NewRefreshTokenStore()
	users := memory.NewUserStore()
	auditLogs := memory.NewAuditLogStore()
	tracker := memory.NewLoginAttemptTracker(clk.Now)

	if err := seed(scopes, clients, users); err != nil {
		return err
	}

	keyManager := token.NewKeyManager(keys, clk)
	issuer := token.NewIssuer(cfg.Issuer, keyManager, clk)
	issuer.DefaultAccessTokenLifetime = cfg.AccessTokenLifetime
	issuer.DefaultIDTokenLifetime = cfg.IDTokenLifetime

	cookieMgr := session.NewCookieManager(cfg.CookieHMAC, cfg.CookieBlock, session.CookieConfig{
		Name:         cfg.EffectiveCookieName(),
		RequireHTTPS: cfg.RequireHTTPS,
		Path:         "/",
		MaxAge:       8 * time.Hour,
	})

	loginTmpl := template.Must(template.New("login").Parse(loginHTML))
	loginHandler := &oidc.LoginHandler{
		Cfg: oidc.LoginConfig{
			IssuerURL:       cfg.Issuer,
			LoginPath:       cfg.LoginPath,
			AuthorizePath:   "/connect/authorize",
			SessionLifetime: 8 * time.Hour,
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
			IssuerURL:        cfg.Issuer,
			LoginPath:        cfg.LoginPath,
			AuthorizePath:    "/connect/authorize",
			AuthCodeLifetime: cfg.AuthCodeLifetime,
			RequirePKCE:      cfg.RequirePKCE,
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
				AccessTokenLifetime:          cfg.AccessTokenLifetime,
				IDTokenLifetime:              cfg.IDTokenLifetime,
				RefreshTokenLifetime:         cfg.RefreshTokenLifetime,
				RefreshTokenAbsoluteLifetime: cfg.RefreshTokenAbsoluteLifetime,
			},
		},
	}

	// EnsureActiveKey so discovery/JWKS have a key to publish on first boot.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := keyManager.EnsureActiveKey(ctx); err != nil {
		cancel()
		return err
	}
	cancel()

	_ = auditLogs
	_ = store.ScopeStore(nil)

	handlers := server.Handlers{
		Login:     loginHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		Discovery: oidc.NewDiscoveryHandler(cfg.Issuer, scopes),
		JWKS:      oidc.NewJWKSHandler(issuer),
		Health:    server.NewHealth(),
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL:     cfg.Issuer,
			RequireHTTPS:  cfg.RequireHTTPS,
			LoginPath:     cfg.LoginPath,
			AuthorizePath: "/connect/authorize",
			TokenPath:     "/connect/token",
			JWKSPath:      "/.well-known/jwks.json",
			DiscoveryPath: "/.well-known/openid-configuration",
			HealthPath:    "/healthz",
		},
		server.RouterOptions{Logger: logger},
		handlers,
	)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "issuer", cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

const loginHTML = `<!doctype html>
<html><body>
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="returnUrl" value="{{.ReturnURL}}">
<input name="username">
<input name="password" type="password">
<button type="submit">Sign in</button>
</form>
</body></html>`

// seed writes the minimum sample data: the openid/profile/email/offline_access
// scopes, a sample public client, and a sample user. It runs synchronously
// at boot so the server is usable immediately without any admin UI.
func seed(scopes store.ScopeStore, clients store.ClientStore, users *memory.UserStore) error {
	ctx := context.Background()
	for _, s := range []domain.Scope{
		{Name: "openid", DisplayName: "OpenID", Description: "Verify your identity", Required: true, Emphasize: true},
		{Name: "profile", DisplayName: "Profile", Description: "Your basic profile information"},
		{Name: "email", DisplayName: "Email", Description: "Your email address"},
		{Name: "offline_access", DisplayName: "Offline access", Description: "Refresh tokens for long-lived access"},
	} {
		if err := scopes.Store(ctx, &s); err != nil {
			return err
		}
	}
	c := &domain.Client{
		ClientID:                "demo-public",
		DisplayName:             "Demo Public Client",
		RedirectURIs:            []string{"https://demo.example/callback"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}
	if err := clients.Store(ctx, c); err != nil {
		return err
	}
	return users.Add(domain.UserInfo{
		UserID: "u-demo",
		Claims: map[string]any{
			"preferred_username": "demo",
			"name":               "Demo User",
			"email":              "demo@example.com",
			"email_verified":     true,
		},
	}, "demo")
}
