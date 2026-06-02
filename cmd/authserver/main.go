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
	"go-authserver/internal/store/gormstore"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"

	"gorm.io/gorm"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

// storeBundle is the bag of store interfaces the rest of the wiring
// reads from. Both the memory and the GORM backends produce a
// value of this type, so handlers don't know (or care) which one is
// in use.
type storeBundle struct {
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

// userAdder is the seed-only extension of UserStore. The memory and
// gormstore implementations both satisfy it; the interface lives here
// so the rest of main doesn't have to import either concrete type.
type userAdder interface {
	Add(u domain.UserInfo, password string) error
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	clk := clock.SystemClock{}
	bundle, gormDB, closer, err := buildStores(cfg.DBDriver, cfg.DBDSN, clk.Now, logger)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	if err := seedBundle(bundle); err != nil {
		return err
	}

	keyManager := token.NewKeyManager(bundle.SigningKeys, clk)
	issuer := token.NewIssuer(cfg.Issuer, keyManager, clk)
	issuer.DefaultAccessTokenLifetime = cfg.AccessTokenLifetime
	issuer.DefaultIDTokenLifetime = cfg.IDTokenLifetime

	cookieMgr := session.NewCookieManager(cfg.CookieHMAC, cfg.CookieBlock, session.CookieConfig{
		Name:         cfg.EffectiveCookieName(),
		RequireHTTPS: cfg.RequireHTTPS,
		Path:         "/",
		MaxAge:       8 * time.Hour,
	})

	loginTmpl := template.Must(template.New("login").Parse(oidc.LoginTemplate()))
	logoutTmpl := template.Must(template.New("logout").Parse(oidc.LogoutTemplate()))

	loginHandler := &oidc.LoginHandler{
		Cfg: oidc.LoginConfig{
			IssuerURL:       cfg.Issuer,
			LoginPath:       cfg.LoginPath,
			AuthorizePath:   "/connect/authorize",
			SessionLifetime: 8 * time.Hour,
		},
		Users:    bundle.Users,
		Sessions: bundle.Sessions,
		Cookies:  cookieMgr,
		Tracker:  bundle.Tracker,
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
		Clients:   bundle.Clients,
		AuthCodes: bundle.AuthCodes,
		Sessions:  bundle.Sessions,
		Users:     bundle.Users,
		Cookies:   cookieMgr,
		Issuer:    issuer,
		Clock:     clk,
		Logger:    logger,
	}
	tokenHandler := &oidc.TokenHandler{
		AuthCode: &grants.AuthCodeGrant{
			AuthCodes:     bundle.AuthCodes,
			RefreshTokens: bundle.RefreshTokens,
			Clients:       bundle.Clients,
			Users:         bundle.Users,
			Issuer:        issuer,
			Clock:         clk,
			Cfg: grants.AuthCodeConfig{
				AccessTokenLifetime:          cfg.AccessTokenLifetime,
				IDTokenLifetime:              cfg.IDTokenLifetime,
				RefreshTokenLifetime:         cfg.RefreshTokenLifetime,
				RefreshTokenAbsoluteLifetime: cfg.RefreshTokenAbsoluteLifetime,
			},
		},
		Refresh: &grants.RefreshGrant{
			RefreshTokens: bundle.RefreshTokens,
			Sessions:      bundle.Sessions,
			Clients:       bundle.Clients,
			Users:         bundle.Users,
			AuditLogs:     bundle.AuditLogs,
			Issuer:        issuer,
			Clock:         clk,
			Logger:        logger,
			Cfg: grants.RefreshConfig{
				AccessTokenLifetime:          cfg.AccessTokenLifetime,
				IDTokenLifetime:              cfg.IDTokenLifetime,
				RefreshTokenLifetime:         cfg.RefreshTokenLifetime,
				RefreshTokenAbsoluteLifetime: cfg.RefreshTokenAbsoluteLifetime,
				DetectReuse:                  cfg.DetectRefreshTokenReuse,
			},
		},
	}
	userInfoHandler := oidc.NewUserInfoHandler(issuer, bundle.Users, logger)
	revokeHandler := &oidc.RevokeHandler{
		RefreshTokens: bundle.RefreshTokens,
		Clients:       bundle.Clients,
		Now:           clk.Now,
		Logger:        logger,
	}
	logoutHandler := &oidc.LogoutHandler{
		Cfg: oidc.LogoutConfig{
			IssuerURL:             cfg.Issuer,
			AuthorizePath:         "/connect/authorize",
			LogoutPath:            cfg.LogoutPath,
			PostLogoutRedirectURI: cfg.PostLogoutRedirectURI,
		},
		Cookies:       cookieMgr,
		Sessions:      bundle.Sessions,
		RefreshTokens: bundle.RefreshTokens,
		Clients:       bundle.Clients,
		Issuer:        issuer,
		Clock:         clk,
		Logger:        logger,
		Confirm:       logoutTmpl,
	}

	// EnsureActiveKey so discovery/JWKS have a key to publish on first boot.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := keyManager.EnsureActiveKey(ctx); err != nil {
		cancel()
		return err
	}
	cancel()

	handlers := server.Handlers{
		Login:     loginHandler,
		Logout:    logoutHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		UserInfo:  userInfoHandler,
		Revoke:    revokeHandler,
		Discovery: oidc.NewDiscoveryHandler(cfg.Issuer, bundle.Scopes),
		JWKS:      oidc.NewJWKSHandler(issuer),
		Health:    server.NewHealth(),
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL:     cfg.Issuer,
			RequireHTTPS:  cfg.RequireHTTPS,
			LoginPath:     cfg.LoginPath,
			LogoutPath:    cfg.LogoutPath,
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

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "issuer", cfg.Issuer, "driver", cfg.DBDriver)
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
	_ = gormDB // kept alive until shutdown
	return srv.Shutdown(shutdownCtx)
}

// buildStores picks a backend based on driver and returns a populated
// storeBundle. The third return value is a closer (always non-nil for
// the GORM path) the caller should defer.
//
// The "memory" driver is honoured explicitly so tests/CLI users can
// ask for it; an empty driver also falls back to memory.
func buildStores(driver, dsn string, now func() time.Time, logger *slog.Logger) (*storeBundle, *gorm.DB, func(), error) {
	drv := driver
	if drv == "" {
		drv = "memory"
	}
	switch drv {
	case "memory":
		return &storeBundle{
			Clients:       memory.NewClientStore(),
			AuthCodes:     memory.NewAuthorizationCodeStore(),
			RefreshTokens: memory.NewRefreshTokenStore(),
			Sessions:      memory.NewSessionStore(),
			SigningKeys:   memory.NewSigningKeyStore(),
			Scopes:        memory.NewScopeStore(),
			AuditLogs:     memory.NewAuditLogStore(),
			Users:         memory.NewUserStore(),
			Tracker:       memory.NewLoginAttemptTracker(now),
		}, nil, func() {}, nil
	case "sqlite", "postgres":
		db, err := gormstore.Open(drv, dsn)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := gormstore.Migrate(db); err != nil {
			return nil, nil, nil, err
		}
		if logger != nil {
			logger.Info("gormstore ready", "driver", drv)
		}
		bundle := &storeBundle{
			Clients:       gormstore.NewClientStore(db),
			AuthCodes:     gormstore.NewAuthorizationCodeStore(db),
			RefreshTokens: gormstore.NewRefreshTokenStore(db),
			Sessions:      gormstore.NewSessionStore(db),
			SigningKeys:   gormstore.NewSigningKeyStore(db),
			Scopes:        gormstore.NewScopeStore(db),
			AuditLogs:     gormstore.NewAuditLogStore(db),
			Users:         gormstore.NewUserStore(db),
			// The login-attempt tracker stays in-process. It's a
			// sliding-window brute-force counter, not a durable
			// record; sharing it across instances is not a
			// requirement.
			Tracker: memory.NewLoginAttemptTracker(now),
		}
		closer := func() {
			sqlDB, err := db.DB()
			if err != nil {
				return
			}
			_ = sqlDB.Close()
		}
		return bundle, db, closer, nil
	default:
		return nil, nil, nil, errors.New("unknown DB driver: " + drv)
	}
}

// seedBundle writes the minimum sample data so the server is usable
// immediately without any admin UI: the four standard OIDC scopes, a
// public demo client, and a demo user.
func seedBundle(b *storeBundle) error {
	ctx := context.Background()
	for _, s := range []domain.Scope{
		{Name: "openid", DisplayName: "OpenID", Description: "Verify your identity", Required: true, Emphasize: true},
		{Name: "profile", DisplayName: "Profile", Description: "Your basic profile information"},
		{Name: "email", DisplayName: "Email", Description: "Your email address"},
		{Name: "offline_access", DisplayName: "Offline access", Description: "Refresh tokens for long-lived access"},
	} {
		if err := b.Scopes.Store(ctx, &s); err != nil {
			return err
		}
	}
	c := &domain.Client{
		ClientID:                "demo-public",
		DisplayName:             "Demo Public Client",
		RedirectURIs:            []string{"https://demo.example/callback"},
		PostLogoutRedirectURIs:  []string{"https://demo.example/"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}
	if err := b.Clients.Store(ctx, c); err != nil {
		return err
	}
	adder, ok := b.Users.(userAdder)
	if !ok {
		return errors.New("user store does not support Add (seed path)")
	}
	return adder.Add(domain.UserInfo{
		UserID: "u-demo",
		Claims: map[string]any{
			"preferred_username": "demo",
			"name":               "Demo User",
			"email":              "demo@example.com",
			"email_verified":     true,
		},
	}, "demo")
}
