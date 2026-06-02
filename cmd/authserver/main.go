// Command authserver is the composition root for the OAuth2 / OIDC
// authorisation server. It loads config, wires stores + signing keys,
// constructs every HTTP handler, and serves the router until SIGINT.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go-authserver/internal/admin"
	"go-authserver/internal/clock"
	"go-authserver/internal/config"
	"go-authserver/internal/domain"
	"go-authserver/internal/oidc"
	"go-authserver/internal/oidc/grants"
	"go-authserver/internal/server"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
	"go-authserver/internal/store/gormstore"
	"go-authserver/internal/token"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gorm.io/gorm"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Subcommands. The default (no arg, or "serve") starts the HTTP
	// server. "migrate" runs the schema migration + seed once and exits;
	// run it at deploy time so the serve path can start cold-fast with
	// AUTH_AUTO_MIGRATE=false.
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	var err error
	switch cmd {
	case "serve":
		err = run(logger)
	case "migrate":
		err = runMigrate(logger)
	case "rotate-keys":
		err = runRotateKeys(logger)
	case "rotate-dp-keys":
		err = runRotateDPKeys(logger)
	default:
		logger.Error("unknown command", "cmd", cmd, "want", "serve|migrate|rotate-keys|rotate-dp-keys")
		os.Exit(2)
	}
	if err != nil {
		logger.Error("startup failed", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

// runMigrate opens the configured PostgreSQL database, applies the GORM
// schema migration, and seeds the demo fixtures. It is a one-shot command
// meant to run at deploy time (not on every cold start). config.Load
// guarantees the driver is postgres.
func runMigrate(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	drv := cfg.DBDriver

	db, err := gormstore.Open(drv, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()

	if err := gormstore.Migrate(db); err != nil {
		return err
	}
	logger.Info("migration applied", "driver", drv)

	bundle := newGormBundle(db, time.Now)
	if err := seedBundle(bundle); err != nil {
		return err
	}
	// Pre-create the active signing + data-protection keys so the serve
	// path never has to generate them on a cold start.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyManager := token.NewKeyManager(bundle.SigningKeys, clock.SystemClock{})
	if _, err := keyManager.EnsureActiveKey(ctx); err != nil {
		return err
	}
	dpManager := session.NewDPKeyManager(bundle.DataProtection, clock.SystemClock{})
	if _, err := dpManager.EnsureActiveKey(ctx); err != nil {
		return err
	}
	logger.Info("seed + signing/data-protection keys ready", "driver", drv)
	return nil
}

// runRotateKeys generates a fresh active signing key and retires the
// current one (kept in the published JWKS so already-issued tokens stay
// verifiable until they expire). One-shot operator command; run it on a
// schedule for key rotation. Requires a persistent driver — rotating an
// in-memory key ring is meaningless.
func runRotateKeys(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	drv := cfg.DBDriver

	db, err := gormstore.Open(drv, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()

	keyManager := token.NewKeyManager(gormstore.NewSigningKeyStore(db), clock.SystemClock{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := keyManager.Rotate(ctx)
	if err != nil {
		return err
	}
	logger.Info("signing key rotated", "driver", drv, "new_kid", k.KeyID)
	return nil
}

// runRotateDPKeys generates a fresh active data-protection key (cookie +
// CSRF material) and retires the current one. Retired keys stay in the ring
// so existing session cookies keep decoding until they expire; only new
// cookies use the new key. One-shot operator command for periodic rotation.
func runRotateDPKeys(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	drv := cfg.DBDriver

	db, err := gormstore.Open(drv, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()

	dpManager := session.NewDPKeyManager(gormstore.NewDataProtectionKeyStore(db), clock.SystemClock{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := dpManager.Rotate(ctx)
	if err != nil {
		return err
	}
	logger.Info("data-protection key rotated", "driver", drv, "new_kid", k.KeyID)
	return nil
}

// storeBundle is the bag of store interfaces the rest of the wiring
// reads from. Both the memory and the GORM backends produce a
// value of this type, so handlers don't know (or care) which one is
// in use.
type storeBundle struct {
	Clients        store.ClientStore
	AuthCodes      store.AuthorizationCodeStore
	RefreshTokens  store.RefreshTokenStore
	Sessions       store.SessionStore
	SigningKeys    store.SigningKeyStore
	DataProtection store.DataProtectionKeyStore
	Scopes         store.ScopeStore
	AuditLogs      store.AuditLogStore
	Users          store.UserStore
	Roles          store.RoleStore
	Tracker        store.LoginAttemptTracker
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

	// Migrate on the serve path only when explicitly opted in. In
	// production, run `authserver migrate` at deploy time and set
	// AUTH_AUTO_MIGRATE=false so cold starts stay fast.
	if cfg.AutoMigrate {
		if err := gormstore.Migrate(gormDB); err != nil {
			return err
		}
		logger.Info("schema migrated on startup")
	}

	// Seed demo fixtures only when AUTH_SEED is set (default true; turn off
	// in production once the migrate command has run).
	if cfg.Seed {
		if err := seedBundle(bundle); err != nil {
			return err
		}
	}

	keyManager := token.NewKeyManager(bundle.SigningKeys, clk)
	issuer := token.NewIssuer(cfg.Issuer, keyManager, clk)
	issuer.DefaultAccessTokenLifetime = cfg.AccessTokenLifetime
	issuer.DefaultIDTokenLifetime = cfg.IDTokenLifetime

	// Data-protection key ring: the cookie (HMAC + encryption) and CSRF keys
	// come from the store — generated server-side, shared across instances,
	// durable across restarts — not from the environment. The ring lets old
	// cookies decode after a key rotation.
	dpManager := session.NewDPKeyManager(bundle.DataProtection, clk)
	dpCtx, dpCancel := context.WithTimeout(context.Background(), 10*time.Second)
	dpKeys, dpActive, err := dpManager.Keyset(dpCtx)
	dpCancel()
	if err != nil {
		return err
	}
	cookieMgr := session.NewCookieManagerFromKeys(dpKeys, session.CookieConfig{
		Name:         cfg.EffectiveCookieName(),
		RequireHTTPS: cfg.RequireHTTPS,
		Path:         "/",
		MaxAge:       8 * time.Hour,
	}, clk)

	loginTmpl := template.Must(template.New("login").Parse(oidc.LoginTemplate()))
	registerTmpl := template.Must(template.New("register").Parse(oidc.RegisterTemplate()))
	logoutTmpl := template.Must(template.New("logout").Parse(oidc.LogoutTemplate()))

	loginHandler := &oidc.LoginHandler{
		Cfg: oidc.LoginConfig{
			IssuerURL:       cfg.Issuer,
			LoginPath:       cfg.LoginPath,
			RegisterPath:    cfg.RegisterPath,
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
	registerHandler := &oidc.RegisterHandler{
		Cfg: oidc.RegisterConfig{
			RegisterPath: cfg.RegisterPath,
			LoginPath:    cfg.LoginPath,
			IssuerURL:    cfg.Issuer,
		},
		Users:    bundle.Users,
		Clock:    clk,
		Logger:   logger,
		Template: registerTmpl,
	}
	// Single assertion cache shared by /connect/token and
	// /connect/revoke so a client_assertion JWT cannot be replayed
	// across endpoints.
	assertionCache := token.NewMemAssertionCache(clk.Now)

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
		ClientCredentials: &grants.ClientCredentialsGrant{
			Clients: bundle.Clients,
			Issuer:  issuer,
			Clock:   clk,
		Cfg: grants.ClientCredentialsConfig{
			AccessTokenLifetime: cfg.AccessTokenLifetime,
		},
		},
		ClientAuth: oidc.ClientAuthConfig{
			IssuerURL:        cfg.Issuer,
			TokenEndpointURL: cfg.Issuer + "/connect/token",
			AssertionCache:   assertionCache,
			AssertionSkew:    cfg.ClientAssertionClockSkew,
			Clock:            clk,
			Logger:           logger,
		},
		Clients: bundle.Clients,
		Clock:   clk,
		Logger:  logger,
	}
	userInfoHandler := oidc.NewUserInfoHandler(issuer, bundle.Users, logger)
	revokeHandler := &oidc.RevokeHandler{
		RefreshTokens: bundle.RefreshTokens,
		Clients:       bundle.Clients,
		ClientAuth: oidc.ClientAuthConfig{
			IssuerURL:        cfg.Issuer,
			TokenEndpointURL: cfg.Issuer + "/connect/token",
			AssertionCache:   assertionCache,
			AssertionSkew:    cfg.ClientAssertionClockSkew,
			Clock:            clk,
			Logger:           logger,
		},
		Now:    clk.Now,
		Logger: logger,
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

	// --- Admin API + SPA ---
	authMW, err := admin.AuthMiddleware(admin.AuthConfig{
		Token:          cfg.AdminToken,
		AllowAnonymous: cfg.AdminAllowAnonymous,
	}, logger)
	if err != nil {
		return err
	}
	csrfMW := admin.CSRFMiddleware(dpActive.CSRFKey)
	apiMux := http.NewServeMux()
	(&admin.API{
		Clients:       bundle.Clients,
		Scopes:        bundle.Scopes,
		Sessions:      bundle.Sessions,
		RefreshTokens: bundle.RefreshTokens,
		SigningKeys:   bundle.SigningKeys,
		AuditLogs:     bundle.AuditLogs,
		Users:         bundle.Users,
		Roles:         bundle.Roles,
		Clock:         clk,
		Logger:        logger,
	}).Mount(apiMux)
	// The API requires bearer auth; the SPA shell does not (it's
	// public HTML — the JS sends the token on API calls).
	apiHandler := authMW(csrfMW(apiMux))
	uiHandler := csrfMW(http.HandlerFunc(
		(&admin.UI{Template: template.Must(template.New("admin").Parse(admin.IndexPage())), Logger: logger}).ServeIndex,
	))
	adminMount := &server.AdminMount{
		Root: uiHandler,
		API:  apiHandler,
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
		Register:  registerHandler,
		Logout:    logoutHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		UserInfo:  userInfoHandler,
		Revoke:    revokeHandler,
		Discovery: oidc.NewDiscoveryHandler(cfg.Issuer, bundle.Scopes),
		JWKS:      oidc.NewJWKSHandler(issuer),
		Health:    server.NewHealth(),
		Admin:     adminMount,
	}
	router := server.NewRouter(
		server.RouterConfig{
			IssuerURL:         cfg.Issuer,
			RequireHTTPS:      cfg.RequireHTTPS,
			LoginPath:         cfg.LoginPath,
			RegisterPath:      cfg.RegisterPath,
			LogoutPath:        cfg.LogoutPath,
			AuthorizePath:     "/connect/authorize",
			TokenPath:         "/connect/token",
			UserInfoPath:      "/connect/userinfo",
			RevokePath:        "/connect/revoke",
			JWKSPath:          "/.well-known/jwks.json",
			DiscoveryPath:     "/.well-known/openid-configuration",
			HealthPath:        "/healthz",
			LoginRateLimitRPS: cfg.LoginRateLimit,
			LoginRateBurst:    cfg.LoginRateLimit, // burst == rps for the default config
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

// buildStores opens the PostgreSQL-backed store bundle. Postgres is the
// only runtime driver: the in-memory store is never used by the running
// server (it loses sessions and signing keys on restart and cannot be
// shared across instances), it exists solely for the test suite. The
// returned closer shuts the pool down and must be deferred by the caller.
//
// Schema migration is NOT run here — that is the job of the `migrate`
// command (or AUTH_AUTO_MIGRATE in run()). Opening the pool is cheap;
// migrating is what costs cold-start time.
func buildStores(driver, dsn string, now func() time.Time, logger *slog.Logger) (*storeBundle, *gorm.DB, func(), error) {
	drv := driver
	if drv == "" {
		drv = "postgres"
	}
	if drv != "postgres" {
		return nil, nil, nil, errors.New("unsupported DB driver " + strconv.Quote(drv) + "; the server runs on postgres only")
	}
	db, err := gormstore.Open(drv, dsn)
	if err != nil {
		return nil, nil, nil, err
	}
	if logger != nil {
		logger.Info("gormstore ready", "driver", drv)
	}
	closer := func() {
		sqlDB, err := db.DB()
		if err != nil {
			return
		}
		_ = sqlDB.Close()
	}
	return newGormBundle(db, now), db, closer, nil
}

// newGormBundle wires every GORM-backed store over a single *gorm.DB.
// The login-attempt tracker stays in memory in all cases (it is rate-limit
// state, not durable data). Shared by the serve and migrate paths.
func newGormBundle(db *gorm.DB, now func() time.Time) *storeBundle {
	return &storeBundle{
		Clients:        gormstore.NewClientStore(db),
		AuthCodes:      gormstore.NewAuthorizationCodeStore(db),
		RefreshTokens:  gormstore.NewRefreshTokenStore(db),
		Sessions:       gormstore.NewSessionStore(db),
		SigningKeys:    gormstore.NewSigningKeyStore(db),
		DataProtection: gormstore.NewDataProtectionKeyStore(db),
		Scopes:         gormstore.NewScopeStore(db),
		AuditLogs:      gormstore.NewAuditLogStore(db),
		Users:          gormstore.NewUserStore(db),
		Roles:          gormstore.NewRoleStore(db),
		// Persistent, cross-instance lockout tracker so brute-force limits
		// hold globally behind a load balancer.
		Tracker: gormstore.NewLoginAttemptTracker(db, now),
	}
}

// seedBundle writes the minimum sample data so the server is usable
// immediately without any admin UI: the four standard OIDC scopes, a
// public demo client, a confidential demo client (private_key_jwt
// with a freshly generated keypair), and a demo user.
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
	public := &domain.Client{
		ClientID:                "demo-public",
		DisplayName:             "Demo Public Client",
		RedirectURIs:            []string{"http://localhost:8090/callback", "https://demo.example/callback"},
		PostLogoutRedirectURIs:  []string{"http://localhost:8090/", "http://localhost:8090/logout-callback", "https://demo.example/"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}
	if err := b.Clients.Store(ctx, public); err != nil {
		return err
	}
	confidential, err := newSeededConfidentialClient()
	if err != nil {
		return err
	}
	if err := b.Clients.Store(ctx, confidential); err != nil {
		return err
	}

	adminRole := &domain.Role{ID: "role-admin", Name: "admin"}
	if err := b.Roles.CreateRole(ctx, adminRole); err != nil {
		if !errors.Is(err, store.ErrDuplicate) {
			return err
		}
	}

	now := time.Now().UTC()
	demoUser := &domain.User{
		ID:             "u-demo",
		Username:       "demo",
		Email:          "demo@example.com",
		EmailConfirmed: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := b.Users.CreateUser(ctx, demoUser, "demo"); err != nil {
		if !errors.Is(err, store.ErrDuplicate) {
			return err
		}
	}
	if err := b.Users.AddUserClaims(ctx, "u-demo", []domain.UserClaim{
		{Type: "name", Value: "Demo User"},
	}); err != nil {
		return err
	}
	if err := b.Users.AddToRoles(ctx, "u-demo", []string{"admin"}); err != nil {
		return err
	}
	return nil
}

// newSeededConfidentialClient generates a fresh RSA-2048 keypair,
// keeps the private key in memory (lost on restart — by design; this
// is a demo seed), and returns a *domain.Client with the public
// JWKS registered inline.
func newSeededConfidentialClient() (*domain.Client, error) {
	priv, err := token.GenerateRSAKey(token.RSAKeyBits)
	if err != nil {
		return nil, err
	}
	pubJWK, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "demo-confidential-kid"); err != nil {
		return nil, err
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	return &domain.Client{
		ClientID:                "demo-confidential",
		DisplayName:             "Demo Confidential Client",
		AllowedScopes:           []string{"read", "write", "openid"},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodPrivateKeyJWT,
		AllowClientCredentials:  true,
		JWKSJSON:                string(raw),
	}, nil
}
