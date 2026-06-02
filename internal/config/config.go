// Package config loads server configuration from environment variables and
// validates it at startup. Configuration is fail-fast: an invalid value
// causes Load to return a descriptive error and the process to exit.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer       string
	Listen       string
	RequireHTTPS bool

	DBDriver string
	DBDSN    string

	// AutoMigrate runs the GORM schema migration during server startup.
	// Convenient for dev and ephemeral (in-memory) databases, but it
	// adds noticeable cold-start latency for a persistent DB. In
	// serverless / production, set AUTH_AUTO_MIGRATE=false and run
	// `authserver migrate` once at deploy time instead.
	AutoMigrate bool

	// Seed writes the demo client/user/scope fixtures during startup.
	// Disable in production (AUTH_SEED=false); the `authserver migrate`
	// command seeds explicitly.
	Seed bool

	CookieName string

	LoginPath             string
	LogoutPath            string
	RegisterPath          string
	PostLogoutRedirectURI string

	AuthCodeLifetime             time.Duration
	AccessTokenLifetime          time.Duration
	IDTokenLifetime              time.Duration
	RefreshTokenLifetime         time.Duration
	RefreshTokenAbsoluteLifetime time.Duration
	DetectRefreshTokenReuse      bool
	ClientAssertionClockSkew     time.Duration
	RequirePKCE                  bool
	LoginRateLimit               int
	AdminAllowAnonymous          bool

	// AdminToken is the static bearer shared with admin operators.
	// When empty, the admin API is unreachable unless
	// AdminAllowAnonymous is set (which is a dev-only convenience).
	AdminToken string
}

func Load() (*Config, error) {
	c := &Config{
		Issuer:                       getenv("AUTH_ISSUER", ""),
		Listen:                       getenv("AUTH_LISTEN_ADDR", ":5175"),
		RequireHTTPS:                 getbool("AUTH_REQUIRE_HTTPS", true),
		DBDriver:                     getenv("AUTH_DB_DRIVER", "postgres"),
		DBDSN:                        getenv("AUTH_DB_DSN", "postgres://postgres:postgres@localhost:5432/authserver?sslmode=disable"),
		AutoMigrate:                  getbool("AUTH_AUTO_MIGRATE", true),
		Seed:                         getbool("AUTH_SEED", true),
		CookieName:                   getenv("AUTH_COOKIE_NAME", ".auth.session"),
		LoginPath:                    getenv("AUTH_LOGIN_PATH", "/login"),
		LogoutPath:                   getenv("AUTH_LOGOUT_PATH", "/logout"),
		RegisterPath:                 getenv("AUTH_REGISTER_PATH", "/register"),
		PostLogoutRedirectURI:        getenv("AUTH_POST_LOGOUT_REDIRECT_URI", "/"),
		AuthCodeLifetime:             getdur("AUTH_AUTH_CODE_LIFETIME", 60*time.Second),
		AccessTokenLifetime:          getdur("AUTH_ACCESS_TOKEN_LIFETIME", time.Hour),
		IDTokenLifetime:              getdur("AUTH_ID_TOKEN_LIFETIME", time.Hour),
		RefreshTokenLifetime:         getdur("AUTH_REFRESH_TOKEN_LIFETIME", 720*time.Hour),
		RefreshTokenAbsoluteLifetime: getdur("AUTH_REFRESH_TOKEN_ABS_LIFETIME", 720*time.Hour),
		DetectRefreshTokenReuse:      getbool("AUTH_DETECT_REFRESH_REUSE", true),
		ClientAssertionClockSkew:     getdur("AUTH_CLIENT_ASSERTION_CLOCK_SKEW", 60*time.Second),
		RequirePKCE:                  getbool("AUTH_REQUIRE_PKCE", true),
		LoginRateLimit:               getint("AUTH_LOGIN_RATE_LIMIT", 10),
		AdminAllowAnonymous:          getbool("AUTH_ADMIN_ALLOW_ANONYMOUS", false),
	}

	// Cookie + CSRF keys are no longer read from the environment: they live
	// in the data-protection key ring (data_protection_keys table),
	// generated server-side and shared across instances.
	c.AdminToken = getenv("AUTH_ADMIN_TOKEN", "")

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return errors.New("AUTH_ISSUER is required")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("AUTH_ISSUER: %w", err)
	}
	if !u.IsAbs() {
		return errors.New("AUTH_ISSUER must be an absolute URL")
	}
	if c.RequireHTTPS && u.Scheme != "https" {
		return errors.New("AUTH_ISSUER must use https when AUTH_REQUIRE_HTTPS=true")
	}
	if c.AuthCodeLifetime > 2*time.Minute {
		return errors.New("AUTH_AUTH_CODE_LIFETIME must be <= 2m")
	}
	if c.RefreshTokenAbsoluteLifetime < c.RefreshTokenLifetime {
		return errors.New("AUTH_REFRESH_TOKEN_ABS_LIFETIME must be >= AUTH_REFRESH_TOKEN_LIFETIME")
	}
	if c.AccessTokenLifetime <= 0 {
		return errors.New("AUTH_ACCESS_TOKEN_LIFETIME must be positive")
	}
	if c.IDTokenLifetime <= 0 {
		return errors.New("AUTH_ID_TOKEN_LIFETIME must be positive")
	}
	if c.LoginPath == "" || !strings.HasPrefix(c.LoginPath, "/") {
		return errors.New("AUTH_LOGIN_PATH must be an absolute path")
	}
	if c.LogoutPath == "" || !strings.HasPrefix(c.LogoutPath, "/") {
		return errors.New("AUTH_LOGOUT_PATH must be an absolute path")
	}
	if c.RegisterPath == "" || !strings.HasPrefix(c.RegisterPath, "/") {
		return errors.New("AUTH_REGISTER_PATH must be an absolute path")
	}
	if c.LoginRateLimit < 1 {
		return errors.New("AUTH_LOGIN_RATE_LIMIT must be >= 1")
	}
	if !c.AdminAllowAnonymous && strings.TrimSpace(c.AdminToken) == "" {
		return errors.New("AUTH_ADMIN_TOKEN must be set unless AUTH_ADMIN_ALLOW_ANONYMOUS=true")
	}
	// The server runs on PostgreSQL only. The in-memory store keeps
	// sessions, refresh tokens, and — critically — signing keys per-process:
	// they vanish on restart and differ across instances behind a load
	// balancer, so each would mint a different signing key and reject the
	// others' tokens. Never allow it as a runtime driver.
	if c.DBDriver != "postgres" {
		return fmt.Errorf("AUTH_DB_DRIVER must be \"postgres\" (got %q); the server runs on postgres only", c.DBDriver)
	}
	if strings.TrimSpace(c.DBDSN) == "" {
		return errors.New("AUTH_DB_DSN is required (a PostgreSQL DSN)")
	}
	return nil
}

// CookieName returns the cookie name honouring the __Host- prefix rule:
// when HTTPS is required the prefix is added and Domain must be empty. The
// returned name is also the one to send in Set-Cookie.
func (c *Config) EffectiveCookieName() string {
	if c.RequireHTTPS {
		return "__Host-" + c.CookieName
	}
	return c.CookieName
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getbool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getint(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func getdur(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
