// Package config loads server configuration from environment variables and
// validates it at startup. Configuration is fail-fast: an invalid value
// causes Load to return a descriptive error and the process to exit.
package config

import (
	"encoding/base64"
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

	CookieName  string
	CookieHMAC  []byte
	CookieBlock []byte

	LoginPath             string
	LogoutPath            string
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

	CSRFKey []byte
}

func Load() (*Config, error) {
	c := &Config{
		Issuer:                       getenv("AUTH_ISSUER", ""),
		Listen:                       getenv("AUTH_LISTEN_ADDR", ":5175"),
		RequireHTTPS:                 getbool("AUTH_REQUIRE_HTTPS", true),
		DBDriver:                     getenv("AUTH_DB_DRIVER", "sqlite"),
		DBDSN:                        getenv("AUTH_DB_DSN", "file::memory:?cache=shared"),
		CookieName:                   getenv("AUTH_COOKIE_NAME", ".auth.session"),
		LoginPath:                    getenv("AUTH_LOGIN_PATH", "/login"),
		LogoutPath:                   getenv("AUTH_LOGOUT_PATH", "/logout"),
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

	var err error
	if c.CookieHMAC, err = decodeB64(getenv("AUTH_COOKIE_HASH_KEY", ""), 32); err != nil {
		return nil, fmt.Errorf("AUTH_COOKIE_HASH_KEY: %w", err)
	}
	if c.CookieBlock, err = decodeB64(getenv("AUTH_COOKIE_BLOCK_KEY", ""), 32); err != nil {
		return nil, fmt.Errorf("AUTH_COOKIE_BLOCK_KEY: %w", err)
	}
	if c.CSRFKey, err = decodeB64(getenv("AUTH_CSRF_KEY", ""), 32); err != nil {
		return nil, fmt.Errorf("AUTH_CSRF_KEY: %w", err)
	}

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
	if len(c.CookieHMAC) == 0 || len(c.CookieBlock) == 0 {
		return errors.New("AUTH_COOKIE_HASH_KEY and AUTH_COOKIE_BLOCK_KEY are required")
	}
	if len(c.CSRFKey) == 0 {
		return errors.New("AUTH_CSRF_KEY is required")
	}
	if c.LoginRateLimit < 1 {
		return errors.New("AUTH_LOGIN_RATE_LIMIT must be >= 1")
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

// decodeB64 decodes a base64 (std or URL) string and asserts a minimum
// length. Empty input is allowed and yields a zero-length slice.
func decodeB64(s string, minLen int) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				b, err = base64.RawURLEncoding.DecodeString(s)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(b) < minLen {
		return nil, fmt.Errorf("decoded length %d < required %d", len(b), minLen)
	}
	return b, nil
}
