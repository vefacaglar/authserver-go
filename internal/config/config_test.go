package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func env(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
	// Every test must opt-in to admin auth somehow. The default
	// is to set a non-empty static token so production-shaped
	// configs are exercised.
	if _, ok := kv["AUTH_ADMIN_TOKEN"]; !ok {
		if _, ok := kv["AUTH_ADMIN_ALLOW_ANONYMOUS"]; !ok {
			t.Setenv("AUTH_ADMIN_TOKEN", "test-admin-token")
		}
	}
}

func TestLoad_Valid(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":           "https://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":  b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY": b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":         b64(make([]byte, 32)),
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if !cfg.RequireHTTPS {
		t.Errorf("RequireHTTPS default should be true")
	}
	if cfg.AuthCodeLifetime != 60*time.Second {
		t.Errorf("AuthCodeLifetime = %v", cfg.AuthCodeLifetime)
	}
}

func TestLoad_RejectsMissingIssuer(t *testing.T) {
	env(t, map[string]string{
		"AUTH_COOKIE_HASH_KEY":  b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY": b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":         b64(make([]byte, 32)),
	})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_ISSUER") {
		t.Fatalf("Load = %v, want issuer error", err)
	}
}

func TestLoad_RejectsHTTPWhenRequireHTTPS(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":           "http://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":  b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY": b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":         b64(make([]byte, 32)),
	})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Load = %v, want https error", err)
	}
}

func TestLoad_RejectsAuthCodeLifetimeOver2m(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":             "https://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":    b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY":   b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":           b64(make([]byte, 32)),
		"AUTH_AUTH_CODE_LIFETIME": "3m",
	})
	if _, err := Load(); err == nil {
		t.Fatalf("Load accepted auth-code lifetime > 2m")
	}
}

func TestLoad_RejectsAbsoluteShorterThanSliding(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":                     "https://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":            b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY":           b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":                   b64(make([]byte, 32)),
		"AUTH_REFRESH_TOKEN_LIFETIME":     "720h",
		"AUTH_REFRESH_TOKEN_ABS_LIFETIME": "100h",
	})
	if _, err := Load(); err == nil {
		t.Fatalf("Load accepted abs lifetime < sliding lifetime")
	}
}

func TestLoad_DoesNotRequireCookieKeys(t *testing.T) {
	// Cookie + CSRF keys now come from the data-protection key ring in the
	// database, not the environment, so Load must succeed without them.
	env(t, map[string]string{
		"AUTH_ISSUER": "https://auth.example.com",
	})
	if _, err := Load(); err != nil {
		t.Fatalf("Load = %v, want success without cookie keys", err)
	}
}

func TestEffectiveCookieName(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":           "https://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":  b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY": b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":         b64(make([]byte, 32)),
	})
	cfg, _ := Load()
	if !strings.HasPrefix(cfg.EffectiveCookieName(), "__Host-") {
		t.Errorf("EffectiveCookieName = %q, want __Host- prefix under HTTPS", cfg.EffectiveCookieName())
	}
}

func TestLoad_RejectsAdminMisconfigured(t *testing.T) {
	// No admin token, no anonymous flag → must fail.
	t.Setenv("AUTH_ISSUER", "https://auth.example.com")
	t.Setenv("AUTH_COOKIE_HASH_KEY", b64(make([]byte, 32)))
	t.Setenv("AUTH_COOKIE_BLOCK_KEY", b64(make([]byte, 32)))
	t.Setenv("AUTH_CSRF_KEY", b64(make([]byte, 32)))
	t.Setenv("AUTH_ADMIN_TOKEN", "")
	t.Setenv("AUTH_ADMIN_ALLOW_ANONYMOUS", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_ADMIN_TOKEN") {
		t.Fatalf("Load = %v, want admin-token error", err)
	}
}

func TestLoad_AdminAnonymousAccepted(t *testing.T) {
	env(t, map[string]string{
		"AUTH_ISSUER":                "https://auth.example.com",
		"AUTH_COOKIE_HASH_KEY":       b64(make([]byte, 32)),
		"AUTH_COOKIE_BLOCK_KEY":      b64(make([]byte, 32)),
		"AUTH_CSRF_KEY":              b64(make([]byte, 32)),
		"AUTH_ADMIN_ALLOW_ANONYMOUS": "true",
		// AUTH_ADMIN_TOKEN intentionally unset.
	})
	if _, err := Load(); err != nil {
		t.Fatalf("Load with anonymous admin: %v", err)
	}
}
