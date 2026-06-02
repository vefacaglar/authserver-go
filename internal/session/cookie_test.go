package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestManager(t *testing.T, requireHTTPS bool) *CookieManager {
	t.Helper()
	hash := []byte("0123456789abcdef0123456789abcdef")  // 32 bytes
	block := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345") // 32 bytes
	name := ".auth.session"
	if requireHTTPS {
		// Per the __Host- prefix rules the cookie name itself must already
		// carry the prefix when HTTPS is required.
		name = "__Host-" + name
	}
	cfg := CookieConfig{
		Name:         name,
		RequireHTTPS: requireHTTPS,
		Path:         "/",
	}
	return NewCookieManager(hash, block, cfg)
}

func TestCookie_RoundTrip(t *testing.T) {
	m := newTestManager(t, false)
	id := uuid.New()
	encoded, err := m.Encode(id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := m.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != id {
		t.Errorf("round-trip: got %s, want %s", got, id)
	}
}

func TestCookie_RejectsTamperedValue(t *testing.T) {
	m := newTestManager(t, false)
	id := uuid.New()
	encoded, err := m.Encode(id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Flip the last character of the cookie.
	tampered := encoded[:len(encoded)-1]
	if encoded[len(encoded)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}
	if _, err := m.Decode(tampered); err == nil {
		t.Errorf("Decode accepted a tampered cookie")
	}
}

func TestSetCookie_SetsHttpOnlyAndSameSite(t *testing.T) {
	m := newTestManager(t, true)
	id := uuid.New()
	rr := httptest.NewRecorder()
	if err := m.SetCookie(rr, id); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	res := rr.Result()
	defer res.Body.Close()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Errorf("HttpOnly = false")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v", c.SameSite)
	}
	if !c.Secure {
		t.Errorf("Secure = false under RequireHTTPS")
	}
	if c.Name != "__Host-.auth.session" {
		t.Errorf("Name = %q, want __Host-.auth.session", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
}

func TestSetCookie_NoSecureOrPrefixWithoutHTTPS(t *testing.T) {
	m := newTestManager(t, false)
	rr := httptest.NewRecorder()
	if err := m.SetCookie(rr, uuid.New()); err != nil {
		t.Fatalf("SetCookie: %v", err)
	}
	c := rr.Result().Cookies()[0]
	if c.Secure {
		t.Errorf("Secure = true over plain HTTP")
	}
	if c.Name != ".auth.session" {
		t.Errorf("Name = %q, want .auth.session", c.Name)
	}
}

func TestFromRequest_MissingCookie(t *testing.T) {
	m := newTestManager(t, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := m.FromRequest(r); err == nil {
		t.Errorf("FromRequest on request without cookie returned nil error")
	}
}

func TestFromRequest_RejectsForged(t *testing.T) {
	m := newTestManager(t, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: m.config.Name, Value: "garbage"})
	if _, err := m.FromRequest(r); err == nil {
		t.Errorf("FromRequest accepted a forged cookie")
	}
}

func TestClearCookie_SetsExpiredCookie(t *testing.T) {
	m := newTestManager(t, true)
	rr := httptest.NewRecorder()
	m.ClearCookie(rr)
	c := rr.Result().Cookies()[0]
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", c.MaxAge)
	}
	if !c.Expires.Before(time.Now()) {
		t.Errorf("Expires = %v, want before now", c.Expires)
	}
}
