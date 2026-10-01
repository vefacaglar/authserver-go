package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store/memory"

	"github.com/google/uuid"
)

func newTestResolver(t *testing.T) (*SessionResolver, *memory.SessionStore, *clock.FakeClock) {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	sessions := memory.NewSessionStore()
	cookies := session.NewCookieManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		session.CookieConfig{Name: ".auth.session", Path: "/"},
		clk,
	)
	return &SessionResolver{Cookies: cookies, Sessions: sessions, Clock: clk}, sessions, clk
}

func requestWithSession(t *testing.T, res *SessionResolver, id uuid.UUID) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := res.Cookies.SetCookie(rec, id); err != nil {
		t.Fatalf("set cookie: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/profile?x=1", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestRequireSession_AllowsActiveSession(t *testing.T) {
	res, sessions, clk := newTestResolver(t)
	sess := &domain.Session{ID: uuid.New(), UserID: "u-1", CreatedAt: clk.Now(), ExpiresAt: clk.Now().Add(time.Hour)}
	if err := sessions.Store(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	var got *domain.Session
	h := res.RequireSession("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = SessionFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, requestWithSession(t, res, sess.ID))

	if got == nil || got.UserID != "u-1" {
		t.Fatalf("session not in context: %+v", got)
	}
}

func TestRequireSession_RedirectsAnonymousWithReturnURL(t *testing.T) {
	res, _, _ := newTestResolver(t)
	h := res.RequireSession("/login", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next must not run for anonymous requests")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/profile?x=1", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?returnUrl=%2Fprofile%3Fx%3D1" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestRequireSession_RejectsRevokedAndExpired(t *testing.T) {
	res, sessions, clk := newTestResolver(t)
	revokedAt := clk.Now()
	revoked := &domain.Session{ID: uuid.New(), UserID: "u-1", CreatedAt: clk.Now(), ExpiresAt: clk.Now().Add(time.Hour), RevokedAt: &revokedAt}
	expired := &domain.Session{ID: uuid.New(), UserID: "u-1", CreatedAt: clk.Now(), ExpiresAt: clk.Now().Add(-time.Minute)}
	for _, s := range []*domain.Session{revoked, expired} {
		if err := sessions.Store(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	h := res.RequireSession("/login", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next must not run")
	}))
	for _, s := range []*domain.Session{revoked, expired} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, requestWithSession(t, res, s.ID))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", rec.Code)
		}
	}
}

func TestRequireSession_NonGETDropsReturnURL(t *testing.T) {
	res, _, _ := newTestResolver(t)
	h := res.RequireSession("/login", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/profile", nil))
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}
