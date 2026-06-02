package oidc

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store/memory"
)

func newTestLoginHandler(t *testing.T) (*LoginHandler, *memory.UserStore, *memory.SessionStore) {
	t.Helper()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	now := clk.Now()
	_ = users.CreateUser(context.Background(), &domain.User{
		ID:        "u-1",
		Username:  "alice",
		CreatedAt: now,
		UpdatedAt: now,
	}, "s3cr3t")
	_ = users.AddUserClaims(context.Background(), "u-1", []domain.UserClaim{
		{Type: "preferred_username", Value: "alice"},
	})
	cookies := session.NewCookieManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		session.CookieConfig{Name: ".auth.session", Path: "/"},
		clk,
	)
	tracker := memory.NewLoginAttemptTracker(clk.Now)
	tmpl := template.Must(template.New("login").Parse(loginHTML))
	cfg := LoginConfig{
		IssuerURL:       "https://auth.example.com",
		LoginPath:       "/login",
		AuthorizePath:   "/connect/authorize",
		SessionLifetime: time.Hour,
	}
	h := &LoginHandler{
		Cfg:      cfg,
		Users:    users,
		Sessions: sessions,
		Cookies:  cookies,
		Tracker:  tracker,
		Clock:    clk,
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Template: tmpl,
	}
	return h, users, sessions
}

func TestLogin_GET_RendersFormWithCSRF(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Errorf("form missing csrf_token input")
	}
	if !strings.Contains(body, `name="returnUrl"`) {
		t.Errorf("form missing returnUrl input")
	}
	if !strings.Contains(body, `name="username"`) || !strings.Contains(body, `name="password"`) {
		t.Errorf("form missing username/password")
	}
	if findCookie(rr.Result().Cookies(), csrfCookieName) == nil {
		t.Errorf("csrf cookie not set")
	}
}

func TestLogin_GET_ShowsErrorLabel(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login?error=invalid_credentials", nil))
	if !strings.Contains(rr.Body.String(), "Invalid username or password.") {
		t.Errorf("expected error label, got %s", rr.Body.String())
	}
}

func TestLogin_POST_ValidCredentials_RedirectsAndSetsCookie(t *testing.T) {
	h, _, sessions := newTestLoginHandler(t)

	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login?returnUrl=/connect/authorize", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)
	if csrfCookie == nil {
		t.Fatalf("csrf cookie not set")
	}

	postRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=s3cr3t&csrf_token="+url.QueryEscape(csrfToken)+"&returnUrl=/connect/authorize"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	h.ServeHTTP(postRR, req)

	if postRR.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", postRR.Code, postRR.Body.String())
	}
	loc := postRR.Header().Get("Location")
	if loc != "/connect/authorize" {
		t.Errorf("Location = %q, want /connect/authorize", loc)
	}
	if findCookie(postRR.Result().Cookies(), ".auth.session") == nil {
		t.Errorf("session cookie not set")
	}
	all, _ := sessions.GetPaged(req.Context(), domain.PagedRequest{Page: 1, PageSize: 10})
	if all.TotalCount != 1 {
		t.Errorf("sessions in store = %d, want 1", all.TotalCount)
	}
}

func TestLogin_POST_RejectsBadPassword(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)

	postRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=WRONG&csrf_token="+url.QueryEscape(csrfToken)+"&returnUrl=/connect/authorize"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	h.ServeHTTP(postRR, req)

	if postRR.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", postRR.Code)
	}
	loc := postRR.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_credentials") {
		t.Errorf("Location = %q, want error=invalid_credentials", loc)
	}
	if !strings.Contains(loc, "returnUrl=") {
		t.Errorf("Location = %q, want returnUrl= preserved", loc)
	}
	if findCookie(postRR.Result().Cookies(), ".auth.session") != nil {
		t.Errorf("session cookie must not be set on bad password")
	}
}

func TestLogin_POST_MissingCSRF_Rejected(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=s3cr3t"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect back with antiforgery error)", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "error=antiforgery_failed") {
		t.Errorf("Location = %q, want error=antiforgery_failed", loc)
	}
}

func TestLogin_POST_RejectsOpenRedirect(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)

	postRR := httptest.NewRecorder()
	body := "username=alice&password=s3cr3t&csrf_token=" + url.QueryEscape(csrfToken) + "&returnUrl=https://evil.example/cb"
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	h.ServeHTTP(postRR, req)

	if postRR.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", postRR.Code)
	}
	loc := postRR.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_return") {
		t.Errorf("Location = %q, want error=invalid_return", loc)
	}
}

func TestLogin_POST_LockedOut(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	// Drive enough failures to lock the account.
	tracker := h.Tracker
	for i := 0; i < 6; i++ {
		getRR := httptest.NewRecorder()
		h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
		csrfToken := extractCSRFToken(t, getRR.Body.String())
		csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=WRONG&csrf_token="+url.QueryEscape(csrfToken)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}
	_ = tracker

	// One more attempt should be locked out even with the right password.
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=s3cr3t&csrf_token="+url.QueryEscape(csrfToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "error=account_locked") {
		t.Errorf("Location = %q, want account_locked", loc)
	}
}

func TestValidateReturnURL_AllowsIssuerOrigin(t *testing.T) {
	got, err := validateReturnURL("https://auth.example.com/connect/authorize?x=1", "https://auth.example.com", "/connect/authorize")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasPrefix(got, "https://auth.example.com/connect/authorize") {
		t.Errorf("got %q", got)
	}
}

func TestValidateReturnURL_RejectsProtocolRelative(t *testing.T) {
	if _, err := validateReturnURL("//evil.example/cb", "https://auth.example.com", "/connect/authorize"); err == nil {
		t.Errorf("protocol-relative URL accepted")
	}
}

func TestValidateReturnURL_RejectsUnknownPath(t *testing.T) {
	if _, err := validateReturnURL("/admin", "https://auth.example.com", "/connect/authorize"); err == nil {
		t.Errorf("unknown path accepted")
	}
}

func TestValidateReturnURL_AllowsLogout(t *testing.T) {
	got, err := validateReturnURL("/logout", "https://auth.example.com", "/connect/authorize")
	if err != nil || got != "/logout" {
		t.Errorf("got %q err %v", got, err)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	u, err := url.Parse("http://x/?" + extractAttr(body, `name="csrf_token"`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return u.Query().Get("value")
}

func extractAttr(body, attrFragment string) string {
	i := strings.Index(body, attrFragment)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	j := strings.Index(rest, "value=\"")
	if j < 0 {
		return ""
	}
	rest = rest[j+len("value=\""):]
	k := strings.Index(rest, "\"")
	if k < 0 {
		return ""
	}
	return "value=" + rest[:k]
}
