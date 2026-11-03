package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	cfg := LoginConfig{
		IssuerURL:       "https://auth.example.com",
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
		// Default to a fixed "test" IP so existing tests are
		// deterministic. The lockout tests override this with a
		// request-scoped extractor to exercise per-IP isolation.
		ClientIP: func(*http.Request) string { return "test-ip" },
	}
	return h, users, sessions
}

// issueTestCSRF mints a CSRF token the way GET /api/csrf does and
// returns the token plus the cookie a browser would send back.
func issueTestCSRF(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	tok, err := APICSRFGuard(false).Issue(rec)
	if err != nil {
		t.Fatalf("issue csrf: %v", err)
	}
	c := findCookie(rec.Result().Cookies(), csrfCookieName)
	if c == nil {
		t.Fatal("csrf cookie not set")
	}
	return tok, c
}

// postLogin posts one JSON login attempt with a valid CSRF pair.
func postLogin(t *testing.T, h *LoginHandler, username, password, returnURL string) *httptest.ResponseRecorder {
	t.Helper()
	tok, cookie := issueTestCSRF(t)
	body, _ := json.Marshal(loginRequest{Username: username, Password: password, ReturnURL: returnURL})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, tok)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return body.Error
}

func decodeRedirect(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode redirect body %q: %v", rr.Body.String(), err)
	}
	return body.Redirect
}

func TestLogin_GET_MethodNotAllowed(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth/login", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestLogin_POST_ValidCredentials_ReturnsRedirectAndSetsCookie(t *testing.T) {
	h, _, sessions := newTestLoginHandler(t)
	rr := postLogin(t, h, "alice", "s3cr3t", "/connect/authorize")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := decodeRedirect(t, rr); got != "/connect/authorize" {
		t.Errorf("redirect = %q, want /connect/authorize", got)
	}
	if findCookie(rr.Result().Cookies(), ".auth.session") == nil {
		t.Errorf("session cookie not set")
	}
	all, _ := sessions.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if all.TotalCount != 1 {
		t.Errorf("sessions in store = %d, want 1", all.TotalCount)
	}
}

func TestLogin_POST_RejectsBadPassword(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := postLogin(t, h, "alice", "WRONG", "/connect/authorize")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if code := decodeErrorCode(t, rr); code != LoginErrInvalidCredentials {
		t.Errorf("error = %q, want %q", code, LoginErrInvalidCredentials)
	}
	if findCookie(rr.Result().Cookies(), ".auth.session") != nil {
		t.Errorf("session cookie must not be set on bad password")
	}
}

func TestLogin_POST_MissingCSRF_Rejected(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	body, _ := json.Marshal(loginRequest{Username: "alice", Password: "s3cr3t"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if code := decodeErrorCode(t, rr); code != LoginErrAntiforgeryFailed {
		t.Errorf("error = %q, want %q", code, LoginErrAntiforgeryFailed)
	}
}

func TestLogin_POST_RejectsOpenRedirect(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := postLogin(t, h, "alice", "s3cr3t", "https://evil.example/cb")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if code := decodeErrorCode(t, rr); code != LoginErrInvalidReturn {
		t.Errorf("error = %q, want %q", code, LoginErrInvalidReturn)
	}
}

// A successful login with no return_url lands on the home page ("/"),
// as a relative path so the user stays on the host that served the SPA.
func TestLogin_POST_EmptyReturnUrl_RedirectsToHome(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := postLogin(t, h, "alice", "s3cr3t", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := decodeRedirect(t, rr); got != "/" {
		t.Errorf("redirect = %q, want /", got)
	}
	if findCookie(rr.Result().Cookies(), ".auth.session") == nil {
		t.Errorf("session cookie must be set on successful login")
	}
}

// A return_url that passes URL parsing but is not on the allow-list
// still triggers invalid_return. Pinning the behaviour so a refactor
// of validateReturnURL does not silently widen the allow-list.
func TestLogin_POST_DisallowedPathReturnUrl_Rejects(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	rr := postLogin(t, h, "alice", "s3cr3t", "/admin")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if code := decodeErrorCode(t, rr); code != LoginErrInvalidReturn {
		t.Errorf("error = %q, want %q", code, LoginErrInvalidReturn)
	}
}

func TestLogin_POST_LockedOut(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	// Drive enough failures to lock the account.
	for i := 0; i < 6; i++ {
		postLogin(t, h, "alice", "WRONG", "")
	}

	// One more attempt should be locked out even with the right password.
	rr := postLogin(t, h, "alice", "s3cr3t", "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if code := decodeErrorCode(t, rr); code != LoginErrAccountLocked {
		t.Errorf("error = %q, want %q", code, LoginErrAccountLocked)
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

// The lockout key must bind the username to the source IP. A
// username-only key would let a distributed attacker rotate IPs and
// accumulate MaxFailures against a single account without being
// slowed by the per-IP rate limiter, because the rate limiter and the
// lockout counter would run on independent axes. Composing the two
// keys ties them together.
//
// Two behaviours are pinned here:
//
//  1. The same username from different IPs is tracked separately.
//  2. The same (username, IP) pair shares a counter. Hitting
//     MaxFailures locks that pair, but a different IP for the same
//     username is not affected.
func TestLogin_LockoutKey_BindsUsernameAndIP(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	tracker, ok := h.Tracker.(*memory.LoginAttemptTracker)
	if !ok {
		t.Fatalf("tracker is %T, want *memory.LoginAttemptTracker", h.Tracker)
	}
	tracker.MaxFailures = 3

	post := func(ip string) *httptest.ResponseRecorder {
		h.ClientIP = func(*http.Request) string { return ip }
		return postLogin(t, h, "alice", "WRONG", "")
	}

	// 3 failures from 10.0.0.1 → that key locks.
	for i := 0; i < 3; i++ {
		rr := post("10.0.0.1")
		if code := decodeErrorCode(t, rr); code != LoginErrInvalidCredentials {
			t.Fatalf("failure #%d: error = %q, want invalid_credentials", i+1, code)
		}
	}
	// A 4th attempt from the same IP must see the lock.
	if code := decodeErrorCode(t, post("10.0.0.1")); code != LoginErrAccountLocked {
		t.Errorf("locked: error = %q, want account_locked", code)
	}

	// The same username from a different IP is on a separate key
	// and is NOT locked.
	if code := decodeErrorCode(t, post("10.0.0.2")); code != LoginErrInvalidCredentials {
		t.Errorf("different IP first failure: error = %q, want invalid_credentials (not locked)", code)
	}
}

// A successful login from IP #1 does not clear the lockout for IP #2 —
// the keys are independent.
func TestLogin_LockoutKey_ResetsAcrossIPs(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	tracker, ok := h.Tracker.(*memory.LoginAttemptTracker)
	if !ok {
		t.Fatalf("tracker is %T, want *memory.LoginAttemptTracker", h.Tracker)
	}
	tracker.MaxFailures = 2

	post := func(ip string) *httptest.ResponseRecorder {
		h.ClientIP = func(*http.Request) string { return ip }
		return postLogin(t, h, "alice", "WRONG", "")
	}

	// IP #1: lock.
	post("192.168.1.1")
	post("192.168.1.1")
	if code := decodeErrorCode(t, post("192.168.1.1")); code != LoginErrAccountLocked {
		t.Errorf("IP #1 must be locked; error = %q", code)
	}

	// IP #2: a single failure must report invalid_credentials, not
	// the lock from IP #1.
	if code := decodeErrorCode(t, post("192.168.1.2")); code != LoginErrInvalidCredentials {
		t.Errorf("IP #2 must be unaffected by IP #1's lockout; error = %q", code)
	}
}

// ClientIP must read the IP from the composer's ClientIP function
// (which honours X-Forwarded-For via server.ClientIP), so a
// misconfigured reverse proxy that loses the real client IP is not
// silently downgraded to a single global key.
func TestLogin_LockoutKey_HonorsXFF(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	tracker, ok := h.Tracker.(*memory.LoginAttemptTracker)
	if !ok {
		t.Fatalf("tracker is %T, want *memory.LoginAttemptTracker", h.Tracker)
	}
	// MaxFailures=2 so the (N+1)-th failure triggers the lock.
	tracker.MaxFailures = 2

	// Use the same XFF-aware extractor that production wiring
	// installs. This is server.ClientIP, copy-pasted here to keep
	// the test self-contained without an import cycle.
	h.ClientIP = func(r *http.Request) string {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
		return r.RemoteAddr
	}

	post := func(xff string) *httptest.ResponseRecorder {
		tok, cookie := issueTestCSRF(t)
		body, _ := json.Marshal(loginRequest{Username: "alice", Password: "WRONG"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeaderName, tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		req.RemoteAddr = "10.10.10.10:5555"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// MaxFailures=2: the handler checks IsLockedOut BEFORE recording
	// the failure, so the lock set on the second failure is only
	// observable on the third attempt.
	if code := decodeErrorCode(t, post("1.1.1.1")); code != LoginErrInvalidCredentials {
		t.Fatalf("first failure: error = %q", code)
	}
	if code := decodeErrorCode(t, post("1.1.1.1")); code != LoginErrInvalidCredentials {
		t.Errorf("second failure: error = %q, want invalid_credentials (lock set, not yet observed)", code)
	}
	if code := decodeErrorCode(t, post("1.1.1.1")); code != LoginErrAccountLocked {
		t.Errorf("third failure same XFF: error = %q, want account_locked", code)
	}

	// Different XFF → fresh key, fresh failure counter.
	if code := decodeErrorCode(t, post("2.2.2.2")); code != LoginErrInvalidCredentials {
		t.Errorf("different XFF: error = %q, want invalid_credentials (not locked)", code)
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
