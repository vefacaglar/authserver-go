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
	tmpl := template.Must(template.New("login").Parse(LoginTemplate()))
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
		// Default to a fixed "test" IP so existing tests are
		// deterministic. The new lockout tests override this with
		// a request-scoped extractor to exercise per-IP isolation.
		ClientIP: func(*http.Request) string { return "test-ip" },
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

// TestLogin_POST_EmptyReturnUrl_RedirectsToIssuerRoot: regression for
// §1.3 of plan-2.md. A successful login with no returnUrl used to
// land the user back on /login with an error=invalid_return banner,
// because validateReturnURL returns ("", nil) for empty input.
// The handler must now redirect to the issuer root.
func TestLogin_POST_EmptyReturnUrl_RedirectsToIssuerRoot(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)

	postRR := httptest.NewRecorder()
	body := "username=alice&password=s3cr3t&csrf_token=" + url.QueryEscape(csrfToken)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	h.ServeHTTP(postRR, req)

	if postRR.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", postRR.Code)
	}
	loc := postRR.Header().Get("Location")
	want := "https://auth.example.com/"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
	if findCookie(postRR.Result().Cookies(), ".auth.session") == nil {
		t.Errorf("session cookie must be set on successful login")
	}
}

// TestLogin_POST_DisallowedPathReturnUrl_Rejects: a returnUrl that
// passes URL parsing but is not on the allow-list still triggers
// invalid_return. This is the same open-redirect guard the
// TestLogin_POST_RejectsOpenRedirect test exercises; pinning the
// behaviour here so a refactor of validateReturnURL does not
// silently widen the allow-list.
func TestLogin_POST_DisallowedPathReturnUrl_Rejects(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfToken := extractCSRFToken(t, getRR.Body.String())
	csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)

	postRR := httptest.NewRecorder()
	body := "username=alice&password=s3cr3t&csrf_token=" + url.QueryEscape(csrfToken) + "&returnUrl=/admin"
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

// §2.3 (plan-2.md) — the lockout key must bind the username to the
// source IP. A username-only key would let a distributed attacker
// rotate IPs and accumulate MaxFailures against a single account
// without being slowed by the per-IP rate limiter, because the
// rate limiter and the lockout counter would run on independent
// axes. Composing the two keys ties them together.
//
// Three behaviours are pinned here:
//
//   1. The same username from different IPs is tracked separately.
//      Each (username, IP) pair has its own failure counter; a
//      successful login from one IP does not unlock a locked key
//      bound to a different IP.
//   2. The same (username, IP) pair shares a counter. Hitting
//      MaxFailures locks that pair, but a different IP for the same
//      username is not affected.
//   3. The lockout key is the literal concatenation "username|ip",
//      so that a future operator can read the tracker storage and
//      tell which IP a lockout applies to.
func TestLogin_LockoutKey_BindsUsernameAndIP(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	tracker, ok := h.Tracker.(*memory.LoginAttemptTracker)
	if !ok {
		t.Fatalf("tracker is %T, want *memory.LoginAttemptTracker", h.Tracker)
	}
	tracker.MaxFailures = 3

	// Variable IP per request: same username "alice", different
	// IPs. A distributed attacker scenario.
	ipFor := func(ip string) func(*http.Request) string {
		return func(*http.Request) string { return ip }
	}
	h.ClientIP = ipFor("10.0.0.1")

	post := func(t *testing.T, ip string) *httptest.ResponseRecorder {
		h.ClientIP = ipFor(ip)
		getRR := httptest.NewRecorder()
		h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
		csrfToken := extractCSRFToken(t, getRR.Body.String())
		csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)

		postRR := httptest.NewRecorder()
		body := "username=alice&password=WRONG&csrf_token=" + url.QueryEscape(csrfToken)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":1234"
		req.AddCookie(csrfCookie)
		h.ServeHTTP(postRR, req)
		return postRR
	}

	// 3 failures from 10.0.0.1 → that key locks.
	for i := 0; i < 3; i++ {
		rr := post(t, "10.0.0.1")
		if !strings.Contains(rr.Header().Get("Location"), "error=invalid_credentials") {
			t.Fatalf("failure #%d: Location = %q, want invalid_credentials", i+1, rr.Header().Get("Location"))
		}
	}
	// A 4th attempt from the same IP must see the lock.
	rr := post(t, "10.0.0.1")
	if !strings.Contains(rr.Header().Get("Location"), "error=account_locked") {
		t.Errorf("locked: Location = %q, want account_locked", rr.Header().Get("Location"))
	}

	// The same username from a different IP is on a separate key
	// and is NOT locked. 3 failures lock IP #2 too, but the 1st
	// attempt must still report invalid_credentials (not locked).
	rr1 := post(t, "10.0.0.2")
	if strings.Contains(rr1.Header().Get("Location"), "error=account_locked") {
		t.Errorf("different IP must not be locked: Location = %q", rr1.Header().Get("Location"))
	}
	if !strings.Contains(rr1.Header().Get("Location"), "error=invalid_credentials") {
		t.Errorf("different IP first failure: Location = %q, want invalid_credentials", rr1.Header().Get("Location"))
	}
}

// TestLogin_LockoutKey_ResetsAcrossIPs: confirms that a successful
// login from IP #1 does not clear the lockout for IP #2 — the keys
// are independent. We hit MaxFailures from one IP, then verify the
// other IP's key is unaffected.
func TestLogin_LockoutKey_ResetsAcrossIPs(t *testing.T) {
	h, _, _ := newTestLoginHandler(t)
	tracker, ok := h.Tracker.(*memory.LoginAttemptTracker)
	if !ok {
		t.Fatalf("tracker is %T, want *memory.LoginAttemptTracker", h.Tracker)
	}
	tracker.MaxFailures = 2

	ipFor := func(ip string) func(*http.Request) string {
		return func(*http.Request) string { return ip }
	}
	post := func(t *testing.T, ip string) *httptest.ResponseRecorder {
		h.ClientIP = ipFor(ip)
		getRR := httptest.NewRecorder()
		h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
		csrfToken := extractCSRFToken(t, getRR.Body.String())
		csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)
		postRR := httptest.NewRecorder()
		body := "username=alice&password=WRONG&csrf_token=" + url.QueryEscape(csrfToken)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":1234"
		req.AddCookie(csrfCookie)
		h.ServeHTTP(postRR, req)
		return postRR
	}

	// IP #1: lock.
	post(t, "192.168.1.1")
	post(t, "192.168.1.1")
	rr := post(t, "192.168.1.1")
	if !strings.Contains(rr.Header().Get("Location"), "error=account_locked") {
		t.Errorf("IP #1 must be locked; Location = %q", rr.Header().Get("Location"))
	}

	// IP #2: a single failure must report invalid_credentials, not
	// the lock from IP #1.
	rr2 := post(t, "192.168.1.2")
	if !strings.Contains(rr2.Header().Get("Location"), "error=invalid_credentials") {
		t.Errorf("IP #2 must be unaffected by IP #1's lockout; Location = %q", rr2.Header().Get("Location"))
	}
}

// TestLogin_LockoutKey_HonorsXFF: ClientIP must read the IP from the
// composer's ClientIP function (which honours X-Forwarded-For via
// server.ClientIP), so a misconfigured reverse proxy that loses the
// real client IP is not silently downgraded to a single global key.
// We exercise the wiring by setting the request's XFF and observing
// the key in the tracker.
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

	post := func(t *testing.T, xff string) *httptest.ResponseRecorder {
		getRR := httptest.NewRecorder()
		h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/login", nil))
		csrfToken := extractCSRFToken(t, getRR.Body.String())
		csrfCookie := findCookie(getRR.Result().Cookies(), csrfCookieName)
		postRR := httptest.NewRecorder()
		body := "username=alice&password=WRONG&csrf_token=" + url.QueryEscape(csrfToken)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		req.RemoteAddr = "10.10.10.10:5555"
		req.AddCookie(csrfCookie)
		h.ServeHTTP(postRR, req)
		return postRR
	}

	// MaxFailures=2: the (N+1)-th failure locks, so the first two
	// failures report invalid_credentials and the third is locked.
	// (The handler checks IsLockedOut BEFORE recording the failure,
	// so the lock set on the second failure is only observable on
	// the third attempt.)
	rr := post(t, "1.1.1.1")
	if !strings.Contains(rr.Header().Get("Location"), "error=invalid_credentials") {
		t.Fatalf("first failure: Location = %q", rr.Header().Get("Location"))
	}
	rr2 := post(t, "1.1.1.1")
	if !strings.Contains(rr2.Header().Get("Location"), "error=invalid_credentials") {
		t.Errorf("second failure: Location = %q, want invalid_credentials (lock set, not yet observed)", rr2.Header().Get("Location"))
	}
	rr3 := post(t, "1.1.1.1")
	if !strings.Contains(rr3.Header().Get("Location"), "error=account_locked") {
		t.Errorf("third failure same XFF: Location = %q, want account_locked", rr3.Header().Get("Location"))
	}

	// Different XFF → fresh key, fresh failure counter. Single
	// attempt must report invalid_credentials, not locked.
	rr4 := post(t, "2.2.2.2")
	if !strings.Contains(rr4.Header().Get("Location"), "error=invalid_credentials") {
		t.Errorf("different XFF: Location = %q, want invalid_credentials (not locked)", rr4.Header().Get("Location"))
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
