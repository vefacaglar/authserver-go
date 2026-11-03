package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

func getWithSession(t *testing.T, ts *testServer, path string, sess *http.Cookie) (*http.Response, string) {
	t.Helper()
	var cookies []*http.Cookie
	if sess != nil {
		cookies = append(cookies, sess)
	}
	resp, err := ts.do(t, http.MethodGet, path, nil, cookies)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

type homeLoginJSON struct {
	When    time.Time `json:"when"`
	IP      string    `json:"ip"`
	Device  string    `json:"device"`
	Current bool      `json:"current"`
}

type homeJSON struct {
	Username     string          `json:"username"`
	Email        string          `json:"email"`
	Logins       []homeLoginJSON `json:"logins"`
	FailedLogins []homeLoginJSON `json:"failed_logins"`
}

// getHome fetches and decodes GET /api/account/home.
func getHome(t *testing.T, ts *testServer, sess *http.Cookie) (*http.Response, homeJSON) {
	t.Helper()
	resp, body := getWithSession(t, ts, "/api/account/home", sess)
	var out homeJSON
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode home: %v (body=%s)", err, body)
		}
	}
	return resp, out
}

func TestHome_AnonymousGets401(t *testing.T) {
	ts := newTestServer(t)
	resp, body := getWithSession(t, ts, "/api/account/home", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(body, "login_required") {
		t.Fatalf("body = %q, want login_required", body)
	}
}

func TestHome_LoginWithoutReturnURLLandsOnHome(t *testing.T) {
	ts := newTestServer(t)
	_, redirect := loginViaAPI(t, ts, testUser, testPassword, "")
	if redirect != "/" {
		t.Fatalf("redirect = %q, want the relative home path", redirect)
	}
}

func TestHome_AnonymousBounceThroughLoginReturnsHome(t *testing.T) {
	ts := newTestServer(t)
	// The SPA sends anonymous visitors to login with returnUrl=/ ;
	// that value must pass the open-redirect guard.
	_, redirect := loginViaAPI(t, ts, testUser, testPassword, "/")
	if redirect != "/" {
		t.Fatalf("redirect = %q, want /", redirect)
	}
}

func TestHome_ShowsProfileAndRecentLogins(t *testing.T) {
	homeShowsProfileAndLogins(t, newTestServer(t))
}

func TestHome_ShowsProfileAndRecentLogins_GORM(t *testing.T) {
	homeShowsProfileAndLogins(t, newGormTestServer(t))
}

func homeShowsProfileAndLogins(t *testing.T, ts *testServer) {
	t.Helper()
	loginAs(t, ts, testUser, testPassword, "/connect/authorize?x=1")
	ts.clk.Advance(time.Minute)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize?x=1")

	resp, home := getHome(t, ts, sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if home.Username != testUser || home.Email != "demo@example.com" {
		t.Errorf("home = %+v, want the demo user's fields", home)
	}
	if len(home.Logins) != 2 {
		t.Fatalf("logins = %d, want 2", len(home.Logins))
	}
	if !home.Logins[0].Current || home.Logins[1].Current {
		t.Errorf("current flags = [%v %v], want only the newest marked", home.Logins[0].Current, home.Logins[1].Current)
	}
	// Newest first: the second login happened one minute after the first.
	if !home.Logins[0].When.After(home.Logins[1].When) {
		t.Errorf("history not newest-first: %v then %v", home.Logins[0].When, home.Logins[1].When)
	}
	if len(home.FailedLogins) != 0 {
		t.Errorf("failed_logins = %d, want 0", len(home.FailedLogins))
	}
}

func TestHome_HistoryIsPerUser(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	other := domain.AuditLog{
		ID: uuid.New(), Action: domain.AuditLoginSucceeded, ActorUserID: "someone-else",
		Timestamp: ts.clk.Now(), IPAddress: "203.0.113.9", UserAgent: "x",
	}
	evil := domain.AuditLog{
		ID: uuid.New(), Action: domain.AuditLoginSucceeded, ActorUserID: "u-demo",
		Timestamp: ts.clk.Now().Add(-time.Hour), IPAddress: "<script>alert(1)</script>", UserAgent: "x",
	}
	for _, l := range []domain.AuditLog{other, evil} {
		l := l
		if err := ts.auditLogs.Store(context.Background(), &l); err != nil {
			t.Fatal(err)
		}
	}

	_, rawBody := getWithSession(t, ts, "/api/account/home", sess)
	if strings.Contains(rawBody, "203.0.113.9") {
		t.Error("another user's sign-in leaked into the home response")
	}
	// The raw JSON must not carry an executable script tag: encoding/json
	// escapes < and >, and the SPA renders values as text.
	if strings.Contains(rawBody, "<script>alert(1)</script>") {
		t.Error("stored IP value serialised unescaped")
	}
}

func TestSession_ReportsSignedInUser(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	resp, body := getWithSession(t, ts, "/api/auth/session", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var view struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		IsAdmin       bool   `json:"is_admin"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if !view.Authenticated || view.Username != testUser {
		t.Errorf("view = %+v, want authenticated demo user", view)
	}
	if view.IsAdmin {
		t.Error("demo user reported as admin without the role")
	}

	resp, body = getWithSession(t, ts, "/api/auth/session", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("anonymous session probe: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestHome_ExpiredSessionGets401(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	ts.clk.Advance(2 * time.Hour) // session lifetime in the harness is 1h

	resp, _ := getWithSession(t, ts, "/api/account/home", sess)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
