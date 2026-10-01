package test

import (
	"context"
	"io"
	"net/http"
	"net/url"
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

func TestHome_AnonymousRedirectsToLogin(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := getWithSession(t, ts, "/", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?returnUrl=%2F" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestHome_LoginWithoutReturnURLLandsOnHome(t *testing.T) {
	ts := newTestServer(t)
	resp := loginWithCreds(t, ts, testUser, testPassword, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != testIssuer+"/" {
		t.Fatalf("Location = %q, want issuer root", loc)
	}
}

func TestHome_AnonymousBounceThroughLoginReturnsHome(t *testing.T) {
	ts := newTestServer(t)
	// "/" sends anonymous users to /login?returnUrl=/ ; that returnUrl
	// must pass the open-redirect guard instead of erroring out.
	resp := loginWithCreds(t, ts, testUser, testPassword, "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("status=%d Location=%q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
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

	resp, body := getWithSession(t, ts, "/", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	for _, want := range []string{"Demo User", "demo@example.com", testUser, "recent sign-ins", "this sign-in"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if n := strings.Count(body, "<tr>"); n != 2 {
		t.Errorf("history rows = %d, want 2", n)
	}
	// Newest first: the 1700000060 login precedes the 1700000000 one.
	if i, j := strings.Index(body, "2023-11-14 22:14 UTC"), strings.Index(body, "2023-11-14 22:13 UTC"); i < 0 || j < 0 || i > j {
		t.Errorf("history not newest-first (i=%d j=%d)", i, j)
	}
}

func TestHome_HistoryIsPerUserAndEscaped(t *testing.T) {
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

	_, body := getWithSession(t, ts, "/", sess)
	if strings.Contains(body, "203.0.113.9") {
		t.Error("another user's sign-in leaked into the home page")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("stored IP value rendered unescaped")
	}
}

func TestLogin_AlreadySignedInGETRedirectsHome(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	resp, _ := getWithSession(t, ts, "/login", sess)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("status=%d Location=%q, want 303 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A redirect-driven visit (returnUrl present) must still render the form.
	resp, _ = getWithSession(t, ts, "/login?returnUrl="+url.QueryEscape("/connect/authorize"), sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("returnUrl visit status = %d, want 200", resp.StatusCode)
	}
}

func TestHome_ExpiredSessionRedirectsToLogin(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	ts.clk.Advance(2 * time.Hour) // session lifetime in the harness is 1h

	resp, _ := getWithSession(t, ts, "/", sess)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
}
