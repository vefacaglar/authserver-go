package test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

// profileCSRF loads /profile and returns the CSRF cookie and form token.
func profileCSRF(t *testing.T, ts *testServer, sess *http.Cookie) (*http.Cookie, string) {
	t.Helper()
	resp, body := getWithSession(t, ts, "/profile", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /profile status = %d, want 200", resp.StatusCode)
	}
	return findCookie(resp.Cookies(), "_csrf_profile"), extractInputValue(t, body, `name="csrf_token"`)
}

func postProfile(t *testing.T, ts *testServer, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	resp, err := ts.do(t, http.MethodPost, path, form, cookies)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	resp.Body.Close()
	return resp
}

func TestProfile_AnonymousGoesThroughLoginAndBack(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := getWithSession(t, ts, "/profile", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?returnUrl=%2Fprofile" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	login := loginWithCreds(t, ts, testUser, testPassword, "/profile")
	login.Body.Close()
	if login.StatusCode != http.StatusFound || login.Header.Get("Location") != "/profile" {
		t.Fatalf("login status=%d Location=%q, want 302 to /profile", login.StatusCode, login.Header.Get("Location"))
	}
}

func TestProfile_ReturnURLAllowListIsExact(t *testing.T) {
	ts := newTestServer(t)
	for _, bad := range []string{"/profile/../admin", "/profilex", "/profile/evil"} {
		resp := loginWithCreds(t, ts, testUser, testPassword, bad)
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?error=invalid_return") {
			t.Errorf("returnUrl %q: Location = %q, want invalid_return", bad, loc)
		}
	}
}

func TestProfile_ShowsFormAndNavigation(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	for _, page := range []string{"/", "/profile"} {
		resp, body := getWithSession(t, ts, page, sess)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", page, resp.StatusCode)
		}
		for _, link := range []string{`href="/"`, `href="/profile"`, `href="/logout"`} {
			if !strings.Contains(body, link) {
				t.Errorf("%s: navigation missing %s", page, link)
			}
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control = %q", page, cc)
		}
	}
	_, body := getWithSession(t, ts, "/profile", sess)
	for _, want := range []string{`value="Demo User"`, "demo@example.com", "this device", "active sessions"} {
		if !strings.Contains(body, want) {
			t.Errorf("profile body missing %q", want)
		}
	}
}

func TestProfile_UpdateName(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)

	resp := postProfile(t, ts, "/profile", url.Values{"csrf_token": {token}, "name": {"  Ada <b>Lovelace</b>  "}}, sess, csrfCookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile?status=name_updated" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	claims, err := ts.users.GetUserClaims(context.Background(), "u-demo")
	if err != nil {
		t.Fatal(err)
	}
	names, others := 0, 0
	for _, c := range claims {
		if c.Type == "name" {
			names++
			if c.Value != "Ada <b>Lovelace</b>" {
				t.Errorf("name claim = %q (should be trimmed, stored verbatim)", c.Value)
			}
		} else {
			others++
		}
	}
	if names != 1 || others == 0 {
		t.Errorf("name claims = %d, other claims = %d; want exactly one name and the rest untouched", names, others)
	}

	_, body := getWithSession(t, ts, "/profile?status=name_updated", sess)
	if !strings.Contains(body, "Your name was updated.") {
		t.Error("status banner missing")
	}
	if strings.Contains(body, "<b>Lovelace</b>") {
		t.Error("name rendered unescaped")
	}
	_, home := getWithSession(t, ts, "/", sess)
	if !strings.Contains(home, "Ada &lt;b&gt;Lovelace&lt;/b&gt;") {
		t.Error("home page does not show the new name")
	}
	assertAuditAction(t, ts, domain.AuditProfileUpdated)

	// Submitting the same value again is a no-op and writes no second entry.
	before, _ := ts.auditLogs.ListByActor(context.Background(), "u-demo", domain.AuditProfileUpdated, 10)
	resp = postProfile(t, ts, "/profile", url.Values{"csrf_token": {token}, "name": {"Ada <b>Lovelace</b>"}}, sess, csrfCookie)
	if resp.Header.Get("Location") != "/profile?status=name_unchanged" {
		t.Errorf("repeat Location = %q", resp.Header.Get("Location"))
	}
	after, _ := ts.auditLogs.ListByActor(context.Background(), "u-demo", domain.AuditProfileUpdated, 10)
	if len(after) != len(before) {
		t.Errorf("audit entries %d -> %d on unchanged name", len(before), len(after))
	}
}

func TestProfile_UpdateNameValidationAndCSRF(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)

	tests := []struct {
		name, csrf, value, want string
	}{
		{"missing csrf", "", "Ok Name", "error=antiforgery_failed"},
		{"wrong csrf", "nope", "Ok Name", "error=antiforgery_failed"},
		{"blank", token, "   ", "error=name_required"},
		{"too long", token, strings.Repeat("a", 101), "error=name_too_long"},
		{"control char", token, "bad\x00name", "error=name_invalid"},
		{"newline", token, "bad\nname", "error=name_invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := postProfile(t, ts, "/profile", url.Values{"csrf_token": {tc.csrf}, "name": {tc.value}}, sess, csrfCookie)
			if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), tc.want) {
				t.Fatalf("status=%d Location=%q, want suffix %q", resp.StatusCode, resp.Header.Get("Location"), tc.want)
			}
		})
	}
	claims, _ := ts.users.GetUserClaims(context.Background(), "u-demo")
	for _, c := range claims {
		if c.Type == "name" && c.Value != "Demo User" {
			t.Errorf("rejected input changed the name to %q", c.Value)
		}
	}
	// Anonymous POSTs never reach the handler.
	resp := postProfile(t, ts, "/profile", url.Values{"csrf_token": {token}, "name": {"x"}}, csrfCookie)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Errorf("anonymous POST Location = %q, want /login", resp.Header.Get("Location"))
	}
}

func TestProfile_RevokeOtherSession(t *testing.T) {
	ts := newTestServer(t)
	first := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	second := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	list, err := ts.sessions.ListByUserID(context.Background(), "u-demo", ts.clk.Now())
	if err != nil || len(list) != 2 {
		t.Fatalf("sessions = %d, %v; want 2", len(list), err)
	}
	// Identify the second browser's session by decoding via the page
	// itself: the one that is NOT "this device" for the first cookie.
	csrfCookie, token := profileCSRF(t, ts, first)
	_, body := getWithSession(t, ts, "/profile", first)
	var otherID string
	for _, s := range list {
		if strings.Contains(body, s.ID.String()) {
			otherID = s.ID.String()
		}
	}
	if otherID == "" {
		t.Fatal("no revocable session listed on the profile page")
	}

	resp := postProfile(t, ts, "/profile/sessions/revoke", url.Values{"csrf_token": {token}, "session_id": {otherID}}, first, csrfCookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile?status=session_revoked" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	assertAuditAction(t, ts, domain.AuditSessionRevoked)

	// Exactly one of the two browsers lost access; the initiator did not.
	r1, _ := getWithSession(t, ts, "/", first)
	r2, _ := getWithSession(t, ts, "/", second)
	if r1.StatusCode != http.StatusOK {
		t.Errorf("initiating session status = %d, want 200", r1.StatusCode)
	}
	if r2.StatusCode != http.StatusSeeOther {
		t.Errorf("revoked session status = %d, want 303 to login", r2.StatusCode)
	}
}

func TestProfile_RevokeGuards(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)

	// Another user's live session must look like a missing one and stay alive.
	now := ts.clk.Now()
	foreign := &domain.Session{ID: uuid.New(), UserID: "someone-else", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := ts.sessions.Store(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{foreign.ID.String(), uuid.NewString(), "not-a-uuid"} {
		resp := postProfile(t, ts, "/profile/sessions/revoke", url.Values{"csrf_token": {token}, "session_id": {id}}, sess, csrfCookie)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("session_id %q: status = %d, want 404", id, resp.StatusCode)
		}
	}
	if got, _ := ts.sessions.Find(context.Background(), foreign.ID); got == nil || got.RevokedAt != nil {
		t.Error("another user's session was revoked")
	}

	// Missing CSRF is rejected before anything is looked up.
	resp := postProfile(t, ts, "/profile/sessions/revoke", url.Values{"session_id": {foreign.ID.String()}}, sess, csrfCookie)
	if !strings.HasSuffix(resp.Header.Get("Location"), "error=antiforgery_failed") {
		t.Errorf("no-CSRF Location = %q", resp.Header.Get("Location"))
	}

	// The current session is handed to the logout flow instead of revoked.
	list, _ := ts.sessions.ListByUserID(context.Background(), "u-demo", ts.clk.Now())
	resp = postProfile(t, ts, "/profile/sessions/revoke", url.Values{"csrf_token": {token}, "session_id": {list[0].ID.String()}}, sess, csrfCookie)
	if resp.Header.Get("Location") != "/logout" {
		t.Errorf("current-session Location = %q, want /logout", resp.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", sess); r.StatusCode != http.StatusOK {
		t.Error("current session was revoked by the profile page")
	}
}

func TestProfile_MethodsAndRouting(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	resp, err := ts.do(t, http.MethodGet, "/profile/sessions/revoke", nil, []*http.Cookie{sess})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "POST" {
		t.Errorf("GET revoke: status=%d Allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
}

func TestLogin_FailedAttemptIsRecordedAndShownOnHome(t *testing.T) {
	ts := newTestServer(t)

	// Wrong password for a known account, by username and by email.
	for _, id := range []string{testUser, "demo@example.com"} {
		resp := loginWithCreds(t, ts, id, "wrong-password-xyz", "")
		resp.Body.Close()
		if !strings.HasPrefix(resp.Header.Get("Location"), "/login?error=invalid_credentials") {
			t.Fatalf("failed login Location = %q", resp.Header.Get("Location"))
		}
	}
	// Unknown identifier: no owner, so nothing is recorded.
	resp := loginWithCreds(t, ts, "nobody-here", "whatever-pass", "")
	resp.Body.Close()

	failed, err := ts.auditLogs.ListByActor(context.Background(), "u-demo", domain.AuditLoginFailed, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 2 {
		t.Fatalf("failed entries = %d, want 2", len(failed))
	}
	all, _ := ts.auditLogs.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 100})
	for _, l := range all.Items {
		for _, secret := range []string{"wrong-password-xyz", "nobody-here", "whatever-pass"} {
			if strings.Contains(l.Metadata, secret) || strings.Contains(l.IPAddress, secret) || strings.Contains(l.TargetID, secret) {
				t.Errorf("audit entry %s leaked typed input %q", l.Action, secret)
			}
		}
		if l.Action == domain.AuditLoginFailed && l.ActorUserID == "" {
			t.Error("login_failed written without an owner")
		}
	}

	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	_, body := getWithSession(t, ts, "/", sess)
	if !strings.Contains(body, "recent failed sign-ins") || strings.Contains(body, "no failed sign-ins recorded") {
		t.Error("home page does not list the failed sign-ins")
	}
	if n := strings.Count(body, "<tr>"); n != 3 { // 1 success + 2 failures
		t.Errorf("history rows = %d, want 3", n)
	}
}

func TestHome_NoFailedAttemptsMessage(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	_, body := getWithSession(t, ts, "/", sess)
	if !strings.Contains(body, "no failed sign-ins recorded") {
		t.Error("empty state missing")
	}
}
