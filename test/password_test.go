package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go-authserver/internal/domain"
)

const newTestPassword = "a-brand-new-pass"

func changePasswordForm(token, current, next, confirm string) url.Values {
	return url.Values{
		"csrf_token":           {token},
		"current_password":     {current},
		"new_password":         {next},
		"new_password_confirm": {confirm},
	}
}

func refreshStatus(t *testing.T, ts *testServer, refreshToken string) int {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {testClientID}}
	resp, err := ts.do(t, http.MethodPost, "/connect/token", form, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestProfile_PageShowsPasswordFormAndRevokeOthers(t *testing.T) {
	ts := newTestServer(t)
	first := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	_, body := getWithSession(t, ts, "/profile", first)
	for _, want := range []string{`action="/profile/password"`, `name="current_password"`, `name="new_password_confirm"`} {
		if !strings.Contains(body, want) {
			t.Errorf("profile page missing %s", want)
		}
	}
	// With a single session there is nothing else to sign out.
	if strings.Contains(body, "sign out all other sessions") {
		t.Error("revoke-others button shown with only one session")
	}

	loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	_, body = getWithSession(t, ts, "/profile", first)
	if !strings.Contains(body, `action="/profile/sessions/revoke-others"`) || !strings.Contains(body, "sign out all other sessions") {
		t.Error("revoke-others button missing with two sessions")
	}
}

func TestProfile_ChangePassword(t *testing.T) {
	ts := newTestServer(t)
	// Session A holds a refresh token; session B (the browser doing the change) is current.
	tokens, sessA := exchangeCodeForTokens(t, ts)
	sessB := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sessB)

	resp := postProfile(t, ts, "/profile/password", changePasswordForm(token, testPassword, newTestPassword, newTestPassword), sessB, csrfCookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile?status=password_changed" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Old password stops working, the new one works.
	old := loginWithCreds(t, ts, testUser, testPassword, "")
	old.Body.Close()
	if !strings.HasPrefix(old.Header.Get("Location"), "/login?error=invalid_credentials") {
		t.Errorf("old password still accepted: Location=%q", old.Header.Get("Location"))
	}
	fresh := loginWithCreds(t, ts, testUser, newTestPassword, "")
	fresh.Body.Close()
	if fresh.StatusCode != http.StatusFound || fresh.Header.Get("Location") != "/" {
		t.Errorf("new password rejected: status=%d Location=%q", fresh.StatusCode, fresh.Header.Get("Location"))
	}

	// The current browser stays signed in; the other session and its refresh token are dead.
	if r, _ := getWithSession(t, ts, "/", sessB); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	if r, _ := getWithSession(t, ts, "/", sessA); r.StatusCode != http.StatusSeeOther {
		t.Errorf("other session status = %d, want 303 to login", r.StatusCode)
	}
	if got := refreshStatus(t, ts, tokens.RefreshToken); got != http.StatusBadRequest {
		t.Errorf("refresh token after password change: status = %d, want 400", got)
	}

	user, err := ts.users.FindUserByID(context.Background(), "u-demo")
	if err != nil || user.SecurityStamp == "" {
		t.Errorf("security stamp not rotated: %+v, %v", user, err)
	}
	assertAuditAction(t, ts, domain.AuditPasswordChanged)
}

func TestProfile_ChangePasswordRejections(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)

	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"no csrf", changePasswordForm("", testPassword, newTestPassword, newTestPassword), "error=antiforgery_failed"},
		{"missing field", changePasswordForm(token, testPassword, newTestPassword, ""), "error=password_missing"},
		{"wrong current", changePasswordForm(token, "not-my-password", newTestPassword, newTestPassword), "error=current_password_wrong"},
		{"mismatch", changePasswordForm(token, testPassword, newTestPassword, newTestPassword+"x"), "error=password_mismatch"},
		{"too short", changePasswordForm(token, testPassword, "short", "short"), "error=password_weak"},
		{"too long", changePasswordForm(token, testPassword, strings.Repeat("a", 73), strings.Repeat("a", 73)), "error=password_weak"},
		{"padded", changePasswordForm(token, testPassword, " "+newTestPassword, " "+newTestPassword), "error=password_weak"},
	}
	// Reusing the current password is covered by
	// TestProfile_ChangePasswordRejectsReusingCurrent: the seed password
	// is shorter than the policy minimum, so it needs a compliant one first.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := postProfile(t, ts, "/profile/password", tc.form, sess, csrfCookie)
			if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), tc.want) {
				t.Fatalf("status=%d Location=%q, want suffix %q", resp.StatusCode, resp.Header.Get("Location"), tc.want)
			}
		})
	}

	// Nothing above may have changed the password.
	ok := loginWithCreds(t, ts, testUser, testPassword, "")
	ok.Body.Close()
	if ok.Header.Get("Location") != "/" {
		t.Errorf("rejected requests changed the password: Location=%q", ok.Header.Get("Location"))
	}
	// Anonymous POSTs never reach the handler.
	anon := postProfile(t, ts, "/profile/password", changePasswordForm(token, testPassword, newTestPassword, newTestPassword), csrfCookie)
	if !strings.HasPrefix(anon.Header.Get("Location"), "/login") {
		t.Errorf("anonymous POST Location = %q", anon.Header.Get("Location"))
	}
}

func TestProfile_ChangePasswordRejectsReusingCurrent(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)
	// First move to a policy-compliant password, then try to "change" to itself.
	postProfile(t, ts, "/profile/password", changePasswordForm(token, testPassword, newTestPassword, newTestPassword), sess, csrfCookie)
	resp := postProfile(t, ts, "/profile/password", changePasswordForm(token, newTestPassword, newTestPassword, newTestPassword), sess, csrfCookie)
	if !strings.HasSuffix(resp.Header.Get("Location"), "error=password_unchanged") {
		t.Errorf("Location = %q, want password_unchanged", resp.Header.Get("Location"))
	}
}

func TestProfile_ChangePasswordLocksOutGuessing(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sess)

	for i := 0; i < 5; i++ {
		resp := postProfile(t, ts, "/profile/password", changePasswordForm(token, "guess-"+string(rune('a'+i)), newTestPassword, newTestPassword), sess, csrfCookie)
		if !strings.HasSuffix(resp.Header.Get("Location"), "error=current_password_wrong") {
			t.Fatalf("attempt %d Location = %q", i, resp.Header.Get("Location"))
		}
	}
	// Even the right password is refused while locked, and nothing changes.
	resp := postProfile(t, ts, "/profile/password", changePasswordForm(token, testPassword, newTestPassword, newTestPassword), sess, csrfCookie)
	if !strings.HasSuffix(resp.Header.Get("Location"), "error=account_locked") {
		t.Fatalf("Location = %q, want account_locked", resp.Header.Get("Location"))
	}
	ok := loginWithCreds(t, ts, testUser, testPassword, "")
	ok.Body.Close()
	if ok.Header.Get("Location") != "/" {
		t.Errorf("password changed while locked out: Location=%q", ok.Header.Get("Location"))
	}
}

func TestProfile_RevokeOtherSessions(t *testing.T) {
	ts := newTestServer(t)
	tokens, other := exchangeCodeForTokens(t, ts)
	current := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, current)

	// Missing CSRF is rejected and revokes nothing.
	resp := postProfile(t, ts, "/profile/sessions/revoke-others", url.Values{}, current, csrfCookie)
	if !strings.HasSuffix(resp.Header.Get("Location"), "error=antiforgery_failed") {
		t.Fatalf("no-CSRF Location = %q", resp.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", other); r.StatusCode != http.StatusOK {
		t.Fatal("session revoked without a valid CSRF token")
	}

	resp = postProfile(t, ts, "/profile/sessions/revoke-others", url.Values{"csrf_token": {token}}, current, csrfCookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile?status=other_sessions_revoked" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", current); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	if r, _ := getWithSession(t, ts, "/", other); r.StatusCode != http.StatusSeeOther {
		t.Errorf("other session status = %d, want 303", r.StatusCode)
	}
	if got := refreshStatus(t, ts, tokens.RefreshToken); got != http.StatusBadRequest {
		t.Errorf("refresh token of a revoked session: status = %d, want 400", got)
	}
	assertAuditAction(t, ts, domain.AuditSessionRevoked)

	// The audit entry records how many sessions were closed, nothing sensitive.
	logs, _ := ts.auditLogs.ListByActor(context.Background(), "u-demo", domain.AuditSessionRevoked, 5)
	var md struct {
		Scope string `json:"scope"`
		Count int    `json:"count"`
	}
	if len(logs) == 0 || json.Unmarshal([]byte(logs[0].Metadata), &md) != nil || md.Scope != "others" || md.Count != 1 {
		t.Errorf("audit metadata = %+v (%v)", md, logs)
	}
}

func TestProfile_ChangePassword_GORM(t *testing.T) {
	ts := newGormTestServer(t)
	_, sessA := exchangeCodeForTokens(t, ts)
	sessB := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	csrfCookie, token := profileCSRF(t, ts, sessB)

	resp := postProfile(t, ts, "/profile/password", changePasswordForm(token, testPassword, newTestPassword, newTestPassword), sessB, csrfCookie)
	if resp.Header.Get("Location") != "/profile?status=password_changed" {
		t.Fatalf("Location = %q", resp.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", sessA); r.StatusCode != http.StatusSeeOther {
		t.Errorf("other session status = %d, want 303", r.StatusCode)
	}
	if r, _ := getWithSession(t, ts, "/", sessB); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	fresh := loginWithCreds(t, ts, testUser, newTestPassword, "")
	fresh.Body.Close()
	if fresh.Header.Get("Location") != "/" {
		t.Errorf("new password rejected on GORM store: Location=%q", fresh.Header.Get("Location"))
	}
	// The security-stamp write must not clobber the freshly hashed password.
	user, _ := ts.users.FindUserByID(context.Background(), "u-demo")
	if user == nil || user.SecurityStamp == "" {
		t.Error("security stamp missing on GORM store")
	}
}
