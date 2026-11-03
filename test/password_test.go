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

func changePasswordPayload(current, next, confirm string) map[string]any {
	return map[string]any{
		"current_password":     current,
		"new_password":         next,
		"new_password_confirm": confirm,
	}
}

func changePassword(t *testing.T, ts *testServer, sess *http.Cookie, current, next, confirm string) *http.Response {
	t.Helper()
	return ts.doJSON(t, http.MethodPost, "/api/account/profile/password", changePasswordPayload(current, next, confirm), []*http.Cookie{sess})
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

func TestProfile_HasOtherSessionsFlag(t *testing.T) {
	ts := newTestServer(t)
	first := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	_, prof := getProfile(t, ts, first)
	if prof.HasOtherSessions {
		t.Error("has_other_sessions = true with a single session")
	}

	loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	_, prof = getProfile(t, ts, first)
	if !prof.HasOtherSessions {
		t.Error("has_other_sessions = false with two sessions")
	}
}

func TestProfile_ChangePassword(t *testing.T) {
	ts := newTestServer(t)
	// Session A holds a refresh token; session B (the browser doing the change) is current.
	tokens, sessA := exchangeCodeForTokens(t, ts)
	sessB := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	resp := changePassword(t, ts, sessB, testPassword, newTestPassword, newTestPassword)
	body := readBodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "password_changed") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	// Old password stops working, the new one works.
	old := loginWithCreds(t, ts, testUser, testPassword, "")
	old.Body.Close()
	if old.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still accepted: status=%d", old.StatusCode)
	}
	if _, redirect := loginViaAPI(t, ts, testUser, newTestPassword, ""); redirect != "/" {
		t.Errorf("new password redirect = %q, want /", redirect)
	}

	// The current browser stays signed in; the other session and its refresh token are dead.
	if r, _ := getHome(t, ts, sessB); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	if r, _ := getHome(t, ts, sessA); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("other session status = %d, want 401", r.StatusCode)
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

	tests := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"missing field", changePasswordPayload(testPassword, newTestPassword, ""), "password_missing"},
		{"wrong current", changePasswordPayload("not-my-password", newTestPassword, newTestPassword), "current_password_wrong"},
		{"mismatch", changePasswordPayload(testPassword, newTestPassword, newTestPassword+"x"), "password_mismatch"},
		{"too short", changePasswordPayload(testPassword, "short", "short"), "password_weak"},
		{"too long", changePasswordPayload(testPassword, strings.Repeat("a", 73), strings.Repeat("a", 73)), "password_weak"},
		{"padded", changePasswordPayload(testPassword, " "+newTestPassword, " "+newTestPassword), "password_weak"},
	}
	// Reusing the current password is covered by
	// TestProfile_ChangePasswordRejectsReusingCurrent: the seed password
	// is shorter than the policy minimum, so it needs a compliant one first.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.doJSON(t, http.MethodPost, "/api/account/profile/password", tc.payload, []*http.Cookie{sess})
			body := readBodyString(t, resp)
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, tc.want) {
				t.Fatalf("status=%d body=%q, want 400 with %q", resp.StatusCode, body, tc.want)
			}
		})
	}

	t.Run("no csrf", func(t *testing.T) {
		b, _ := json.Marshal(changePasswordPayload(testPassword, newTestPassword, newTestPassword))
		req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/account/profile/password"), strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(sess)
		resp, err := ts.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readBodyString(t, resp)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "antiforgery_failed") {
			t.Fatalf("status=%d body=%q, want 403 antiforgery_failed", resp.StatusCode, body)
		}
	})

	// Nothing above may have changed the password.
	if _, redirect := loginViaAPI(t, ts, testUser, testPassword, ""); redirect != "/" {
		t.Errorf("rejected requests changed the password: redirect=%q", redirect)
	}
	// Anonymous POSTs never reach the handler.
	anon := ts.doJSON(t, http.MethodPost, "/api/account/profile/password", changePasswordPayload(testPassword, newTestPassword, newTestPassword), nil)
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous POST status = %d, want 401", anon.StatusCode)
	}
}

func TestProfile_ChangePasswordRejectsReusingCurrent(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	// First move to a policy-compliant password, then try to "change" to itself.
	resp := changePassword(t, ts, sess, testPassword, newTestPassword, newTestPassword)
	resp.Body.Close()
	resp = changePassword(t, ts, sess, newTestPassword, newTestPassword, newTestPassword)
	body := readBodyString(t, resp)
	if !strings.Contains(body, "password_unchanged") {
		t.Errorf("body = %q, want password_unchanged", body)
	}
}

func TestProfile_ChangePasswordLocksOutGuessing(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	for i := 0; i < 5; i++ {
		resp := changePassword(t, ts, sess, "guess-"+string(rune('a'+i)), newTestPassword, newTestPassword)
		body := readBodyString(t, resp)
		if !strings.Contains(body, "current_password_wrong") {
			t.Fatalf("attempt %d body = %q", i, body)
		}
	}
	// Even the right password is refused while locked, and nothing changes.
	resp := changePassword(t, ts, sess, testPassword, newTestPassword, newTestPassword)
	body := readBodyString(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "account_locked") {
		t.Fatalf("status=%d body=%q, want 429 account_locked", resp.StatusCode, body)
	}
	if _, redirect := loginViaAPI(t, ts, testUser, testPassword, ""); redirect != "/" {
		t.Errorf("password changed while locked out: redirect=%q", redirect)
	}
}

func TestProfile_RevokeOtherSessions(t *testing.T) {
	ts := newTestServer(t)
	tokens, other := exchangeCodeForTokens(t, ts)
	current := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	// Missing CSRF is rejected and revokes nothing.
	req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/account/profile/sessions/revoke-others"), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(current)
	noCSRF, err := ts.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBodyString(t, noCSRF)
	if noCSRF.StatusCode != http.StatusForbidden || !strings.Contains(body, "antiforgery_failed") {
		t.Fatalf("no-CSRF: status=%d body=%q", noCSRF.StatusCode, body)
	}
	if r, _ := getHome(t, ts, other); r.StatusCode != http.StatusOK {
		t.Fatal("session revoked without a valid CSRF token")
	}

	resp := postProfileJSON(t, ts, "/api/account/profile/sessions/revoke-others", map[string]any{}, current)
	body = readBodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "other_sessions_revoked") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if r, _ := getHome(t, ts, current); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	if r, _ := getHome(t, ts, other); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("other session status = %d, want 401", r.StatusCode)
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

	resp := changePassword(t, ts, sessB, testPassword, newTestPassword, newTestPassword)
	body := readBodyString(t, resp)
	if !strings.Contains(body, "password_changed") {
		t.Fatalf("body = %q", body)
	}
	if r, _ := getHome(t, ts, sessA); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("other session status = %d, want 401", r.StatusCode)
	}
	if r, _ := getHome(t, ts, sessB); r.StatusCode != http.StatusOK {
		t.Errorf("current session status = %d, want 200", r.StatusCode)
	}
	if _, redirect := loginViaAPI(t, ts, testUser, newTestPassword, ""); redirect != "/" {
		t.Errorf("new password rejected on GORM store: redirect=%q", redirect)
	}
	// The security-stamp write must not clobber the freshly hashed password.
	user, _ := ts.users.FindUserByID(context.Background(), "u-demo")
	if user == nil || user.SecurityStamp == "" {
		t.Error("security stamp missing on GORM store")
	}
}
