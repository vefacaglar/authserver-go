package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

type profileSessionJSON struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
}

type profileJSON struct {
	Username         string               `json:"username"`
	Email            string               `json:"email"`
	HasOtherSessions bool                 `json:"has_other_sessions"`
	Sessions         []profileSessionJSON `json:"sessions"`
}

// getProfile fetches and decodes GET /api/account/profile.
func getProfile(t *testing.T, ts *testServer, sess *http.Cookie) (*http.Response, profileJSON) {
	t.Helper()
	resp, body := getWithSession(t, ts, "/api/account/profile", sess)
	var out profileJSON
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode profile: %v (body=%s)", err, body)
		}
	}
	return resp, out
}

// postProfileJSON posts to a profile API subpath with the SPA's CSRF
// pair attached (via doJSON) and returns the raw response.
func postProfileJSON(t *testing.T, ts *testServer, path string, payload any, sess *http.Cookie) *http.Response {
	t.Helper()
	return ts.doJSON(t, http.MethodPost, path, payload, []*http.Cookie{sess})
}

func TestProfile_AnonymousGets401AndLoginReturnsToProfile(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := getWithSession(t, ts, "/api/account/profile", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// /profile is on the login return allow-list, so the SPA can send
	// anonymous visitors through login and back.
	_, redirect := loginViaAPI(t, ts, testUser, testPassword, "/profile")
	if redirect != "/profile" {
		t.Fatalf("redirect = %q, want /profile", redirect)
	}
}

func TestProfile_ReturnURLAllowListIsExact(t *testing.T) {
	ts := newTestServer(t)
	for _, bad := range []string{"/profile/../admin", "/profilex", "/profile/evil"} {
		resp := loginWithCreds(t, ts, testUser, testPassword, bad)
		body := readBodyString(t, resp)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_return") {
			t.Errorf("returnUrl %q: status=%d body=%q, want 400 invalid_return", bad, resp.StatusCode, body)
		}
	}
}

func TestProfile_ReturnsAccountAndSessions(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	resp, prof := getProfile(t, ts, sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if prof.Username != testUser || prof.Email != "demo@example.com" {
		t.Errorf("profile = %+v, want the demo user's fields", prof)
	}
	if len(prof.Sessions) != 1 || !prof.Sessions[0].Current {
		t.Errorf("sessions = %+v, want one current session", prof.Sessions)
	}
	if prof.HasOtherSessions {
		t.Error("has_other_sessions = true with a single session")
	}

	// The home payload is served by the same session.
	if r, _ := getHome(t, ts, sess); r.StatusCode != http.StatusOK {
		t.Errorf("home status = %d, want 200", r.StatusCode)
	}
}

// The profile no longer collects a personal name: the view carries no
// name field, and a POST to the bare profile path is rejected.
func TestProfile_NameIsNotCollected(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	_, raw := getWithSession(t, ts, "/api/account/profile", sess)
	if strings.Contains(raw, `"name"`) {
		t.Error("profile payload still carries a name field")
	}

	resp := postProfileJSON(t, ts, "/api/account/profile", map[string]any{"name": "Ada Lovelace"}, sess)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
		t.Errorf("POST profile: status=%d Allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	claims, _ := ts.users.GetUserClaims(context.Background(), "u-demo")
	for _, c := range claims {
		if c.Type == "name" {
			t.Errorf("name claim stored: %q", c.Value)
		}
	}
}

func TestProfile_RevokeOtherSession(t *testing.T) {
	ts := newTestServer(t)
	first := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	second := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	_, prof := getProfile(t, ts, first)
	if len(prof.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(prof.Sessions))
	}
	var otherID string
	for _, s := range prof.Sessions {
		if !s.Current {
			otherID = s.ID
		}
	}
	if otherID == "" {
		t.Fatal("no revocable session listed in the profile payload")
	}

	resp := postProfileJSON(t, ts, "/api/account/profile/sessions/revoke", map[string]any{"session_id": otherID}, first)
	body := readBodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "session_revoked") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	assertAuditAction(t, ts, domain.AuditSessionRevoked)

	// Exactly one of the two browsers lost access; the initiator did not.
	if r, _ := getHome(t, ts, first); r.StatusCode != http.StatusOK {
		t.Errorf("initiating session status = %d, want 200", r.StatusCode)
	}
	if r, _ := getHome(t, ts, second); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked session status = %d, want 401", r.StatusCode)
	}
}

func TestProfile_RevokeGuards(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")

	// Another user's live session must look like a missing one and stay alive.
	now := ts.clk.Now()
	foreign := &domain.Session{ID: uuid.New(), UserID: "someone-else", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := ts.sessions.Store(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{foreign.ID.String(), uuid.NewString(), "not-a-uuid"} {
		resp := postProfileJSON(t, ts, "/api/account/profile/sessions/revoke", map[string]any{"session_id": id}, sess)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("session_id %q: status = %d, want 404", id, resp.StatusCode)
		}
	}
	if got, _ := ts.sessions.Find(context.Background(), foreign.ID); got == nil || got.RevokedAt != nil {
		t.Error("another user's session was revoked")
	}

	// Missing CSRF is rejected before anything is looked up.
	req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/account/profile/sessions/revoke"), strings.NewReader(`{"session_id":"`+foreign.ID.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sess)
	noCSRF, err := ts.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBodyString(t, noCSRF)
	if noCSRF.StatusCode != http.StatusForbidden || !strings.Contains(body, "antiforgery_failed") {
		t.Errorf("no-CSRF: status=%d body=%q, want 403 antiforgery_failed", noCSRF.StatusCode, body)
	}

	// The current session cannot be revoked here (that is what logout
	// is for) and stays alive.
	_, prof := getProfile(t, ts, sess)
	resp := postProfileJSON(t, ts, "/api/account/profile/sessions/revoke", map[string]any{"session_id": prof.Sessions[0].ID}, sess)
	body = readBodyString(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "current_session") {
		t.Errorf("current-session revoke: status=%d body=%q, want 400 current_session", resp.StatusCode, body)
	}
	if r, _ := getHome(t, ts, sess); r.StatusCode != http.StatusOK {
		t.Error("current session was revoked by the profile API")
	}
}

func TestProfile_MethodsAndRouting(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	resp, err := ts.do(t, http.MethodGet, "/api/account/profile/sessions/revoke", nil, []*http.Cookie{sess})
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
		body := readBodyString(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "invalid_credentials") {
			t.Fatalf("failed login: status=%d body=%q", resp.StatusCode, body)
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
	_, home := getHome(t, ts, sess)
	if len(home.FailedLogins) != 2 {
		t.Errorf("home failed_logins = %d, want 2", len(home.FailedLogins))
	}
	if len(home.Logins) != 1 {
		t.Errorf("home logins = %d, want 1", len(home.Logins))
	}
}

func TestHome_NoFailedAttemptsIsEmptyList(t *testing.T) {
	ts := newTestServer(t)
	sess := loginAs(t, ts, testUser, testPassword, "/connect/authorize")
	_, raw := getWithSession(t, ts, "/api/account/home", sess)
	if !strings.Contains(raw, `"failed_logins":[]`) {
		t.Errorf("failed_logins must serialise as an empty list, body=%s", raw)
	}
}
