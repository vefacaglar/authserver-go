package test

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/mail"
	"go-authserver/internal/token"
)

// captureMailer records every message instead of sending it.
type captureMailer struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (m *captureMailer) Send(_ context.Context, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *captureMailer) messages() []mail.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mail.Message(nil), m.sent...)
}

var resetLinkRe = regexp.MustCompile(`https://app\.example\.test(/reset-password\?token=[A-Za-z0-9_-]+)`)

// requestReset submits the forgot-password form via the JSON API and
// returns the response.
func requestReset(t *testing.T, ts *testServer, identifier string) *http.Response {
	t.Helper()
	return ts.doJSON(t, http.MethodPost, "/api/auth/forgot-password", map[string]any{"identifier": identifier}, nil)
}

// resetPathFromMail extracts the /reset-password?token=... path from the
// most recent captured email.
func resetPathFromMail(t *testing.T, ts *testServer) string {
	t.Helper()
	msgs := ts.mail.messages()
	if len(msgs) == 0 {
		t.Fatal("no email was sent")
	}
	m := resetLinkRe.FindStringSubmatch(msgs[len(msgs)-1].Body)
	if m == nil {
		t.Fatalf("no reset link in email body:\n%s", msgs[len(msgs)-1].Body)
	}
	return m[1]
}

// resetTokenFromPath pulls the raw token out of a mailed reset path.
func resetTokenFromPath(path string) string {
	return strings.TrimPrefix(path, "/reset-password?token=")
}

// resetTokenValid probes the SPA's token check endpoint.
func resetTokenValid(t *testing.T, ts *testServer, raw string) (*http.Response, bool) {
	t.Helper()
	resp, body := getWithSession(t, ts, "/api/auth/reset-password?token="+raw, nil)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode validity: %v (body=%s)", err, body)
	}
	return resp, out.Valid
}

// submitReset posts the new password for a raw reset token.
func submitReset(t *testing.T, ts *testServer, raw, next, confirm string) (*http.Response, string) {
	t.Helper()
	resp := ts.doJSON(t, http.MethodPost, "/api/auth/reset-password", map[string]any{
		"token":                raw,
		"new_password":         next,
		"new_password_confirm": confirm,
	}, nil)
	return resp, readBodyString(t, resp)
}

func TestForgot_FullFlow(t *testing.T) {
	ts := newTestServer(t)
	tokens, otherSession := exchangeCodeForTokens(t, ts)

	resp := requestReset(t, ts, "demo@example.com") // by email
	body := readBodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"sent":true`) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	msgs := ts.mail.messages()
	if len(msgs) != 1 || msgs[0].To != "demo@example.com" {
		t.Fatalf("emails = %+v, want exactly one to the account's address", msgs)
	}
	if !strings.Contains(msgs[0].Body, "expires in 30 minutes") {
		t.Error("email does not state the expiry")
	}
	path := resetPathFromMail(t, ts)

	// The raw token is never stored: only its hash is.
	raw := resetTokenFromPath(path)
	if _, err := ts.resets.FindByHash(context.Background(), raw); err == nil {
		t.Error("raw token found in the store; only the hash may be stored")
	}
	if _, err := ts.resets.FindByHash(context.Background(), token.HashToken(raw)); err != nil {
		t.Errorf("hashed token not found: %v", err)
	}

	probe, valid := resetTokenValid(t, ts, raw)
	if probe.Header.Get("Referrer-Policy") != "no-referrer" || probe.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("reset probe headers: Referrer-Policy=%q Cache-Control=%q",
			probe.Header.Get("Referrer-Policy"), probe.Header.Get("Cache-Control"))
	}
	if !valid {
		t.Fatal("reset token not valid for a fresh link")
	}

	done, doneBody := submitReset(t, ts, raw, "brand-new-secret", "brand-new-secret")
	if done.StatusCode != http.StatusOK || !strings.Contains(doneBody, "/login?notice=password_reset") {
		t.Fatalf("reset status=%d body=%q", done.StatusCode, doneBody)
	}

	// New password works, old does not, and every earlier session is dead.
	old := loginWithCreds(t, ts, testUser, testPassword, "")
	old.Body.Close()
	if old.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still works: status=%d", old.StatusCode)
	}
	if _, redirect := loginViaAPI(t, ts, testUser, "brand-new-secret", ""); redirect != "/" {
		t.Errorf("new password rejected: redirect=%q", redirect)
	}
	if r, _ := getHome(t, ts, otherSession); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("pre-reset session still valid (status %d)", r.StatusCode)
	}
	if got := refreshStatus(t, ts, tokens.RefreshToken); got != http.StatusBadRequest {
		t.Errorf("pre-reset refresh token still valid (status %d)", got)
	}
	assertAuditAction(t, ts, domain.AuditResetRequested)
	assertAuditAction(t, ts, domain.AuditResetCompleted)

	// The link is single-use.
	if _, valid := resetTokenValid(t, ts, raw); valid {
		t.Error("used link still reports valid")
	}
}

func TestForgot_ResponseDoesNotRevealAccounts(t *testing.T) {
	ts := newTestServer(t)
	// A real account without an email, an unknown identifier and a real one.
	noMail := domain.User{ID: "u-nomail", Username: "nomail", CreatedAt: ts.clk.Now(), UpdatedAt: ts.clk.Now()}
	if err := ts.users.CreateUser(context.Background(), &noMail, "whatever-pass"); err != nil {
		t.Fatal(err)
	}

	var bodies []string
	for _, id := range []string{"definitely-nobody", "nomail", testUser} {
		resp := requestReset(t, ts, id)
		bodies = append(bodies, readBodyString(t, resp))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%q: status = %d", id, resp.StatusCode)
		}
	}
	for _, b := range bodies {
		if b != bodies[0] || !strings.Contains(b, `"sent":true`) {
			t.Errorf("response differs by identifier: %v", bodies)
			break
		}
	}
	if n := len(ts.mail.messages()); n != 1 {
		t.Errorf("emails sent = %d, want 1 (only the real account with an address)", n)
	}
}

func TestForgot_FormValidation(t *testing.T) {
	ts := newTestServer(t)
	resp := requestReset(t, ts, "   ")
	body := readBodyString(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "missing_identifier") {
		t.Errorf("blank identifier: status=%d body=%q", resp.StatusCode, body)
	}
	// No CSRF pair: refused before any account lookup.
	req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/auth/forgot-password"), strings.NewReader(`{"identifier":"`+testUser+`"}`))
	req.Header.Set("Content-Type", "application/json")
	r, err := ts.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body = readBodyString(t, r)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, "antiforgery_failed") {
		t.Errorf("no-CSRF: status=%d body=%q", r.StatusCode, body)
	}
	if len(ts.mail.messages()) != 0 {
		t.Error("an email was sent for an invalid request")
	}
}

func TestForgot_PerAccountThrottle(t *testing.T) {
	ts := newTestServer(t)
	for i := 0; i < 8; i++ {
		resp := requestReset(t, ts, testUser)
		body := readBodyString(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"sent":true`) {
			t.Fatalf("request %d: status=%d body=%q (the throttle must be invisible)", i, resp.StatusCode, body)
		}
	}
	if n := len(ts.mail.messages()); n != 5 {
		t.Errorf("emails sent = %d, want 5 before the throttle drops requests", n)
	}
}

func TestForgot_OnlyNewestLinkWorks(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	first := resetPathFromMail(t, ts)
	requestReset(t, ts, testUser)
	second := resetPathFromMail(t, ts)
	if first == second {
		t.Fatal("two requests produced the same link")
	}
	if _, valid := resetTokenValid(t, ts, resetTokenFromPath(first)); valid {
		t.Error("older link still usable after a newer one was issued")
	}
	if _, valid := resetTokenValid(t, ts, resetTokenFromPath(second)); !valid {
		t.Error("newest link not usable")
	}
}

func TestReset_InvalidAndExpiredTokens(t *testing.T) {
	ts := newTestServer(t)
	for _, raw := range []string{"", "garbage"} {
		if _, valid := resetTokenValid(t, ts, raw); valid {
			t.Errorf("token %q reported valid", raw)
		}
	}

	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	ts.clk.Advance(31 * time.Minute)
	if _, valid := resetTokenValid(t, ts, resetTokenFromPath(path)); valid {
		t.Error("expired link still reports valid")
	}
}

func TestReset_ExpiryBetweenGetAndPostIsRejected(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	raw := resetTokenFromPath(path)

	if _, valid := resetTokenValid(t, ts, raw); !valid {
		t.Fatal("fresh token not valid")
	}
	ts.clk.Advance(31 * time.Minute)
	r, body := submitReset(t, ts, raw, "brand-new-secret", "brand-new-secret")
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_token") {
		t.Errorf("expired POST: status=%d body=%q, want 400 invalid_token", r.StatusCode, body)
	}
	if l := loginWithCreds(t, ts, testUser, "brand-new-secret", ""); l.StatusCode != http.StatusUnauthorized {
		t.Error("password changed with an expired token")
	} else {
		l.Body.Close()
	}
}

func TestReset_ValidationKeepsTokenUsable(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	raw := resetTokenFromPath(path)

	for _, tc := range []struct{ name, next, confirm, want string }{
		{"mismatch", "brand-new-secret", "different-secret", "passwords do not match"},
		{"weak", "short", "short", "must be 8-72 characters"},
		{"missing", "", "", "fill out both password fields"},
	} {
		r, body := submitReset(t, ts, raw, tc.next, tc.confirm)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, tc.want) {
			t.Errorf("%s: status=%d body=%q lacks %q", tc.name, r.StatusCode, body, tc.want)
		}
		if _, valid := resetTokenValid(t, ts, raw); !valid {
			t.Errorf("%s: the token was burned by a validation error", tc.name)
		}
	}
	// None of those attempts consumed the link or changed the password.
	done, _ := submitReset(t, ts, raw, "brand-new-secret", "brand-new-secret")
	if done.StatusCode != http.StatusOK {
		t.Errorf("valid submission after typos: status = %d, want 200", done.StatusCode)
	}
}

func TestReset_PostGuards(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	raw := resetTokenFromPath(path)

	post := func(payload string, csrfToken string, csrfCookie *http.Cookie) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/auth/reset-password"), strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if csrfToken != "" {
			req.Header.Set("X-CSRF-Token", csrfToken)
		}
		if csrfCookie != nil {
			req.AddCookie(csrfCookie)
		}
		r, err := ts.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	good := `{"token":"` + raw + `","new_password":"brand-new-secret","new_password_confirm":"brand-new-secret"}`
	token, cookie := fetchCSRF(t, ts)

	if got := post(good, token, nil); got != http.StatusForbidden {
		t.Errorf("POST without the CSRF cookie: status = %d, want 403", got)
	}
	if got := post(good, "wrong", cookie); got != http.StatusForbidden {
		t.Errorf("POST with a wrong CSRF token: status = %d, want 403", got)
	}
	forged := `{"token":"forged-token","new_password":"brand-new-secret","new_password_confirm":"brand-new-secret"}`
	if got := post(forged, token, cookie); got != http.StatusBadRequest {
		t.Errorf("POST with a forged reset token: status = %d, want 400", got)
	}
	if l := loginWithCreds(t, ts, testUser, "brand-new-secret", ""); l.StatusCode != http.StatusUnauthorized {
		t.Error("a rejected request changed the password")
	} else {
		l.Body.Close()
	}
}

func TestReset_ConcurrentSubmissionsExactlyOneWins(t *testing.T) {
	for name, ts := range map[string]*testServer{"memory": newTestServer(t), "gorm": newGormTestServer(t)} {
		t.Run(name, func(t *testing.T) {
			requestReset(t, ts, testUser)
			path := resetPathFromMail(t, ts)
			raw := resetTokenFromPath(path)
			csrfToken, csrfCookie := fetchCSRF(t, ts)
			payload := `{"token":"` + raw + `","new_password":"brand-new-secret","new_password_confirm":"brand-new-secret"}`

			const n = 8
			codes := make(chan int, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, _ := http.NewRequest(http.MethodPost, ts.URL("/api/auth/reset-password"), strings.NewReader(payload))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-CSRF-Token", csrfToken)
					req.AddCookie(csrfCookie)
					r, err := ts.client.Do(req)
					if err != nil {
						t.Error(err)
						return
					}
					r.Body.Close()
					codes <- r.StatusCode
				}()
			}
			wg.Wait()
			close(codes)
			wins := 0
			for c := range codes {
				if c == http.StatusOK {
					wins++
				}
			}
			if wins != 1 {
				t.Fatalf("successful resets = %d, want exactly 1", wins)
			}
		})
	}
}

func TestForgotReset_GORM(t *testing.T) {
	ts := newGormTestServer(t)
	_, other := exchangeCodeForTokens(t, ts)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	done, body := submitReset(t, ts, resetTokenFromPath(path), "brand-new-secret", "brand-new-secret")
	if done.StatusCode != http.StatusOK || !strings.Contains(body, "/login?notice=password_reset") {
		t.Fatalf("status=%d body=%q", done.StatusCode, body)
	}
	if r, _ := getHome(t, ts, other); r.StatusCode != http.StatusUnauthorized {
		t.Error("pre-reset session survived on the GORM store")
	}
	if _, redirect := loginViaAPI(t, ts, testUser, "brand-new-secret", ""); redirect != "/" {
		t.Errorf("new password rejected on GORM store: redirect=%q", redirect)
	}
}
