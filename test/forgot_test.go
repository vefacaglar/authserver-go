package test

import (
	"context"
	"net/http"
	"net/url"
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

// requestReset submits the forgot-password form and returns the response.
func requestReset(t *testing.T, ts *testServer, identifier string) *http.Response {
	t.Helper()
	resp, body := getWithSession(t, ts, "/forgot-password", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /forgot-password status = %d", resp.StatusCode)
	}
	csrf := extractInputValue(t, body, `name="csrf_token"`)
	out := postProfile(t, ts, "/forgot-password", url.Values{"csrf_token": {csrf}, "identifier": {identifier}}, findCookie(resp.Cookies(), "_csrf_forgot"))
	return out
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

// submitReset opens the reset page for path and posts the new password.
func submitReset(t *testing.T, ts *testServer, path, next, confirm string) (*http.Response, string) {
	t.Helper()
	resp, body := getWithSession(t, ts, path, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", path, resp.StatusCode)
	}
	csrf := extractInputValue(t, body, `name="csrf_token"`)
	tok := extractInputValue(t, body, `name="token"`)
	cookie := findCookie(resp.Cookies(), "_csrf_reset")
	form := url.Values{"csrf_token": {csrf}, "token": {tok}, "new_password": {next}, "new_password_confirm": {confirm}}
	r, err := ts.do(t, http.MethodPost, "/reset-password", form, []*http.Cookie{cookie})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return r, b.String()
}

func TestForgot_FullFlow(t *testing.T) {
	ts := newTestServer(t)
	tokens, otherSession := exchangeCodeForTokens(t, ts)

	resp := requestReset(t, ts, "demo@example.com") // by email
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/forgot-password?sent=1" {
		t.Fatalf("status=%d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
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
	raw := strings.TrimPrefix(path, "/reset-password?token=")
	if _, err := ts.resets.FindByHash(context.Background(), raw); err == nil {
		t.Error("raw token found in the store; only the hash may be stored")
	}
	if _, err := ts.resets.FindByHash(context.Background(), token.HashToken(raw)); err != nil {
		t.Errorf("hashed token not found: %v", err)
	}

	pageResp, page := getWithSession(t, ts, path, nil)
	if pageResp.Header.Get("Referrer-Policy") != "no-referrer" || pageResp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("reset page headers: Referrer-Policy=%q Cache-Control=%q",
			pageResp.Header.Get("Referrer-Policy"), pageResp.Header.Get("Cache-Control"))
	}
	if !strings.Contains(page, `name="new_password"`) {
		t.Fatal("reset form not rendered for a valid link")
	}

	done, _ := submitReset(t, ts, path, "brand-new-secret", "brand-new-secret")
	if done.StatusCode != http.StatusSeeOther || done.Header.Get("Location") != "/login?notice=password_reset" {
		t.Fatalf("reset status=%d Location=%q", done.StatusCode, done.Header.Get("Location"))
	}

	// New password works, old does not, and every earlier session is dead.
	old := loginWithCreds(t, ts, testUser, testPassword, "")
	old.Body.Close()
	if !strings.HasPrefix(old.Header.Get("Location"), "/login?error=invalid_credentials") {
		t.Errorf("old password still works: %q", old.Header.Get("Location"))
	}
	fresh := loginWithCreds(t, ts, testUser, "brand-new-secret", "")
	fresh.Body.Close()
	if fresh.Header.Get("Location") != "/" {
		t.Errorf("new password rejected: %q", fresh.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", otherSession); r.StatusCode != http.StatusSeeOther {
		t.Errorf("pre-reset session still valid (status %d)", r.StatusCode)
	}
	if got := refreshStatus(t, ts, tokens.RefreshToken); got != http.StatusBadRequest {
		t.Errorf("pre-reset refresh token still valid (status %d)", got)
	}
	assertAuditAction(t, ts, domain.AuditResetRequested)
	assertAuditAction(t, ts, domain.AuditResetCompleted)

	// The link is single-use.
	again, againBody := getWithSession(t, ts, path, nil)
	if again.StatusCode != http.StatusOK || !strings.Contains(againBody, "invalid or has expired") {
		t.Errorf("used link: status=%d, expected the generic invalid-link page", again.StatusCode)
	}
}

func TestForgot_LoginPageHasLinkAndNotice(t *testing.T) {
	ts := newTestServer(t)
	_, body := getWithSession(t, ts, "/login", nil)
	if !strings.Contains(body, `href="/forgot-password"`) {
		t.Error("login page has no forgot-password link")
	}
	_, body = getWithSession(t, ts, "/login?notice=password_reset", nil)
	if !strings.Contains(body, "your password was updated") {
		t.Error("login notice missing")
	}
	_, body = getWithSession(t, ts, "/login?notice=<script>", nil)
	if strings.Contains(body, "your password was updated") || strings.Contains(body, "<script>") {
		t.Error("unknown notice value was rendered")
	}
}

func TestForgot_ResponseDoesNotRevealAccounts(t *testing.T) {
	ts := newTestServer(t)
	// A real account without an email, an unknown identifier and a real one.
	noMail := domain.User{ID: "u-nomail", Username: "nomail", CreatedAt: ts.clk.Now(), UpdatedAt: ts.clk.Now()}
	if err := ts.users.CreateUser(context.Background(), &noMail, "whatever-pass"); err != nil {
		t.Fatal(err)
	}

	var locations []string
	for _, id := range []string{"definitely-nobody", "nomail", testUser} {
		resp := requestReset(t, ts, id)
		locations = append(locations, resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%q: status = %d", id, resp.StatusCode)
		}
	}
	for _, l := range locations {
		if l != "/forgot-password?sent=1" {
			t.Errorf("response differs by identifier: %v", locations)
			break
		}
	}
	if n := len(ts.mail.messages()); n != 1 {
		t.Errorf("emails sent = %d, want 1 (only the real account with an address)", n)
	}
	_, page := getWithSession(t, ts, "/forgot-password?sent=1", nil)
	if !strings.Contains(page, "if an account matches") {
		t.Error("generic confirmation missing")
	}
}

func TestForgot_FormValidation(t *testing.T) {
	ts := newTestServer(t)
	resp := requestReset(t, ts, "   ")
	if resp.Header.Get("Location") != "/forgot-password?error=missing_identifier" {
		t.Errorf("blank identifier Location = %q", resp.Header.Get("Location"))
	}
	r, err := ts.do(t, http.MethodPost, "/forgot-password", url.Values{"identifier": {testUser}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.Header.Get("Location") != "/forgot-password?error=antiforgery_failed" {
		t.Errorf("no-CSRF Location = %q", r.Header.Get("Location"))
	}
	if len(ts.mail.messages()) != 0 {
		t.Error("an email was sent for an invalid request")
	}
}

func TestForgot_PerAccountThrottle(t *testing.T) {
	ts := newTestServer(t)
	for i := 0; i < 8; i++ {
		resp := requestReset(t, ts, testUser)
		if resp.Header.Get("Location") != "/forgot-password?sent=1" {
			t.Fatalf("request %d Location = %q (the throttle must be invisible)", i, resp.Header.Get("Location"))
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
	_, body := getWithSession(t, ts, first, nil)
	if strings.Contains(body, `name="new_password"`) {
		t.Error("older link still usable after a newer one was issued")
	}
	_, body = getWithSession(t, ts, second, nil)
	if !strings.Contains(body, `name="new_password"`) {
		t.Error("newest link not usable")
	}
}

func TestReset_InvalidAndExpiredTokens(t *testing.T) {
	ts := newTestServer(t)
	for _, path := range []string{"/reset-password", "/reset-password?token=", "/reset-password?token=garbage"} {
		resp, body := getWithSession(t, ts, path, nil)
		if resp.StatusCode != http.StatusOK || strings.Contains(body, `name="new_password"`) || !strings.Contains(body, "invalid or has expired") {
			t.Errorf("%s: status=%d, expected the generic invalid-link page", path, resp.StatusCode)
		}
	}

	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	ts.clk.Advance(31 * time.Minute)
	_, body := getWithSession(t, ts, path, nil)
	if strings.Contains(body, `name="new_password"`) {
		t.Error("expired link still shows the form")
	}
}

func TestReset_ExpiryBetweenGetAndPostIsRejected(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)

	resp, body := getWithSession(t, ts, path, nil)
	csrf := extractInputValue(t, body, `name="csrf_token"`)
	tok := extractInputValue(t, body, `name="token"`)
	ts.clk.Advance(31 * time.Minute)
	form := url.Values{"csrf_token": {csrf}, "token": {tok}, "new_password": {"brand-new-secret"}, "new_password_confirm": {"brand-new-secret"}}
	r, err := ts.do(t, http.MethodPost, "/reset-password", form, []*http.Cookie{findCookie(resp.Cookies(), "_csrf_reset")})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("expired POST status = %d, want 400", r.StatusCode)
	}
	if l := loginWithCreds(t, ts, testUser, "brand-new-secret", ""); !strings.HasPrefix(l.Header.Get("Location"), "/login?error=") {
		t.Error("password changed with an expired token")
	}
}

func TestReset_ValidationKeepsTokenUsable(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)

	for _, tc := range []struct{ name, next, confirm, want string }{
		{"mismatch", "brand-new-secret", "different-secret", "passwords do not match"},
		{"weak", "short", "short", "must be 8-72 characters"},
		{"missing", "", "", "fill out both password fields"},
	} {
		r, body := submitReset(t, ts, path, tc.next, tc.confirm)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, tc.want) {
			t.Errorf("%s: status=%d body lacks %q", tc.name, r.StatusCode, tc.want)
		}
		if !strings.Contains(body, `name="new_password"`) {
			t.Errorf("%s: form not re-shown, the token was burned by a validation error", tc.name)
		}
	}
	// None of those attempts consumed the link or changed the password.
	done, _ := submitReset(t, ts, path, "brand-new-secret", "brand-new-secret")
	if done.StatusCode != http.StatusSeeOther {
		t.Errorf("valid submission after typos: status = %d, want 303", done.StatusCode)
	}
}

func TestReset_PostGuards(t *testing.T) {
	ts := newTestServer(t)
	requestReset(t, ts, testUser)
	path := resetPathFromMail(t, ts)
	resp, body := getWithSession(t, ts, path, nil)
	csrf := extractInputValue(t, body, `name="csrf_token"`)
	tok := extractInputValue(t, body, `name="token"`)
	cookie := findCookie(resp.Cookies(), "_csrf_reset")

	post := func(form url.Values, c *http.Cookie) int {
		var cookies []*http.Cookie
		if c != nil {
			cookies = append(cookies, c)
		}
		r, err := ts.do(t, http.MethodPost, "/reset-password", form, cookies)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	good := func() url.Values {
		return url.Values{"csrf_token": {csrf}, "token": {tok}, "new_password": {"brand-new-secret"}, "new_password_confirm": {"brand-new-secret"}}
	}
	if post(good(), nil) != http.StatusBadRequest {
		t.Error("POST without the CSRF cookie accepted")
	}
	bad := good()
	bad.Set("csrf_token", "wrong")
	if post(bad, cookie) != http.StatusBadRequest {
		t.Error("POST with a wrong CSRF token accepted")
	}
	bad = good()
	bad.Set("token", "forged-token")
	if post(bad, cookie) != http.StatusBadRequest {
		t.Error("POST with a forged reset token accepted")
	}
	if l := loginWithCreds(t, ts, testUser, "brand-new-secret", ""); !strings.HasPrefix(l.Header.Get("Location"), "/login?error=") {
		t.Error("a rejected request changed the password")
	}
}

func TestReset_ConcurrentSubmissionsExactlyOneWins(t *testing.T) {
	for name, ts := range map[string]*testServer{"memory": newTestServer(t), "gorm": newGormTestServer(t)} {
		t.Run(name, func(t *testing.T) {
			requestReset(t, ts, testUser)
			path := resetPathFromMail(t, ts)
			resp, body := getWithSession(t, ts, path, nil)
			csrf := extractInputValue(t, body, `name="csrf_token"`)
			tok := extractInputValue(t, body, `name="token"`)
			cookie := findCookie(resp.Cookies(), "_csrf_reset")

			const n = 8
			codes := make(chan int, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					form := url.Values{"csrf_token": {csrf}, "token": {tok}, "new_password": {"brand-new-secret"}, "new_password_confirm": {"brand-new-secret"}}
					r, err := ts.do(t, http.MethodPost, "/reset-password", form, []*http.Cookie{cookie})
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
				if c == http.StatusSeeOther {
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
	done, _ := submitReset(t, ts, path, "brand-new-secret", "brand-new-secret")
	if done.Header.Get("Location") != "/login?notice=password_reset" {
		t.Fatalf("Location = %q", done.Header.Get("Location"))
	}
	if r, _ := getWithSession(t, ts, "/", other); r.StatusCode != http.StatusSeeOther {
		t.Error("pre-reset session survived on the GORM store")
	}
	fresh := loginWithCreds(t, ts, testUser, "brand-new-secret", "")
	fresh.Body.Close()
	if fresh.Header.Get("Location") != "/" {
		t.Errorf("new password rejected on GORM store: %q", fresh.Header.Get("Location"))
	}
}
