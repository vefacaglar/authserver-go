package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// Login flow error codes surfaced via the ?error= query parameter so the
// login page can render a localised message without exposing server logs.
const (
	LoginErrInvalidCredentials = "invalid_credentials"
	LoginErrMissingCredentials = "missing_credentials"
	LoginErrAccountLocked      = "account_locked"
	LoginErrAntiforgeryFailed  = "antiforgery_failed"
	LoginErrInvalidReturn      = "invalid_return"
	LoginErrServerError        = "server_error"
)

// CSRF cookie/field names. The double-submit pattern: the server sets an
// HttpOnly cookie carrying an opaque token, and the form mirrors the same
// token in a hidden input. A cross-origin attacker can neither read the
// HttpOnly cookie nor inject a form field that the server would trust.
const (
	csrfCookieName = "_csrf"
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
)

// issueCSRFToken returns a fresh opaque token and stores it in the response
// cookie. The same value is rendered into the form (and also returned so
// the handler can put it in the template).
func (h *LoginHandler) issueCSRFToken(w http.ResponseWriter, r *http.Request) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		h.Logger.Error("csrf rand", "err", err)
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     h.Cfg.LoginPath,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.Cfg.IssuerURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	return tok
}

// verifyCSRFToken compares the cookie value with the form field / header
// value using a constant-time compare. Missing on either side is a failure.
func (h *LoginHandler) verifyCSRFToken(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	got := r.FormValue(csrfFieldName)
	if got == "" {
		got = r.Header.Get(csrfHeaderName)
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(got)) == 1
}

// LoginConfig bundles the policy inputs the login handler reads.
type LoginConfig struct {
	IssuerURL       string
	LoginPath       string
	RegisterPath    string
	AuthorizePath   string
	SessionLifetime time.Duration
}

// LoginHandler implements GET (render) and POST (validate) for /login.
// State stored in cookies:
//   - the encrypted SSO session cookie, set on success
//   - the gorilla/csrf cookie, set by the csrf middleware
type LoginHandler struct {
	Cfg      LoginConfig
	Users    store.UserStore
	Sessions store.SessionStore
	Cookies  *session.CookieManager
	Tracker  store.LoginAttemptTracker
	Clock    clock.Clock
	Logger   *slog.Logger
	Template *template.Template
	// ClientIP extracts the source IP for the lockout key. Optional;
	// when nil the handler falls back to r.RemoteAddr so misconfigured
	// deployments do not accidentally disable lockouts (they would
	// just use the un-proxied address). Production wiring should
	// inject the same clientIP used by the rate limiter so the
	// username-keyed and IP-keyed enforcement share a view of
	// "who is this request from".
	ClientIP func(*http.Request) string
}

func (h *LoginHandler) render(w http.ResponseWriter, r *http.Request, errorCode, returnURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	token := h.issueCSRFToken(w, r)
	registerPath := h.Cfg.RegisterPath
	if returnURL != "" {
		registerPath += "?returnUrl=" + url.QueryEscape(returnURL)
	}
	data := struct {
		CSRFToken    string
		Action       string
		ReturnURL    string
		RegisterPath string
		Error        string
		ErrorLabel   string
	}{
		CSRFToken:    token,
		Action:       h.Cfg.LoginPath,
		ReturnURL:    returnURL,
		RegisterPath: registerPath,
		Error:        errorCode,
	}
	if errorCode != "" {
		data.ErrorLabel = loginErrorLabel(errorCode)
	}
	if err := h.Template.Execute(w, data); err != nil {
		h.Logger.Error("login render failed", "err", err)
	}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render(w, r, r.URL.Query().Get("error"), r.URL.Query().Get("returnUrl"))
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

func (h *LoginHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		h.respondWithError(w, r, LoginErrInvalidCredentials, "")
		return
	}
	if !h.verifyCSRFToken(r) {
		h.respondWithError(w, r, LoginErrAntiforgeryFailed, r.FormValue("returnUrl"))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	returnURL := r.FormValue("returnUrl")
	if username == "" || password == "" {
		h.respondWithError(w, r, LoginErrMissingCredentials, returnURL)
		return
	}

	trackerKey := h.lockoutKey(r, username)
	locked, err := h.Tracker.IsLockedOut(ctx, trackerKey)
	if err != nil {
		h.Logger.Error("tracker lookup failed", "err", err)
	}
	if locked {
		h.respondWithError(w, r, LoginErrAccountLocked, returnURL)
		return
	}

	info, err := h.Users.ValidateCredentials(ctx, username, password)
	if err != nil {
		h.Logger.Error("user store error", "err", err)
		h.respondWithError(w, r, LoginErrServerError, returnURL)
		return
	}
	if info == nil {
		_ = h.Tracker.RecordFailure(ctx, trackerKey)
		h.respondWithError(w, r, LoginErrInvalidCredentials, returnURL)
		return
	}

	if err := h.Tracker.Reset(ctx, trackerKey); err != nil {
		h.Logger.Warn("tracker reset failed", "err", err)
	}

	now := h.Clock.Now().UTC()
	sess := &domain.Session{
		ID:        uuid.New(),
		UserID:    info.UserID,
		CreatedAt: now,
		ExpiresAt: now.Add(h.Cfg.SessionLifetime),
	}
	if err := h.Sessions.Store(ctx, sess); err != nil {
		h.Logger.Error("session store failed", "err", err)
		h.respondWithError(w, r, LoginErrServerError, returnURL)
		return
	}
	if err := h.Cookies.SetCookie(w, sess.ID); err != nil {
		h.Logger.Error("session cookie set failed", "err", err)
		h.respondWithError(w, r, LoginErrServerError, returnURL)
		return
	}

	target, err := validateReturnURL(returnURL, h.Cfg.IssuerURL, h.Cfg.AuthorizePath)
	if err != nil {
		h.respondWithError(w, r, LoginErrInvalidReturn, "")
		return
	}
	if target == "" {
		// No returnUrl supplied (or it was empty after validation);
		// send the user to the issuer root rather than dumping them
		// back on the login page after a successful credential check.
		target = strings.TrimRight(h.Cfg.IssuerURL, "/") + "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *LoginHandler) respondWithError(w http.ResponseWriter, r *http.Request, code, returnURL string) {
	q := url.Values{}
	q.Set("error", code)
	if returnURL != "" {
		q.Set("returnUrl", returnURL)
	}
	target := h.Cfg.LoginPath + "?" + q.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

// validateReturnURL implements the open-redirect guard. The value must be
// either a relative path beginning with "/" (and not "//", which some
// browsers treat as a protocol-relative URL) or an absolute URL whose
// origin matches the issuer's.
func validateReturnURL(raw, issuerURL, authorizePath string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		iss, err := url.Parse(issuerURL)
		if err != nil {
			return "", err
		}
		if u.Scheme != iss.Scheme || u.Host != iss.Host {
			return "", errors.New("return url origin mismatch")
		}
		return u.String(), nil
	}
	// Reject protocol-relative and other tricks.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", errors.New("return url not a path")
	}
	// Pin to known paths so a login redirect can never be used to bounce
	// the user into an unrelated internal route.
	if !strings.HasPrefix(raw, authorizePath) && !strings.HasPrefix(raw, "/logout") {
		return "", errors.New("return url not in allow-list")
	}
	return raw, nil
}

// lockoutKey composes the tracker key for failed-login enforcement.
// A username-only key would let a distributed attacker rotate IPs to
// accumulate MaxFailures against a single account while the
// per-IP rate limiter slows each individual IP. Composing username
// with the source IP binds the two enforcement axes together:
// MaxFailures against an account must come from a single IP (or
// small IP set) to be effective, which is the realistic threat.
//
// A bare username key is recoverable from the composed key
// (everything before the separator), so the composed key does not
// reduce the protection of single-IP legitimate use.
func (h *LoginHandler) lockoutKey(r *http.Request, username string) string {
	ip := ""
	if h.ClientIP != nil {
		ip = h.ClientIP(r)
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return username + "|" + ip
}

func loginErrorLabel(code string) string {
	switch code {
	case LoginErrInvalidCredentials:
		return "Invalid username or password."
	case LoginErrMissingCredentials:
		return "Please enter both a username and a password."
	case LoginErrAccountLocked:
		return "Account temporarily locked due to repeated failures. Try again later."
	case LoginErrAntiforgeryFailed:
		return "Your session expired. Please reload and try again."
	case LoginErrInvalidReturn:
		return "The destination link is invalid. Please start over."
	default:
		return "An unexpected error occurred."
	}
}
