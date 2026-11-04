package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// Login flow error codes returned in the JSON error body so the SPA can
// map them to messages without exposing server logs.
const (
	LoginErrInvalidCredentials = "invalid_credentials"
	LoginErrMissingCredentials = "missing_credentials"
	LoginErrAccountLocked      = "account_locked"
	LoginErrAntiforgeryFailed  = "antiforgery_failed"
	LoginErrInvalidReturn      = "invalid_return"
	LoginErrServerError        = "server_error"
)

// CSRF cookie/field names. The double-submit pattern: the server sets an
// HttpOnly cookie carrying an opaque token (see GET /api/csrf), and the
// client mirrors the same token in the X-CSRF-Token header (or the
// csrf_token form field on the logout confirm form). A cross-origin
// attacker can read neither the HttpOnly cookie nor the /api/csrf body.
const (
	csrfCookieName = "_csrf"
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
)

// LoginConfig bundles the policy inputs the login handler reads.
type LoginConfig struct {
	IssuerURL     string
	AuthorizePath string
	// ProfilePath is an allowed post-login target so the profile page
	// can send anonymous visitors through login and back.
	ProfilePath     string
	RequireHTTPS    bool
	SessionLifetime time.Duration
}

// LoginHandler implements POST /api/auth/login for the SPA. On success
// it sets the encrypted SSO session cookie and returns the validated
// redirect target as JSON; the SPA performs the navigation. The target
// is always server-validated (see validateReturnURL) — the SPA never
// gets to pick an arbitrary destination.
type LoginHandler struct {
	Cfg      LoginConfig
	Users    store.UserStore
	Sessions store.SessionStore
	Cookies  *session.CookieManager
	Tracker  store.LoginAttemptTracker
	Clock    clock.Clock
	Logger   *slog.Logger
	// ClientIP extracts the source IP for the lockout key. Optional;
	// when nil the handler falls back to r.RemoteAddr so misconfigured
	// deployments do not accidentally disable lockouts (they would
	// just use the un-proxied address). Production wiring should
	// inject the same clientIP used by the rate limiter so the
	// username-keyed and IP-keyed enforcement share a view of
	// "who is this request from".
	ClientIP func(*http.Request) string
	// AuditLogs records successful sign-ins for the home page's recent
	// activity list. Optional; a write failure never blocks a login.
	AuditLogs store.AuditLogStore
}

type loginRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	ReturnURL string `json:"return_url"`
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	ctx := r.Context()
	if !APICSRFGuard(h.Cfg.RequireHTTPS).VerifyHeader(r) {
		h.respondWithError(ctx, w, http.StatusForbidden, LoginErrAntiforgeryFailed)
		return
	}
	var body loginRequest
	if err := decodeJSON(r, &body); err != nil {
		h.reject(ctx, w, http.StatusBadRequest, LoginErrInvalidCredentials, "malformed_json")
		return
	}
	username := strings.TrimSpace(body.Username)
	password := body.Password
	returnURL := body.ReturnURL
	if username == "" || password == "" {
		h.respondWithError(ctx, w, http.StatusBadRequest, LoginErrMissingCredentials)
		return
	}

	trackerKey := h.lockoutKey(r, username)
	locked, err := h.Tracker.IsLockedOut(ctx, trackerKey)
	if err != nil && h.Logger != nil {
		h.Logger.ErrorContext(ctx, "login: tracker lookup failed", "err", err)
	}
	if locked {
		h.respondWithError(ctx, w, http.StatusTooManyRequests, LoginErrAccountLocked)
		return
	}

	info, err := h.Users.ValidateCredentials(ctx, username, password)
	if err != nil {
		h.fail(ctx, w, "login: credential validation failed", err)
		return
	}
	if info == nil {
		if err := h.Tracker.RecordFailure(ctx, trackerKey); err != nil && h.Logger != nil {
			h.Logger.WarnContext(ctx, "login: recording failed attempt failed", "err", err)
		}
		h.recordFailedLogin(r, username, h.Clock.Now().UTC())
		h.respondWithError(ctx, w, http.StatusUnauthorized, LoginErrInvalidCredentials)
		return
	}

	if err := h.Tracker.Reset(ctx, trackerKey); err != nil && h.Logger != nil {
		h.Logger.WarnContext(ctx, "tracker reset failed", "err", err)
	}

	now := h.Clock.Now().UTC()
	sess := &domain.Session{
		ID:        uuid.New(),
		UserID:    info.UserID,
		CreatedAt: now,
		ExpiresAt: now.Add(h.Cfg.SessionLifetime),
	}
	if err := h.Sessions.Store(ctx, sess); err != nil {
		h.fail(ctx, w, "login: session persistence failed", err)
		return
	}
	if err := h.Cookies.SetCookie(w, sess.ID); err != nil {
		h.fail(ctx, w, "login: session cookie creation failed", err)
		return
	}

	h.recordLogin(r, info.UserID, now)

	target, err := validateReturnURL(returnURL, h.Cfg.IssuerURL, h.Cfg.AuthorizePath, h.Cfg.ProfilePath)
	if err != nil {
		h.respondWithError(ctx, w, http.StatusBadRequest, LoginErrInvalidReturn)
		return
	}
	if target == "" {
		// No redirect brought the user here: land on the home page. The
		// path is relative on purpose: it stays on whatever host served
		// the SPA instead of bouncing to the configured issuer origin.
		target = homePath
	}
	if h.Logger != nil {
		h.Logger.InfoContext(ctx, "login succeeded", "event", "login_succeeded", "status", http.StatusOK)
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect": target})
}

func (h *LoginHandler) respondWithError(ctx context.Context, w http.ResponseWriter, status int, code string) {
	h.reject(ctx, w, status, code, code)
}

func (h *LoginHandler) reject(ctx context.Context, w http.ResponseWriter, status int, code, reason string) {
	description := loginErrorLabel(code)
	if h.Logger != nil {
		h.Logger.WarnContext(ctx, "login rejected", "event", "login_failed",
			"status", status, "response_code", code, "response_message", description, "error_code", reason)
	}
	writeJSONError(w, status, code, description)
}

func (h *LoginHandler) fail(ctx context.Context, w http.ResponseWriter, message string, err error) {
	description := loginErrorLabel(LoginErrServerError)
	if h.Logger != nil {
		h.Logger.ErrorContext(ctx, message, "event", "login_failed",
			"status", http.StatusInternalServerError, "response_code", LoginErrServerError,
			"response_message", description, "err", err)
	}
	writeJSONError(w, http.StatusInternalServerError, LoginErrServerError, description)
}

// recordLogin appends a login_succeeded audit entry.
func (h *LoginHandler) recordLogin(r *http.Request, userID string, now time.Time) {
	h.recordAuth(r, userID, domain.AuditLoginSucceeded, "", now)
}

// recordFailedLogin appends a login_failed entry for the account the
// typed identifier belongs to, so the owner sees it on the home page.
// Attempts against unknown identifiers are not recorded: they have no
// owner to show them to, and the typed text is never stored because it
// can be a password typed into the wrong field. Rate limiting and the
// lockout tracker already bound how many of these a client can write.
func (h *LoginHandler) recordFailedLogin(r *http.Request, identifier string, now time.Time) {
	if h.AuditLogs == nil {
		return
	}
	userID := h.lookupUserID(r.Context(), identifier)
	if userID == "" {
		return
	}
	h.recordAuth(r, userID, domain.AuditLoginFailed, `{"reason":"invalid_credentials"}`, now)
}

// lookupUserID resolves a username or email to a user id, or "" when
// there is no such account (or the lookup fails).
func (h *LoginHandler) lookupUserID(ctx context.Context, identifier string) string {
	if u, err := h.Users.FindUserByUsername(ctx, identifier); err == nil {
		return u.ID
	}
	if u, err := h.Users.FindUserByEmail(ctx, identifier); err == nil {
		return u.ID
	}
	return ""
}

// recordAuth appends an audit entry. History is informational, not part
// of authentication, so a write failure is logged and swallowed.
func (h *LoginHandler) recordAuth(r *http.Request, userID, action, metadata string, now time.Time) {
	if h.AuditLogs == nil {
		return
	}
	ip := ""
	if h.ClientIP != nil {
		ip = h.ClientIP(r)
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	err := h.AuditLogs.Store(r.Context(), &domain.AuditLog{
		ID:          uuid.New(),
		Action:      action,
		ActorUserID: userID,
		TargetType:  "User",
		TargetID:    userID,
		Timestamp:   now,
		IPAddress:   truncate(ip, 64),
		UserAgent:   truncate(r.UserAgent(), 512),
		Metadata:    metadata,
	})
	if err != nil && h.Logger != nil {
		h.Logger.WarnContext(r.Context(), "login audit write failed", "err", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// validateReturnURL implements the open-redirect guard. The value must be
// either a relative path beginning with "/" (and not "//", which some
// browsers treat as a protocol-relative URL) or an absolute URL whose
// origin matches the issuer's.
func validateReturnURL(raw, issuerURL, authorizePath string, accountPaths ...string) (string, error) {
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
	// The account pages are matched on the exact path (any query is fine),
	// never as a prefix.
	if u.Path == homePath || (u.Path != "" && slices.Contains(accountPaths, u.Path)) {
		return raw, nil
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
