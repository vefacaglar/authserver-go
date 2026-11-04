package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/errlog"
	"go-authserver/internal/mail"
	"go-authserver/internal/store"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// Forgot-password error codes, surfaced through ?error=.
const (
	forgotErrAntiforgery = "antiforgery_failed"
	forgotErrMissing     = "missing_identifier"
)

// resetTokenRetention is how long expired tokens are kept before the
// opportunistic cleanup deletes them.
const resetTokenRetention = 24 * time.Hour

// ForgotPasswordConfig bundles the paths and policy the handler needs.
// ResetPath is the SPA page the emailed link opens.
type ForgotPasswordConfig struct {
	ResetPath     string
	PublicURL     string
	TokenLifetime time.Duration
	RequireHTTPS  bool
}

// ForgotPasswordHandler implements POST /api/auth/forgot-password.
//
// The response never depends on whether an account matched: the same
// {"sent": true} body is returned for unknown identifiers, accounts
// without an email, throttled accounts and real sends, so the form
// cannot be used to discover which accounts exist. The email itself is
// sent in the background so SMTP latency does not leak the difference
// either.
type ForgotPasswordHandler struct {
	Cfg     ForgotPasswordConfig
	Users   store.UserStore
	Resets  store.PasswordResetStore
	Mailer  mail.Mailer
	Tracker store.LoginAttemptTracker
	// AuditLogs is optional.
	AuditLogs store.AuditLogStore
	Clock     clock.Clock
	Logger    *slog.Logger
	// ClientIP extracts the source IP for audit entries. Optional.
	ClientIP func(*http.Request) string
	// Spawn runs the email send. Production leaves it nil (a goroutine);
	// tests set it to run inline so they can assert on the sent message.
	Spawn func(func())
}

type forgotPasswordRequest struct {
	Identifier string `json:"identifier"`
}

func (h *ForgotPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	if !APICSRFGuard(h.Cfg.RequireHTTPS).VerifyHeader(r) {
		writeJSONError(w, http.StatusForbidden, forgotErrAntiforgery, forgotErrorLabel(forgotErrAntiforgery))
		return
	}
	var body forgotPasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, forgotErrMissing, forgotErrorLabel(forgotErrMissing))
		return
	}
	identifier := strings.TrimSpace(body.Identifier)
	if identifier == "" {
		writeJSONError(w, http.StatusBadRequest, forgotErrMissing, forgotErrorLabel(forgotErrMissing))
		return
	}
	h.process(r, identifier)
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// process issues and mails a reset token when the identifier matches an
// account that can receive one. It reports nothing back to the caller.
func (h *ForgotPasswordHandler) process(r *http.Request, identifier string) {
	ctx := r.Context()
	now := h.Clock.Now().UTC()

	// Best-effort housekeeping; runs for every request so it adds no
	// signal about whether the identifier matched.
	_, _ = h.Resets.DeleteExpired(ctx, now.Add(-resetTokenRetention))

	user := h.findUser(ctx, identifier)
	if user == nil || user.Email == "" {
		return
	}

	// Reuse the lockout tracker as a per-account request throttle: every
	// request counts, and once the threshold is hit further requests are
	// silently dropped until the window passes. This keeps the form from
	// being used to mail-bomb a user.
	key := "pwreset:" + user.ID
	if h.Tracker != nil {
		if locked, err := h.Tracker.IsLockedOut(ctx, key); err != nil {
			h.Logger.ErrorContext(r.Context(), "forgot: tracker lookup failed", "err", err)
		} else if locked {
			return
		}
		_ = h.Tracker.RecordFailure(ctx, key)
	}

	raw, hash, err := token.NewOpaqueToken()
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "forgot: token generation failed", "err", err)
		return
	}
	// Only the newest link works.
	if err := h.Resets.InvalidateForUser(ctx, user.ID, now); err != nil {
		h.Logger.ErrorContext(r.Context(), "forgot: invalidating older tokens failed", "err", err)
		return
	}
	if err := h.Resets.Create(ctx, &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: hash,
		CreatedAt: now,
		ExpiresAt: now.Add(h.Cfg.TokenLifetime),
	}); err != nil {
		h.Logger.ErrorContext(r.Context(), "forgot: storing token failed", "err", err)
		return
	}
	h.audit(r, user.ID)

	msg := mail.Message{
		To:      user.Email,
		Subject: "Reset your password",
		Body:    h.emailBody(raw),
	}
	logContext := errlog.DetachRequest(ctx)
	send := func() {
		// The request context ends with the response; mail needs its own.
		sctx, cancel := context.WithTimeout(logContext, 30*time.Second)
		defer cancel()
		if err := h.Mailer.Send(sctx, msg); err != nil {
			h.Logger.ErrorContext(sctx, "forgot: sending reset email failed", "err", err)
		}
	}
	if h.Spawn != nil {
		h.Spawn(send)
	} else {
		go send()
	}
}

func (h *ForgotPasswordHandler) findUser(ctx context.Context, identifier string) *domain.User {
	if u, err := h.Users.FindUserByUsername(ctx, identifier); err == nil {
		return u
	}
	if u, err := h.Users.FindUserByEmail(ctx, identifier); err == nil {
		return u
	}
	return nil
}

func (h *ForgotPasswordHandler) emailBody(rawToken string) string {
	link := h.Cfg.PublicURL + h.Cfg.ResetPath + "?token=" + url.QueryEscape(rawToken)
	mins := int(h.Cfg.TokenLifetime.Minutes())
	return "Hello,\n\n" +
		"Someone (hopefully you) asked to reset the password for your account.\n" +
		"Open the link below to choose a new password. It can be used once and\n" +
		"expires in " + strconv.Itoa(mins) + " minutes:\n\n" +
		link + "\n\n" +
		"If you did not ask for this, ignore this email. Your password stays unchanged.\n"
}

func (h *ForgotPasswordHandler) audit(r *http.Request, userID string) {
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
		Action:      domain.AuditResetRequested,
		ActorUserID: userID,
		TargetType:  "User",
		TargetID:    userID,
		Timestamp:   h.Clock.Now().UTC(),
		IPAddress:   truncate(ip, 64),
		UserAgent:   truncate(r.UserAgent(), 512),
	})
	if err != nil {
		h.Logger.WarnContext(r.Context(), "forgot: audit write failed", "err", err)
	}
}

func forgotErrorLabel(code string) string {
	switch code {
	case forgotErrAntiforgery:
		return "Your page expired. Please reload and try again."
	case forgotErrMissing:
		return "Please enter your username or email."
	default:
		return "An unexpected error occurred."
	}
}
