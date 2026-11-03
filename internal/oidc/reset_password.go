package oidc

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// Reset-password error codes.
const (
	resetErrAntiforgery = "antiforgery_failed"
	resetErrInvalid     = "invalid_token"
	resetErrMissing     = "password_missing"
	resetErrMismatch    = "password_mismatch"
	resetErrWeak        = "password_weak"
	resetErrServer      = "server_error"
)

// loginNoticePasswordReset is the ?notice= value the login page turns
// into a "password updated" banner.
const loginNoticePasswordReset = "password_reset"

// ResetPasswordConfig bundles the paths the handler needs.
type ResetPasswordConfig struct {
	LoginPath    string
	RequireHTTPS bool
}

// ResetPasswordHandler implements the API behind the page the emailed
// link opens: GET /api/auth/reset-password?token=... reports whether
// the token is usable, POST sets the new password.
type ResetPasswordHandler struct {
	Cfg           ResetPasswordConfig
	Users         store.UserStore
	Resets        store.PasswordResetStore
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	// AuditLogs is optional.
	AuditLogs store.AuditLogStore
	Clock     clock.Clock
	Logger    *slog.Logger
	// ClientIP extracts the source IP for audit entries. Optional.
	ClientIP func(*http.Request) string
}

func (h *ResetPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The token is a live credential: keep it out of Referer headers
	// and caches.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

// lookup returns the usable token for a raw value, or nil when it is
// unknown, consumed or expired.
func (h *ResetPasswordHandler) lookup(r *http.Request, raw string) *domain.PasswordResetToken {
	if raw == "" {
		return nil
	}
	t, err := h.Resets.FindByHash(r.Context(), token.HashToken(raw))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.Logger.Error("reset: token lookup failed", "err", err)
		}
		return nil
	}
	if t.ConsumedAt != nil || !h.Clock.Now().Before(t.ExpiresAt) {
		return nil
	}
	return t
}

func (h *ResetPasswordHandler) respondWithError(w http.ResponseWriter, status int, code string) {
	writeJSONError(w, status, code, resetErrorLabel(code))
}

func (h *ResetPasswordHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	// Same answer whether the token is missing, wrong, used or expired.
	writeJSON(w, http.StatusOK, map[string]any{"valid": h.lookup(r, raw) != nil})
}

type resetPasswordRequest struct {
	Token           string `json:"token"`
	NewPassword     string `json:"new_password"`
	PasswordConfirm string `json:"new_password_confirm"`
}

func (h *ResetPasswordHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	if !APICSRFGuard(h.Cfg.RequireHTTPS).VerifyHeader(r) {
		h.respondWithError(w, http.StatusForbidden, resetErrAntiforgery)
		return
	}
	var body resetPasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, resetErrInvalid)
		return
	}
	raw := body.Token
	if h.lookup(r, raw) == nil {
		h.respondWithError(w, http.StatusBadRequest, resetErrInvalid)
		return
	}

	next := body.NewPassword
	confirm := body.PasswordConfirm
	switch {
	case next == "" || confirm == "":
		h.respondWithError(w, http.StatusBadRequest, resetErrMissing)
		return
	case next != confirm:
		h.respondWithError(w, http.StatusBadRequest, resetErrMismatch)
		return
	case ValidatePassword(next) != nil:
		h.respondWithError(w, http.StatusBadRequest, resetErrWeak)
		return
	}

	// Validation happens before consumption so a typo does not burn the
	// link. The CAS below is what makes the token single-use; it must win
	// before the password is touched.
	ctx := r.Context()
	now := h.Clock.Now().UTC()
	t := h.lookup(r, raw)
	if t == nil {
		h.respondWithError(w, http.StatusBadRequest, resetErrInvalid)
		return
	}
	won, err := h.Resets.Consume(ctx, t.ID, now)
	if err != nil {
		h.Logger.Error("reset: consume failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, resetErrServer)
		return
	}
	if !won {
		h.respondWithError(w, http.StatusBadRequest, resetErrInvalid)
		return
	}

	if err := h.Users.SetPassword(ctx, t.UserID, next); err != nil {
		// The token is spent; the user has to ask for a new link.
		h.Logger.Error("reset: set password failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, resetErrServer)
		return
	}

	// Everything below is cleanup after a successful change. Failures are
	// logged but must not report the reset as failed.
	if user, err := h.Users.FindUserByID(ctx, t.UserID); err == nil {
		user.SecurityStamp = uuid.NewString()
		user.UpdatedAt = now
		if err := h.Users.UpdateUser(ctx, user); err != nil {
			h.Logger.Error("reset: security stamp rotation failed", "err", err)
		}
	} else {
		h.Logger.Error("reset: user lookup failed", "err", err)
	}
	if err := h.Resets.InvalidateForUser(ctx, t.UserID, now); err != nil {
		h.Logger.Error("reset: invalidating other tokens failed", "err", err)
	}
	// Whoever held a session may be the attacker; end them all.
	revoked, err := h.Sessions.RevokeByUserIDExcept(ctx, t.UserID, uuid.Nil, now)
	if err != nil {
		h.Logger.Error("reset: revoking sessions failed", "err", err)
	}
	for _, id := range revoked {
		if err := h.RefreshTokens.RevokeBySessionID(ctx, id, now); err != nil {
			h.Logger.Error("reset: revoking refresh tokens failed", "err", err)
		}
	}
	h.audit(r, t.UserID, len(revoked))

	writeJSON(w, http.StatusOK, map[string]any{"redirect": h.Cfg.LoginPath + "?notice=" + loginNoticePasswordReset})
}

func (h *ResetPasswordHandler) audit(r *http.Request, userID string, revoked int) {
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
		Action:      domain.AuditResetCompleted,
		ActorUserID: userID,
		TargetType:  "User",
		TargetID:    userID,
		Timestamp:   h.Clock.Now().UTC(),
		IPAddress:   truncate(ip, 64),
		UserAgent:   truncate(r.UserAgent(), 512),
		Metadata:    `{"sessions_revoked":` + strconv.Itoa(revoked) + `}`,
	})
	if err != nil {
		h.Logger.Warn("reset: audit write failed", "err", err)
	}
}

func resetErrorLabel(code string) string {
	switch code {
	case resetErrAntiforgery:
		return "Your page expired. Please reload and try again."
	case resetErrInvalid:
		return "This reset link is invalid or has expired. Please request a new one."
	case resetErrMissing:
		return "Please fill out both password fields."
	case resetErrMismatch:
		return "The passwords do not match."
	case resetErrWeak:
		return "Password must be 8-72 characters and must not start or end with whitespace."
	default:
		return "An unexpected error occurred. Please request a new reset link."
	}
}
