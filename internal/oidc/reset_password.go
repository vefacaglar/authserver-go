package oidc

import (
	"errors"
	"html/template"
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

// ResetPasswordConfig bundles the paths the page needs.
type ResetPasswordConfig struct {
	ResetPath    string
	ForgotPath   string
	LoginPath    string
	RequireHTTPS bool
}

// ResetPasswordHandler serves the page the emailed link opens: GET shows
// the new-password form for a valid token, POST sets the password.
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
	Template  *template.Template
	// ClientIP extracts the source IP for audit entries. Optional.
	ClientIP func(*http.Request) string
}

type resetData struct {
	CSRFToken  string
	Action     string
	Token      string
	TokenValid bool
	ForgotPath string
	LoginPath  string
	Error      string
	ErrorLabel string
}

func (h *ResetPasswordHandler) csrf() CSRFGuard {
	return CSRFGuard{CookieName: "_csrf_reset", Path: h.Cfg.ResetPath, RequireHTTPS: h.Cfg.RequireHTTPS}
}

func (h *ResetPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The URL carries a live credential: keep it out of Referer headers
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

func (h *ResetPasswordHandler) render(w http.ResponseWriter, status int, raw string, valid bool, errCode string) {
	d := resetData{
		Action:     h.Cfg.ResetPath,
		Token:      raw,
		TokenValid: valid,
		ForgotPath: h.Cfg.ForgotPath,
		LoginPath:  h.Cfg.LoginPath,
	}
	if valid {
		tok, err := h.csrf().Issue(w)
		if err != nil {
			h.Logger.Error("reset: csrf issue failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		d.CSRFToken = tok
	}
	if errCode != "" {
		d.Error, d.ErrorLabel = errCode, resetErrorLabel(errCode)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.Template.Execute(w, d); err != nil {
		h.Logger.Error("reset render failed", "err", err)
	}
}

func (h *ResetPasswordHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if h.lookup(r, raw) == nil {
		// Same page whether the token is missing, wrong, used or expired.
		h.render(w, http.StatusOK, "", false, resetErrInvalid)
		return
	}
	h.render(w, http.StatusOK, raw, true, "")
}

func (h *ResetPasswordHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !h.csrf().Verify(r) {
		h.render(w, http.StatusBadRequest, "", false, resetErrAntiforgery)
		return
	}
	raw := r.FormValue("token")
	if h.lookup(r, raw) == nil {
		h.render(w, http.StatusBadRequest, "", false, resetErrInvalid)
		return
	}

	next := r.FormValue("new_password")
	confirm := r.FormValue("new_password_confirm")
	switch {
	case next == "" || confirm == "":
		h.render(w, http.StatusBadRequest, raw, true, resetErrMissing)
		return
	case next != confirm:
		h.render(w, http.StatusBadRequest, raw, true, resetErrMismatch)
		return
	case ValidatePassword(next) != nil:
		h.render(w, http.StatusBadRequest, raw, true, resetErrWeak)
		return
	}

	// Validation happens before consumption so a typo does not burn the
	// link. The CAS below is what makes the token single-use; it must win
	// before the password is touched.
	ctx := r.Context()
	now := h.Clock.Now().UTC()
	t := h.lookup(r, raw)
	if t == nil {
		h.render(w, http.StatusBadRequest, "", false, resetErrInvalid)
		return
	}
	won, err := h.Resets.Consume(ctx, t.ID, now)
	if err != nil {
		h.Logger.Error("reset: consume failed", "err", err)
		h.render(w, http.StatusInternalServerError, "", false, resetErrServer)
		return
	}
	if !won {
		h.render(w, http.StatusBadRequest, "", false, resetErrInvalid)
		return
	}

	if err := h.Users.SetPassword(ctx, t.UserID, next); err != nil {
		// The token is spent; the user has to ask for a new link.
		h.Logger.Error("reset: set password failed", "err", err)
		h.render(w, http.StatusInternalServerError, "", false, resetErrServer)
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

	http.Redirect(w, r, h.Cfg.LoginPath+"?notice="+loginNoticePasswordReset, http.StatusSeeOther)
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
