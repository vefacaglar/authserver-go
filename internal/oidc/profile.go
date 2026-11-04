package oidc

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// Profile API status/error codes returned in the JSON body.
const (
	profileStatusSessionOut  = "session_revoked"
	profileStatusOthersOut   = "other_sessions_revoked"
	profileStatusPasswordSet = "password_changed"

	profileErrAntiforgery = "antiforgery_failed"
	profileErrServer      = "server_error"
	profileErrCurrent     = "current_session"

	profileErrPasswordMissing  = "password_missing"
	profileErrPasswordMismatch = "password_mismatch"
	profileErrPasswordWeak     = "password_weak"
	profileErrPasswordSame     = "password_unchanged"
	profileErrCurrentWrong     = "current_password_wrong"
	profileErrLocked           = "account_locked"
)

// ProfileConfig bundles the paths and flags the profile API needs.
type ProfileConfig struct {
	// BasePath is the API path the handler is mounted at
	// ("/api/account/profile"); subpaths hang off it.
	BasePath     string
	RequireHTTPS bool
}

// ProfileHandler implements the signed-in user's profile API: view the
// account fields, change the password, and list/revoke their own active
// sessions. It must be mounted behind SessionResolver.RequireSession and
// serves BasePath plus the POST endpoints under it.
type ProfileHandler struct {
	Cfg           ProfileConfig
	Users         store.UserStore
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	AuditLogs     store.AuditLogStore
	// Tracker throttles wrong "current password" guesses on the change
	// password form. Optional, but production wiring should set it.
	Tracker store.LoginAttemptTracker
	Clock   clock.Clock
	Logger  *slog.Logger
	// ClientIP extracts the source IP for audit entries. Optional.
	ClientIP func(*http.Request) string
}

type profileSessionView struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
}

type profileView struct {
	Username         string               `json:"username"`
	Email            string               `json:"email"`
	HasOtherSessions bool                 `json:"has_other_sessions"`
	Sessions         []profileSessionView `json:"sessions"`
}

func (h *ProfileHandler) revokePath() string { return h.Cfg.BasePath + "/sessions/revoke" }
func (h *ProfileHandler) revokeOthersPath() string {
	return h.Cfg.BasePath + "/sessions/revoke-others"
}
func (h *ProfileHandler) passwordPath() string { return h.Cfg.BasePath + "/password" }

func (h *ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, ErrLoginRequired, "login required")
		return
	}
	switch {
	case r.URL.Path == h.Cfg.BasePath && r.Method == http.MethodGet:
		h.getProfile(w, r, sess)
	case r.URL.Path == h.revokePath() && r.Method == http.MethodPost:
		h.revokeSession(w, r, sess)
	case r.URL.Path == h.revokeOthersPath() && r.Method == http.MethodPost:
		h.revokeOthers(w, r, sess)
	case r.URL.Path == h.passwordPath() && r.Method == http.MethodPost:
		h.changePassword(w, r, sess)
	default:
		if r.URL.Path == h.revokePath() || r.URL.Path == h.revokeOthersPath() || r.URL.Path == h.passwordPath() {
			w.Header().Set("Allow", "POST")
		} else {
			w.Header().Set("Allow", "GET")
		}
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

func (h *ProfileHandler) csrfOK(w http.ResponseWriter, r *http.Request) bool {
	if APICSRFGuard(h.Cfg.RequireHTTPS).VerifyHeader(r) {
		return true
	}
	h.respondWithError(w, http.StatusForbidden, profileErrAntiforgery)
	return false
}

func (h *ProfileHandler) respondWithError(w http.ResponseWriter, status int, code string) {
	writeJSONError(w, status, code, profileErrorLabel(code))
}

func (h *ProfileHandler) getProfile(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	ctx := r.Context()
	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: user lookup failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}

	view := profileView{
		Username: user.Username,
		Email:    user.Email,
		Sessions: []profileSessionView{},
	}
	active, err := h.Sessions.ListByUserID(ctx, sess.UserID, h.Clock.Now())
	if err != nil {
		h.Logger.WarnContext(r.Context(), "profile: session list failed", "err", err)
	}
	for _, s := range active {
		if s.ID != sess.ID {
			view.HasOtherSessions = true
		}
		view.Sessions = append(view.Sessions, profileSessionView{
			ID:        s.ID.String(),
			CreatedAt: s.CreatedAt.UTC(),
			ExpiresAt: s.ExpiresAt.UTC(),
			Current:   s.ID == sess.ID,
		})
	}
	writeJSON(w, http.StatusOK, view)
}

type revokeSessionRequest struct {
	SessionID string `json:"session_id"`
}

func (h *ProfileHandler) revokeSession(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if !h.csrfOK(w, r) {
		return
	}
	var body revokeSessionRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid request body")
		return
	}
	id, err := uuid.Parse(body.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	ctx := r.Context()
	target, err := h.Sessions.Find(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
			return
		}
		h.Logger.ErrorContext(r.Context(), "profile: session lookup failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	// A session that is not the caller's looks exactly like a missing one.
	if target.UserID != sess.UserID {
		writeJSONError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	// Signing out the current session is what the logout flow is for; it
	// also clears the cookie.
	if target.ID == sess.ID {
		h.respondWithError(w, http.StatusBadRequest, profileErrCurrent)
		return
	}

	now := h.Clock.Now().UTC()
	if err := h.Sessions.Revoke(ctx, target.ID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.Logger.ErrorContext(r.Context(), "profile: session revoke failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	if err := h.RefreshTokens.RevokeBySessionID(ctx, target.ID, now); err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: refresh token revoke failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	h.audit(r, sess.UserID, domain.AuditSessionRevoked, "Session", target.ID.String(), "")
	writeJSON(w, http.StatusOK, map[string]any{"status": profileStatusSessionOut})
}

// audit appends an entry; like login history it is informational, so a
// write failure is logged and never fails the request.
func (h *ProfileHandler) audit(r *http.Request, userID, action, targetType, targetID, metadata string) {
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
		TargetType:  targetType,
		TargetID:    targetID,
		Timestamp:   h.Clock.Now().UTC(),
		IPAddress:   truncate(ip, 64),
		UserAgent:   truncate(r.UserAgent(), 512),
		Metadata:    metadata,
	})
	if err != nil {
		h.Logger.WarnContext(r.Context(), "profile audit write failed", "action", action, "err", err)
	}
}

func profileStatusLabel(code string) string {
	switch code {
	case profileStatusSessionOut:
		return "The session was signed out."
	case profileStatusOthersOut:
		return "All other sessions were signed out."
	case profileStatusPasswordSet:
		return "Your password was changed. All other sessions were signed out."
	default:
		return ""
	}
}

func profileErrorLabel(code string) string {
	switch code {
	case profileErrAntiforgery:
		return "Your page expired. Please reload and try again."
	case profileErrCurrent:
		return "Use sign out to end the current session."
	case profileErrPasswordMissing:
		return "Please fill out all password fields."
	case profileErrPasswordMismatch:
		return "The new passwords do not match."
	case profileErrPasswordWeak:
		return "The new password must be 8-72 characters and must not start or end with whitespace."
	case profileErrPasswordSame:
		return "The new password must differ from the current one."
	case profileErrCurrentWrong:
		return "The current password is incorrect."
	case profileErrLocked:
		return "Too many failed attempts. Please try again later."
	default:
		return "An unexpected error occurred. Please try again later."
	}
}

// revokeOthers signs out every session of the user except the current one.
func (h *ProfileHandler) revokeOthers(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if !h.csrfOK(w, r) {
		return
	}
	n, err := h.revokeOtherSessions(r, sess)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: revoke other sessions failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	h.audit(r, sess.UserID, domain.AuditSessionRevoked, "User", sess.UserID, `{"scope":"others","count":`+strconv.Itoa(n)+`}`)
	writeJSON(w, http.StatusOK, map[string]any{"status": profileStatusOthersOut, "count": n})
}

// revokeOtherSessions revokes the user's sessions other than sess, plus
// the refresh tokens issued under them, and returns how many sessions it
// revoked.
func (h *ProfileHandler) revokeOtherSessions(r *http.Request, sess *domain.Session) (int, error) {
	ctx := r.Context()
	now := h.Clock.Now().UTC()
	ids, err := h.Sessions.RevokeByUserIDExcept(ctx, sess.UserID, sess.ID, now)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := h.RefreshTokens.RevokeBySessionID(ctx, id, now); err != nil {
			return len(ids), err
		}
	}
	return len(ids), nil
}

// passwordLockoutKey keeps wrong-current-password guesses in their own
// bucket, separate from the sign-in lockout for the same account.
func (h *ProfileHandler) passwordLockoutKey(r *http.Request, userID string) string {
	ip := ""
	if h.ClientIP != nil {
		ip = h.ClientIP(r)
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return "pwchange:" + userID + "|" + ip
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	PasswordConfirm string `json:"new_password_confirm"`
}

func (h *ProfileHandler) changePassword(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if !h.csrfOK(w, r) {
		return
	}
	var body changePasswordRequest
	if err := decodeJSON(r, &body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, profileErrPasswordMissing)
		return
	}
	current := body.CurrentPassword
	next := body.NewPassword
	confirm := body.PasswordConfirm
	if current == "" || next == "" || confirm == "" {
		h.respondWithError(w, http.StatusBadRequest, profileErrPasswordMissing)
		return
	}

	ctx := r.Context()
	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: user lookup failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}

	// Verify the current password before judging the new one, so the form
	// cannot be used to probe policy details without knowing it. The
	// lockout check comes first so a locked caller cannot keep guessing.
	key := h.passwordLockoutKey(r, user.ID)
	if h.Tracker != nil {
		locked, err := h.Tracker.IsLockedOut(ctx, key)
		if err != nil {
			h.Logger.ErrorContext(r.Context(), "profile: tracker lookup failed", "err", err)
		}
		if locked {
			h.respondWithError(w, http.StatusTooManyRequests, profileErrLocked)
			return
		}
	}
	info, err := h.Users.ValidateCredentials(ctx, user.Username, current)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: credential check failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	if info == nil {
		if h.Tracker != nil {
			_ = h.Tracker.RecordFailure(ctx, key)
		}
		h.respondWithError(w, http.StatusBadRequest, profileErrCurrentWrong)
		return
	}
	if h.Tracker != nil {
		if err := h.Tracker.Reset(ctx, key); err != nil {
			h.Logger.WarnContext(r.Context(), "profile: tracker reset failed", "err", err)
		}
	}

	switch {
	case next != confirm:
		h.respondWithError(w, http.StatusBadRequest, profileErrPasswordMismatch)
		return
	case ValidatePassword(next) != nil:
		h.respondWithError(w, http.StatusBadRequest, profileErrPasswordWeak)
		return
	case next == current:
		h.respondWithError(w, http.StatusBadRequest, profileErrPasswordSame)
		return
	}

	if err := h.Users.SetPassword(ctx, user.ID, next); err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: set password failed", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, profileErrServer)
		return
	}
	// The password is already changed; a failure below must not report the
	// change as failed. Log it and carry on as far as possible.
	user.SecurityStamp = uuid.NewString()
	user.UpdatedAt = h.Clock.Now().UTC()
	if err := h.Users.UpdateUser(ctx, user); err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: security stamp rotation failed", "err", err)
	}
	n, err := h.revokeOtherSessions(r, sess)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "profile: revoking other sessions after password change failed", "err", err)
	}
	h.audit(r, user.ID, domain.AuditPasswordChanged, "User", user.ID, `{"sessions_revoked":`+strconv.Itoa(n)+`}`)
	writeJSON(w, http.StatusOK, map[string]any{"status": profileStatusPasswordSet})
}
