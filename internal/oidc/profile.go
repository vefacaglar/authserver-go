package oidc

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// Profile page status/error codes, surfaced through ?status= / ?error=.
const (
	profileStatusNameUpdated   = "name_updated"
	profileStatusNameUnchanged = "name_unchanged"
	profileStatusSessionOut    = "session_revoked"
	profileStatusOthersOut     = "other_sessions_revoked"
	profileStatusPasswordSet   = "password_changed"

	profileErrAntiforgery  = "antiforgery_failed"
	profileErrNameRequired = "name_required"
	profileErrNameTooLong  = "name_too_long"
	profileErrNameInvalid  = "name_invalid"
	profileErrServer       = "server_error"

	profileErrPasswordMissing  = "password_missing"
	profileErrPasswordMismatch = "password_mismatch"
	profileErrPasswordWeak     = "password_weak"
	profileErrPasswordSame     = "password_unchanged"
	profileErrCurrentWrong     = "current_password_wrong"
	profileErrLocked           = "account_locked"
)

// profileNameMaxRunes bounds the display name.
const profileNameMaxRunes = 100

// profileNameClaim is the claim that carries the display name into ID
// tokens and userinfo (scope "profile").
const profileNameClaim = "name"

// ProfileConfig bundles the paths and flags the profile page needs.
type ProfileConfig struct {
	ProfilePath  string
	LogoutPath   string
	RequireHTTPS bool
}

// ProfileHandler serves the signed-in user's profile page: view and edit
// the display name, and list/revoke their own active sessions. It must be
// mounted behind SessionResolver.RequireSession and serves both
// ProfilePath (GET, POST) and ProfilePath+"/sessions/revoke" (POST).
type ProfileHandler struct {
	Cfg           ProfileConfig
	Users         store.UserStore
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	AuditLogs     store.AuditLogStore
	// Tracker throttles wrong "current password" guesses on the change
	// password form. Optional, but production wiring should set it.
	Tracker  store.LoginAttemptTracker
	Clock    clock.Clock
	Logger   *slog.Logger
	Template *template.Template
	// ClientIP extracts the source IP for audit entries. Optional.
	ClientIP func(*http.Request) string
}

type profileSession struct {
	ID      string
	Created string
	Expires string
	Current bool
}

type profileData struct {
	Nav                appNav
	CSRFToken          string
	Action             string
	RevokeAction       string
	RevokeOthersAction string
	PasswordAction     string
	HasOtherSessions   bool
	Username           string
	Name               string
	Email              string
	Sessions           []profileSession
	Status             string
	StatusLabel        string
	Error              string
	ErrorLabel         string
}

func (h *ProfileHandler) csrf() CSRFGuard {
	return CSRFGuard{CookieName: "_csrf_profile", Path: h.Cfg.ProfilePath, RequireHTTPS: h.Cfg.RequireHTTPS}
}

func (h *ProfileHandler) revokePath() string { return h.Cfg.ProfilePath + "/sessions/revoke" }
func (h *ProfileHandler) revokeOthersPath() string {
	return h.Cfg.ProfilePath + "/sessions/revoke-others"
}
func (h *ProfileHandler) passwordPath() string { return h.Cfg.ProfilePath + "/password" }

func (h *ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == h.Cfg.ProfilePath && r.Method == http.MethodGet:
		h.render(w, r, sess)
	case r.URL.Path == h.Cfg.ProfilePath && r.Method == http.MethodPost:
		h.updateName(w, r, sess)
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
			w.Header().Set("Allow", "GET, POST")
		}
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

func (h *ProfileHandler) render(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	ctx := r.Context()
	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.Error("profile: user lookup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token, err := h.csrf().Issue(w)
	if err != nil {
		h.Logger.Error("profile: csrf issue failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := profileData{
		Nav:                appNav{HomePath: homePath, ProfilePath: h.Cfg.ProfilePath, LogoutPath: h.Cfg.LogoutPath, Active: "profile"},
		CSRFToken:          token,
		Action:             h.Cfg.ProfilePath,
		RevokeAction:       h.revokePath(),
		RevokeOthersAction: h.revokeOthersPath(),
		PasswordAction:     h.passwordPath(),
		Username:           user.Username,
		Email:              user.Email,
	}
	claims, err := h.Users.GetUserClaims(ctx, sess.UserID)
	if err != nil {
		h.Logger.Warn("profile: claims lookup failed", "err", err)
	}
	for _, c := range claims {
		if c.Type == profileNameClaim {
			data.Name = c.Value
			break
		}
	}

	active, err := h.Sessions.ListByUserID(ctx, sess.UserID, h.Clock.Now())
	if err != nil {
		h.Logger.Warn("profile: session list failed", "err", err)
	}
	for _, s := range active {
		if s.ID != sess.ID {
			data.HasOtherSessions = true
		}
		data.Sessions = append(data.Sessions, profileSession{
			ID:      s.ID.String(),
			Created: s.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Expires: s.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
			Current: s.ID == sess.ID,
		})
	}

	q := r.URL.Query()
	if label := profileStatusLabel(q.Get("status")); label != "" {
		data.Status, data.StatusLabel = q.Get("status"), label
	}
	if code := q.Get("error"); code != "" {
		data.Error, data.ErrorLabel = code, profileErrorLabel(code)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.Template.Execute(w, data); err != nil {
		h.Logger.Error("profile render failed", "err", err)
	}
}

func (h *ProfileHandler) updateName(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if err := r.ParseForm(); err != nil || !h.csrf().Verify(r) {
		h.redirect(w, r, "error", profileErrAntiforgery)
		return
	}
	name, errCode := normalizeDisplayName(r.FormValue("name"))
	if errCode != "" {
		h.redirect(w, r, "error", errCode)
		return
	}

	ctx := r.Context()
	claims, err := h.Users.GetUserClaims(ctx, sess.UserID)
	if err != nil {
		h.Logger.Error("profile: claims lookup failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	var old []domain.UserClaim
	for _, c := range claims {
		if c.Type == profileNameClaim {
			old = append(old, c)
		}
	}
	if len(old) == 1 && old[0].Value == name {
		h.redirect(w, r, "status", profileStatusNameUnchanged)
		return
	}
	// Remove-then-add rather than ReplaceUserClaims: that call rewrites
	// every claim, so a failure midway could wipe unrelated ones.
	if len(old) > 0 {
		if err := h.Users.RemoveUserClaims(ctx, sess.UserID, old); err != nil {
			h.Logger.Error("profile: remove name claim failed", "err", err)
			h.redirect(w, r, "error", profileErrServer)
			return
		}
	}
	if err := h.Users.AddUserClaims(ctx, sess.UserID, []domain.UserClaim{{Type: profileNameClaim, Value: name}}); err != nil {
		h.Logger.Error("profile: add name claim failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	h.audit(r, sess.UserID, domain.AuditProfileUpdated, "User", sess.UserID, `{"field":"name"}`)
	h.redirect(w, r, "status", profileStatusNameUpdated)
}

func (h *ProfileHandler) revokeSession(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if err := r.ParseForm(); err != nil || !h.csrf().Verify(r) {
		h.redirect(w, r, "error", profileErrAntiforgery)
		return
	}
	id, err := uuid.Parse(r.FormValue("session_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	target, err := h.Sessions.Find(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		h.Logger.Error("profile: session lookup failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	// A session that is not the caller's looks exactly like a missing one.
	if target.UserID != sess.UserID {
		http.NotFound(w, r)
		return
	}
	// Signing out the current session is what the logout flow is for; it
	// also clears the cookie.
	if target.ID == sess.ID {
		http.Redirect(w, r, h.Cfg.LogoutPath, http.StatusSeeOther)
		return
	}

	now := h.Clock.Now().UTC()
	if err := h.Sessions.Revoke(ctx, target.ID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.Logger.Error("profile: session revoke failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	if err := h.RefreshTokens.RevokeBySessionID(ctx, target.ID, now); err != nil {
		h.Logger.Error("profile: refresh token revoke failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	h.audit(r, sess.UserID, domain.AuditSessionRevoked, "Session", target.ID.String(), "")
	h.redirect(w, r, "status", profileStatusSessionOut)
}

func (h *ProfileHandler) redirect(w http.ResponseWriter, r *http.Request, key, code string) {
	q := url.Values{}
	q.Set(key, code)
	http.Redirect(w, r, h.Cfg.ProfilePath+"?"+q.Encode(), http.StatusSeeOther)
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
		h.Logger.Warn("profile audit write failed", "action", action, "err", err)
	}
}

// normalizeDisplayName trims and validates a display name, returning the
// cleaned name or an error code.
func normalizeDisplayName(raw string) (string, string) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", profileErrNameRequired
	}
	if !utf8.ValidString(name) {
		return "", profileErrNameInvalid
	}
	if utf8.RuneCountInString(name) > profileNameMaxRunes {
		return "", profileErrNameTooLong
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", profileErrNameInvalid
		}
	}
	return name, ""
}

func profileStatusLabel(code string) string {
	switch code {
	case profileStatusNameUpdated:
		return "Your name was updated."
	case profileStatusNameUnchanged:
		return "Your name is already set to that."
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
	case profileErrNameRequired:
		return "Please enter a name."
	case profileErrNameTooLong:
		return "The name must be at most 100 characters."
	case profileErrNameInvalid:
		return "The name contains characters that are not allowed."
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
	if err := r.ParseForm(); err != nil || !h.csrf().Verify(r) {
		h.redirect(w, r, "error", profileErrAntiforgery)
		return
	}
	n, err := h.revokeOtherSessions(r, sess)
	if err != nil {
		h.Logger.Error("profile: revoke other sessions failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	h.audit(r, sess.UserID, domain.AuditSessionRevoked, "User", sess.UserID, `{"scope":"others","count":`+strconv.Itoa(n)+`}`)
	h.redirect(w, r, "status", profileStatusOthersOut)
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

func (h *ProfileHandler) changePassword(w http.ResponseWriter, r *http.Request, sess *domain.Session) {
	if err := r.ParseForm(); err != nil || !h.csrf().Verify(r) {
		h.redirect(w, r, "error", profileErrAntiforgery)
		return
	}
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("new_password_confirm")
	if current == "" || next == "" || confirm == "" {
		h.redirect(w, r, "error", profileErrPasswordMissing)
		return
	}

	ctx := r.Context()
	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.Error("profile: user lookup failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}

	// Verify the current password before judging the new one, so the form
	// cannot be used to probe policy details without knowing it. The
	// lockout check comes first so a locked caller cannot keep guessing.
	key := h.passwordLockoutKey(r, user.ID)
	if h.Tracker != nil {
		locked, err := h.Tracker.IsLockedOut(ctx, key)
		if err != nil {
			h.Logger.Error("profile: tracker lookup failed", "err", err)
		}
		if locked {
			h.redirect(w, r, "error", profileErrLocked)
			return
		}
	}
	info, err := h.Users.ValidateCredentials(ctx, user.Username, current)
	if err != nil {
		h.Logger.Error("profile: credential check failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	if info == nil {
		if h.Tracker != nil {
			_ = h.Tracker.RecordFailure(ctx, key)
		}
		h.redirect(w, r, "error", profileErrCurrentWrong)
		return
	}
	if h.Tracker != nil {
		if err := h.Tracker.Reset(ctx, key); err != nil {
			h.Logger.Warn("profile: tracker reset failed", "err", err)
		}
	}

	switch {
	case next != confirm:
		h.redirect(w, r, "error", profileErrPasswordMismatch)
		return
	case ValidatePassword(next) != nil:
		h.redirect(w, r, "error", profileErrPasswordWeak)
		return
	case next == current:
		h.redirect(w, r, "error", profileErrPasswordSame)
		return
	}

	if err := h.Users.SetPassword(ctx, user.ID, next); err != nil {
		h.Logger.Error("profile: set password failed", "err", err)
		h.redirect(w, r, "error", profileErrServer)
		return
	}
	// The password is already changed; a failure below must not report the
	// change as failed. Log it and carry on as far as possible.
	user.SecurityStamp = uuid.NewString()
	user.UpdatedAt = h.Clock.Now().UTC()
	if err := h.Users.UpdateUser(ctx, user); err != nil {
		h.Logger.Error("profile: security stamp rotation failed", "err", err)
	}
	n, err := h.revokeOtherSessions(r, sess)
	if err != nil {
		h.Logger.Error("profile: revoking other sessions after password change failed", "err", err)
	}
	h.audit(r, user.ID, domain.AuditPasswordChanged, "User", user.ID, `{"sessions_revoked":`+strconv.Itoa(n)+`}`)
	h.redirect(w, r, "status", profileStatusPasswordSet)
}
