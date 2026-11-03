package oidc

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

// homePath is the signed-in landing page in the SPA.
const homePath = "/"

// recentLoginsLimit caps the sign-in history shown on the home page.
const recentLoginsLimit = 10

// HomeHandler serves GET /api/account/home: who you are and your most
// recent sign-ins. Mount it behind SessionResolver.RequireSession.
type HomeHandler struct {
	Users     store.UserStore
	AuditLogs store.AuditLogStore
	Logger    *slog.Logger
}

type homeLoginView struct {
	When    time.Time `json:"when"`
	IP      string    `json:"ip"`
	Device  string    `json:"device"`
	Current bool      `json:"current"`
}

type homeView struct {
	Username     string          `json:"username"`
	Email        string          `json:"email"`
	Logins       []homeLoginView `json:"logins"`
	FailedLogins []homeLoginView `json:"failed_logins"`
}

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, ErrLoginRequired, "login required")
		return
	}
	ctx := r.Context()

	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.Error("home: user lookup failed", "err", err)
		writeJSONError(w, http.StatusInternalServerError, ErrServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, homeView{
		Username:     user.Username,
		Email:        user.Email,
		Logins:       h.history(r, sess.UserID, domain.AuditLoginSucceeded, true),
		FailedLogins: h.history(r, sess.UserID, domain.AuditLoginFailed, false),
	})
}

// history loads the user's recent entries for one audit action. markFirst
// flags the newest entry as the current sign-in.
func (h *HomeHandler) history(r *http.Request, userID, action string, markFirst bool) []homeLoginView {
	out := []homeLoginView{}
	if h.AuditLogs == nil {
		return out
	}
	logs, err := h.AuditLogs.ListByActor(r.Context(), userID, action, recentLoginsLimit)
	if err != nil {
		h.Logger.Warn("home: history lookup failed", "action", action, "err", err)
		return out
	}
	for i, l := range logs {
		out = append(out, homeLoginView{
			When:    l.Timestamp.UTC(),
			IP:      l.IPAddress,
			Device:  describeUserAgent(l.UserAgent),
			Current: markFirst && i == 0,
		})
	}
	return out
}

// describeUserAgent reduces a User-Agent string to "Browser on OS". It is
// a display hint only, never used for any security decision.
func describeUserAgent(ua string) string {
	if ua == "" {
		return "unknown device"
	}
	browser := "browser"
	// Order matters: Edge and Chrome UAs also contain "Safari".
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"},
		{"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"},
	} {
		if strings.Contains(ua, b.token) {
			browser = b.name
			break
		}
	}
	os := ""
	// Order matters: iPhone UAs contain "Mac OS X", Android ones "Linux".
	for _, o := range []struct{ token, name string }{
		{"iPhone", "iOS"}, {"iPad", "iOS"}, {"Android", "Android"},
		{"Windows", "Windows"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"},
	} {
		if strings.Contains(ua, o.token) {
			os = o.name
			break
		}
	}
	if os == "" {
		return browser
	}
	return browser + " on " + os
}
