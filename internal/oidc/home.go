package oidc

import (
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

// homePath is the signed-in landing page.
const homePath = "/"

// recentLoginsLimit caps the sign-in history shown on the home page.
const recentLoginsLimit = 10

// HomeConfig bundles the paths the home page links to.
type HomeConfig struct {
	ProfilePath string
	LogoutPath  string
}

// HomeHandler renders the signed-in landing page: who you are and your
// most recent sign-ins. Mount it behind SessionResolver.RequireSession.
type HomeHandler struct {
	Cfg       HomeConfig
	Users     store.UserStore
	AuditLogs store.AuditLogStore
	Logger    *slog.Logger
	Template  *template.Template
}

type homeLogin struct {
	When    string
	IP      string
	Device  string
	Current bool
}

type homeData struct {
	Nav          appNav
	ProfilePath  string
	Username     string
	Name         string
	Email        string
	Logins       []homeLogin
	FailedLogins []homeLogin
	Status       string
	StatusLabel  string
	Error        string
	ErrorLabel   string
}

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	user, err := h.Users.FindUserByID(ctx, sess.UserID)
	if err != nil {
		h.Logger.Error("home: user lookup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := homeData{
		Nav:         appNav{HomePath: homePath, ProfilePath: h.Cfg.ProfilePath, LogoutPath: h.Cfg.LogoutPath, Active: "home"},
		ProfilePath: h.Cfg.ProfilePath,
		Username:    user.Username,
		Email:       user.Email,
	}

	claims, err := h.Users.GetUserClaims(ctx, sess.UserID)
	if err != nil {
		h.Logger.Warn("home: claims lookup failed", "err", err)
	}
	for _, c := range claims {
		if c.Type == "name" {
			data.Name = c.Value
			break
		}
	}

	data.Logins = h.history(r, sess.UserID, domain.AuditLoginSucceeded, true)
	data.FailedLogins = h.history(r, sess.UserID, domain.AuditLoginFailed, false)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.Template.Execute(w, data); err != nil {
		h.Logger.Error("home render failed", "err", err)
	}
}

// history loads the user's recent entries for one audit action. markFirst
// flags the newest entry as the current sign-in.
func (h *HomeHandler) history(r *http.Request, userID, action string, markFirst bool) []homeLogin {
	if h.AuditLogs == nil {
		return nil
	}
	logs, err := h.AuditLogs.ListByActor(r.Context(), userID, action, recentLoginsLimit)
	if err != nil {
		h.Logger.Warn("home: history lookup failed", "action", action, "err", err)
		return nil
	}
	out := make([]homeLogin, 0, len(logs))
	for i, l := range logs {
		out = append(out, homeLogin{
			When:    l.Timestamp.UTC().Format("2006-01-02 15:04 UTC"),
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
