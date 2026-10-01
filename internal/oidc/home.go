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
	LogoutPath string
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
	Username   string
	Name       string
	Email      string
	LogoutPath string
	Logins     []homeLogin
	Error      string
	ErrorLabel string
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
	data := homeData{Username: user.Username, Email: user.Email, LogoutPath: h.Cfg.LogoutPath}

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

	if h.AuditLogs != nil {
		logs, err := h.AuditLogs.ListByActor(ctx, sess.UserID, domain.AuditLoginSucceeded, recentLoginsLimit)
		if err != nil {
			h.Logger.Warn("home: login history lookup failed", "err", err)
		}
		for i, l := range logs {
			data.Logins = append(data.Logins, homeLogin{
				When:    l.Timestamp.UTC().Format("2006-01-02 15:04 UTC"),
				IP:      l.IPAddress,
				Device:  describeUserAgent(l.UserAgent),
				Current: i == 0,
			})
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.Template.Execute(w, data); err != nil {
		h.Logger.Error("home render failed", "err", err)
	}
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
