package admin

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
)

// UI serves the single-page admin shell. The page is modularly designed:
// the assets directory contains separate HTML, core JS, and components JS files,
// which are embedded at compile time using standard go:embed.
type UI struct {
	Template *template.Template
	Logger   *slog.Logger
}

//go:embed assets
var assetsFS embed.FS

// IndexPage returns the embedded admin shell HTML. Exported so the
// composition root in cmd/authserver and the integration tests can
// share the same template.
func IndexPage() string {
	bytes, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		return ""
	}
	return string(bytes)
}

// ServeIndex renders the SPA shell with the CSRF token injected when requesting the index,
// and serves all other modular JS/CSS files statically from the embedded filesystem.
func (u *UI) ServeIndex(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")

	// If the path is empty, "/", or "index.html", render the dynamic index page
	if path == "" || path == "index.html" {
		if u.Template == nil {
			http.Error(w, "admin template not configured", http.StatusInternalServerError)
			return
		}
		// gorilla/csrf injects the token into the request context. We use csrf.Token(r)
		// to get the raw token string and inject it into the index template.
		csrfToken := csrf.Token(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := u.Template.Execute(w, map[string]any{"CSRFToken": csrfToken}); err != nil {
			if u.Logger != nil {
				u.Logger.Error("admin index render", "err", err)
			}
		}
		return
	}

	// Explicit MIME types override for maximum cross-platform compatibility
	if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}

	// Serve the static asset from embedded filesystem directly
	http.FileServer(http.FS(assetsFS)).ServeHTTP(w, r)
}

