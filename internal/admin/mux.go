package admin

import (
	"net/http"
	"strings"
)

// CombineMux returns a single http.Handler that dispatches /api/...
// to apiMux and the index (everything else) to ui. The dispatch
// is path-based and intentionally simple — the admin API uses
// Go 1.22+ ServeMux patterns and the SPA only needs the bare
// index.
func CombineMux(apiMux *http.ServeMux, ui *UI) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(path, "api/") {
			apiMux.ServeHTTP(w, r)
			return
		}
		ui.ServeIndex(w, r)
	})
}
