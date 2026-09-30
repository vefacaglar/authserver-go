package admin

import (
	"context"
	"net/http"

	"github.com/gorilla/csrf"
)

// csrfFromContext reads the CSRF token that gorilla/csrf's
// Protect() middleware injects into the request context. The token
// is the same value the SPA must echo back in the X-CSRF-Token
// header.
func csrfFromContext(ctx context.Context) (string, error) {
	if t, ok := ctx.Value(csrf.TemplateField).(string); ok {
		return t, nil
	}
	return "", nil
}

// CSRFMiddleware returns the gorilla/csrf Protect middleware
// configured for the admin route group. The key must be 32 bytes
// (per gorilla/csrf's requirement) and shared across instances so a
// browser that loaded a CSRF cookie on one instance can post to
// another.
//
// secure follows the same RequireHTTPS flag as the rest of the
// server. When secure=true the CSRF cookie is marked Secure, which
// keeps it out of plaintext requests and is required for the
// `__Host-` prefix to be accepted. When secure=false the cookie
// travels over HTTP as well, which is the right default for local
// dev and tests behind httptest.
func CSRFMiddleware(key []byte, secure bool) func(http.Handler) http.Handler {
	if len(key) < 32 {
		// Pad up; gorilla/csrf will panic if the key is shorter.
		// This is a safety net for tests; production should always
		// pass a 32-byte key from config.
		padded := make([]byte, 32)
		copy(padded, key)
		key = padded
	}
	return csrf.Protect(key,
		csrf.Secure(secure),
		csrf.Path("/admin/"),
		csrf.TrustedOrigins([]string{
			"localhost:5175",
			"127.0.0.1:5175",
			"localhost:8090",
			"127.0.0.1:8090",
		}),
	)
}
