package oidc

import (
	"net/http"

	"go-authserver/internal/oidc/grants"
)

// TokenHandler dispatches POST /connect/token by grant_type. Only the
// grant handlers actually implemented are routed; everything else returns
// unsupported_grant_type.
type TokenHandler struct {
	AuthCode *grants.AuthCodeGrant
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, ErrInvalidRequest, "could not parse form body")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "authorization_code":
		if h.AuthCode == nil {
			writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "authorization_code grant not enabled")
			return
		}
		h.AuthCode.Handle(r.Context(), w, r.PostForm)
	default:
		writeJSONError(w, http.StatusBadRequest, ErrUnsupportedGrantType, "unsupported grant_type")
	}
}
