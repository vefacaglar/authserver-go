package oidc

import (
	"log/slog"
	"net/http"

	"go-authserver/internal/token"
)

// jwksHandler serves GET /.well-known/jwks.json. The body is the public JWK
// set for every signing key (active + retired). Private material is never
// included; this is enforced inside token.Issuer.JWKSForEndpoint.
type jwksHandler struct {
	Issuer *token.Issuer
}

// NewJWKSHandler returns a ready-to-mount JWKS handler.
func NewJWKSHandler(issuer *token.Issuer) http.Handler {
	return &jwksHandler{Issuer: issuer}
}

func (h *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := h.Issuer.JWKSForEndpoint(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "could not build JWKS", "err", err)
		writeJSONError(w, http.StatusInternalServerError, ErrServerError, "could not build JWKS")
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}
