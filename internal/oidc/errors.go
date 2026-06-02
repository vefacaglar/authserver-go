// Package oidc contains the HTTP handlers that expose the OAuth2 / OIDC
// endpoints. Each endpoint file owns one route (or a small set of closely
// related routes) and depends on shared helpers in errors.go plus the
// server-level stores and issuer.
package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// OAuth 2.0 / OIDC error codes that the server emits on the wire.
const (
	ErrInvalidRequest         = "invalid_request"
	ErrInvalidClient          = "invalid_client"
	ErrInvalidGrant           = "invalid_grant"
	ErrUnauthorizedClient     = "unauthorized_client"
	ErrUnsupportedGrantType   = "unsupported_grant_type"
	ErrInvalidScope           = "invalid_scope"
	ErrAccessDenied           = "access_denied"
	ErrServerError            = "server_error"
	ErrTemporarilyUnavailable = "temporarily_unavailable"
	ErrLoginRequired          = "login_required"
	ErrInteractionRequired    = "interaction_required"
	ErrConsentRequired        = "consent_required"
)

type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeJSONError writes a JSON OAuth/OIDC error response and sets the
// no-store cache directives required on token-endpoint responses.
func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	SetNoStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, ErrorDescription: description})
}

// WriteInvalidClient is the special-case helper for client-authentication
// failures. The spec demands a 401 with WWW-Authenticate: Basic.
func WriteInvalidClient(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
	writeJSONError(w, http.StatusUnauthorized, ErrInvalidClient, description)
}

// redirectError builds the redirect URL for a front-channel error after
// redirect_uri has already been validated. The caller is responsible for
// having checked that redirectURI is in the client's allow-list.
func redirectError(redirectURI, code, description, state string) string {
	q := url.Values{}
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	q2 := u.Query()
	for k, vs := range q {
		for _, v := range vs {
			q2.Add(k, v)
		}
	}
	u.RawQuery = q2.Encode()
	return u.String()
}

// SetNoStore applies the no-store / no-cache directives required on
// token-endpoint and similar sensitive responses.
func SetNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
