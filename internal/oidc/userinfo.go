package oidc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

// UserInfoHandler serves GET and POST /connect/userinfo. The bearer
// token can come from the Authorization header (GET/POST) or the form
// body access_token (POST). The token is verified against the JWKS and
// the resulting claims are filtered through the scope the access token
// was granted. Invalid tokens produce a 401 with
// WWW-Authenticate: Bearer.
type UserInfoHandler struct {
	Issuer *token.Issuer
	Users  store.UserStore
	Logger *slog.Logger
}

// NewUserInfoHandler is the constructor for the /connect/userinfo
// handler.
func NewUserInfoHandler(issuer *token.Issuer, users store.UserStore, logger *slog.Logger) http.Handler {
	return &UserInfoHandler{Issuer: issuer, Users: users, Logger: logger}
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, ok := h.extractBearer(r)
	if !ok {
		h.invalidToken(w, "missing or malformed Authorization header")
		return
	}
	tok, err := h.Issuer.VerifyToken(r.Context(), raw)
	if err != nil {
		h.invalidToken(w, "token verification failed")
		return
	}

	scopeVal, _ := tok.Get("scope")
	scopeStr, _ := scopeVal.(string)
	scopes := strings.Fields(scopeStr)
	if !slices.Contains(scopes, "openid") {
		h.forbidden(w, "access token does not grant openid scope")
		return
	}

	sub := tok.Subject()
	info, err := h.Users.FindByID(r.Context(), sub)
	if err != nil {
		h.invalidToken(w, "user not found")
		return
	}

	claims := buildUserInfoClaims(info, scopes)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	SetNoStore(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(claims)
}

func (h *UserInfoHandler) extractBearer(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		const p = "Bearer "
		if strings.HasPrefix(h, p) {
			tok := strings.TrimSpace(h[len(p):])
			if tok != "" {
				return tok, true
			}
		}
		return "", false
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if v := r.PostForm.Get("access_token"); v != "" {
			return v, true
		}
	}
	return "", false
}

func (h *UserInfoHandler) invalidToken(w http.ResponseWriter, desc string) {
	if h.Logger != nil {
		h.Logger.Debug("userinfo invalid token", "reason", desc)
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeJSONError(w, http.StatusUnauthorized, ErrInvalidGrant, desc)
}

func (h *UserInfoHandler) forbidden(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	writeJSONError(w, http.StatusForbidden, ErrAccessDenied, desc)
}

// buildUserInfoClaims filters the user directory's claims by the scope
// the access token was granted. The mapping mirrors the OIDC Core
// "scope-filtered claims" rules:
//
//   - openid  → sub (always)
//   - profile → name, family_name, given_name, middle_name, nickname,
//     preferred_username, picture, updated_at
//   - email   → email, email_verified
//   - phone   → phone_number, phone_number_verified
//   - address → address
//
// Claims the directory does not have are simply not emitted.
func buildUserInfoClaims(info *domain.UserInfo, scopes []string) map[string]any {
	out := map[string]any{
		"sub": info.UserID,
	}
	for _, s := range scopes {
		switch s {
		case "profile":
			for _, k := range []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "picture", "updated_at"} {
				if v, ok := info.Claims[k]; ok {
					out[k] = v
				}
			}
		case "email":
			for _, k := range []string{"email", "email_verified"} {
				if v, ok := info.Claims[k]; ok {
					out[k] = v
				}
			}
		case "phone":
			for _, k := range []string{"phone_number", "phone_number_verified"} {
				if v, ok := info.Claims[k]; ok {
					out[k] = v
				}
			}
		case "address":
			if v, ok := info.Claims["address"]; ok {
				out["address"] = v
			}
		}
	}
	return out
}
