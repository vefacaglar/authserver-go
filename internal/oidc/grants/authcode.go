// Package grants contains the per-grant_type implementations invoked by
// the /connect/token dispatcher.
package grants

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

// AuthCodeConfig bundles the lifetimes used by the authorization_code grant.
type AuthCodeConfig struct {
	AccessTokenLifetime          time.Duration
	IDTokenLifetime              time.Duration
	RefreshTokenLifetime         time.Duration
	RefreshTokenAbsoluteLifetime time.Duration
}

// AuthCodeGrant handles grant_type=authorization_code. It implements the
// security-critical CAS-before-issuance rule: MarkConsumed runs *before* any
// tokens are minted, so a single auth code can never yield tokens twice.
type AuthCodeGrant struct {
	AuthCodes     store.AuthorizationCodeStore
	RefreshTokens store.RefreshTokenStore
	Clients       store.ClientStore
	Users         store.UserStore
	Issuer        *token.Issuer
	Clock         clock.Clock
	Cfg           AuthCodeConfig
}

// TokenResponse is the JSON the token endpoint returns. Fields are pointers
// so the omitempty rule can keep the wire shape correct for grants that
// don't issue refresh or ID tokens.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse mirrors errors.go's errorBody but lives here so grants can
// return the exact response shape without depending on oidc internals.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Handle is the entry point invoked by the token dispatcher. form is the
// already-parsed application/x-www-form-urlencoded body.
func (g *AuthCodeGrant) Handle(ctx context.Context, w http.ResponseWriter, form url.Values) {
	clientID := form.Get("client_id")
	codeRaw := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	codeVerifier := form.Get("code_verifier")

	if clientID == "" || codeRaw == "" || redirectURI == "" {
		g.writeError(w, http.StatusBadRequest, "invalid_request", "client_id, code, redirect_uri are required")
		return
	}

	client, err := g.Clients.FindByClientID(ctx, clientID)
	if err != nil {
		g.writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}

	code, err := g.AuthCodes.FindByHash(ctx, token.HashToken(codeRaw))
	if err != nil {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if g.Clock.Now().After(code.ExpiresAt) {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if code.ClientID != client.ClientID {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if code.RedirectURI != redirectURI {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if code.CodeChallenge != nil {
		if err := token.VerifyS256(*code.CodeChallengeMethod, codeVerifier, *code.CodeChallenge); err != nil {
			g.writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// SECURITY: MarkConsumed must run BEFORE any token is issued. The CAS
	// guarantees that a single auth code is honoured at most once even
	// under concurrent attempts.
	won, err := g.AuthCodes.MarkConsumed(ctx, code.ID, g.Clock.Now().UTC())
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "could not record code consumption")
		return
	}
	if !won {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
		return
	}

	info, err := g.Users.FindByID(ctx, code.UserID)
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}

	scopes := strings.Fields(code.Scope)
	scope := code.Scope

	authTime := code.CreatedAt
	access, err := g.Issuer.IssueAccessToken(ctx, token.AccessTokenClaims{
		Subject:   info.UserID,
		ClientID:  client.ClientID,
		Scope:     scope,
		AuthTime:  &authTime,
		ExpiresIn: g.Cfg.AccessTokenLifetime,
	})
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "access token issuance failed")
		return
	}
	atHash := token.HashAccessToken(access)

	extraClaims := buildIDClaims(info, scopes)
	idNonce := ""
	if code.Nonce != nil {
		idNonce = *code.Nonce
	}
	id, err := g.Issuer.IssueIDToken(ctx, token.IDTokenClaims{
		Subject:   info.UserID,
		ClientID:  client.ClientID,
		Scope:     scope,
		Nonce:     idNonce,
		AuthTime:  authTime,
		AtHash:    atHash,
		Claims:    extraClaims,
		ExpiresIn: g.Cfg.IDTokenLifetime,
	})
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "id token issuance failed")
		return
	}

	resp := TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(g.Cfg.AccessTokenLifetime.Seconds()),
		IDToken:     id,
		Scope:       scope,
	}

	// Refresh token issuance. Spec: requires client.AllowRefreshTokens AND
	// "offline_access" in the granted scope. M3 issues one; M4 adds the
	// rotation + reuse-detection chain logic on top of the same path.
	if client.AllowRefreshTokens && slices.Contains(scopes, "offline_access") {
		raw, hash, err := token.NewOpaqueToken()
		if err != nil {
			g.writeError(w, http.StatusInternalServerError, "server_error", "refresh token mint failed")
			return
		}
		now := g.Clock.Now().UTC()
		sid := code.SessionID
		rt := &domain.RefreshToken{
			ID:                newID(),
			TokenHash:         hash,
			ClientID:          client.ClientID,
			UserID:            info.UserID,
			SessionID:         sid,
			Scope:             scope,
			ExpiresAt:         now.Add(g.Cfg.RefreshTokenLifetime),
			AbsoluteExpiresAt: now.Add(g.Cfg.RefreshTokenAbsoluteLifetime),
			CreatedAt:         now,
		}
		if err := g.RefreshTokens.Store(ctx, rt); err != nil {
			g.writeError(w, http.StatusInternalServerError, "server_error", "refresh token store failed")
			return
		}
		resp.RefreshToken = raw
	}

	writeJSONResponse(w, http.StatusOK, resp)
}

func (g *AuthCodeGrant) writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: code, ErrorDescription: desc})
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func buildIDClaims(info *domain.UserInfo, scopes []string) map[string]any {
	out := map[string]any{}
	for _, s := range scopes {
		switch s {
		case "profile":
			if v, ok := info.Claims["name"]; ok {
				out["name"] = v
			}
			if v, ok := info.Claims["preferred_username"]; ok {
				out["preferred_username"] = v
			}
		case "email":
			if v, ok := info.Claims["email"]; ok {
				out["email"] = v
			}
			if v, ok := info.Claims["email_verified"]; ok {
				out["email_verified"] = v
			}
		}
	}
	return out
}

// newID returns a new refresh-token id. Lives in grants to keep the
// per-grant file self-contained for code review.
func newID() (id [16]byte) {
	return newRandom()
}

// Compile-time guard: errors usage keeps the dependency on the standard
// library visible if a future refactor drops it.
var _ = errors.New
