// Package grants contains the per-grant_type implementations invoked by
// the /connect/token dispatcher.
package grants

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// RefreshTokenReuseAudit is the action string written to the audit log
// when a previously consumed refresh token is presented again.
const RefreshTokenReuseAudit = "RefreshTokenReuseDetected"

// RefreshConfig bundles the lifetimes and the reuse-detection policy
// used by the refresh grant.
type RefreshConfig struct {
	AccessTokenLifetime          time.Duration
	IDTokenLifetime              time.Duration
	RefreshTokenLifetime         time.Duration
	RefreshTokenAbsoluteLifetime time.Duration
	DetectReuse                  bool
}

// RefreshGrant handles grant_type=refresh_token. It implements the
// rotation + reuse-detection rules:
//
//   - On first use the presented token is atomically consumed (CAS) and
//     a fresh refresh token is minted with ParentTokenID set, sliding
//     expiry reset, and AbsoluteExpiresAt carried forward.
//   - On a second presentation of an already-consumed token reuse is
//     detected. When DetectReuse is true every token in the session's
//     chain is revoked, a RefreshTokenReuseDetected audit entry is
//     written, and the response is invalid_grant.
type RefreshGrant struct {
	RefreshTokens store.RefreshTokenStore
	Sessions      store.SessionStore
	Clients       store.ClientStore
	Users         store.UserStore
	AuditLogs     store.AuditLogStore
	Issuer        *token.Issuer
	Clock         clock.Clock
	Logger        *slog.Logger
	Cfg           RefreshConfig
}

// Handle is the entry point invoked by the token dispatcher. The
// authenticated client is supplied by the dispatcher; we re-check
// the form's client_id against it as defence-in-depth. form is the
// already-parsed application/x-www-form-urlencoded body.
func (g *RefreshGrant) Handle(ctx context.Context, w http.ResponseWriter, client *domain.Client, form url.Values) {
	raw := form.Get("refresh_token")
	clientID := form.Get("client_id")
	scopeParam := form.Get("scope") // optional down-scope request

	if raw == "" || clientID == "" {
		g.writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}
	if client == nil {
		g.writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")
		return
	}
	if client.ClientID != clientID {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch with authenticated client")
		return
	}

	existing, err := g.RefreshTokens.FindByHash(ctx, token.HashToken(raw))
	if err != nil {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	if existing.ClientID != client.ClientID {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to a different client")
		return
	}
	if existing.RevokedAt != nil {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token has been revoked")
		return
	}
	now := g.Clock.Now().UTC()
	if now.After(existing.AbsoluteExpiresAt) {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token has expired")
		return
	}
	if existing.ExpiresAt.Before(now) {
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token sliding expiry has elapsed")
		return
	}

	// Atomic CAS. If the call returns false, another caller already
	// consumed this token — i.e. reuse. SPEC: rotation guarantees
	// exactly one fresh token per old token; loss of the CAS means the
	// chain is compromised and must be revoked.
	won, err := g.RefreshTokens.MarkConsumed(ctx, existing.ID, now)
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "could not record refresh token consumption")
		return
	}
	if !won {
		if g.Cfg.DetectReuse {
			g.handleReuse(ctx, w, existing, now)
			return
		}
		g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	}

	info, err := g.Users.FindByID(ctx, existing.UserID)
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}

	// Optional down-scoping: the client may request a subset of the
	// original scope. Empty form value means "keep what was granted".
	granted := strings.Fields(existing.Scope)
	scope := existing.Scope
	if scopeParam != "" {
		requested := strings.Fields(scopeParam)
		if !subset(requested, granted) {
			g.writeError(w, http.StatusBadRequest, "invalid_scope", "requested scope is broader than the granted scope")
			return
		}
		scope = strings.Join(requested, " ")
		granted = requested
	}

	authTime := existing.CreatedAt
	access, err := g.Issuer.IssueAccessToken(ctx, token.AccessTokenClaims{
		Subject:   existing.UserID,
		ClientID:  client.ClientID,
		Scope:     scope,
		AuthTime:  &authTime,
		ExpiresIn: client.AccessTokenLifetime(),
	})
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "server_error", "access token issuance failed")
		return
	}
	atHash := token.HashAccessToken(access)

	// ID token on refresh? RFC 6749 doesn't require it. OIDC Core allows
	// omitting it as long as the original auth_time is preserved on the
	// access token. We omit unless openid is in scope.
	var idToken string
	if slices.Contains(granted, "openid") {
		extra := buildIDClaims(info, granted)
		id, err := g.Issuer.IssueIDToken(ctx, token.IDTokenClaims{
			Subject:   existing.UserID,
			ClientID:  client.ClientID,
			Scope:     scope,
			AuthTime:  authTime,
			AtHash:    atHash,
			Claims:    extra,
			ExpiresIn: g.Cfg.IDTokenLifetime,
		})
		if err != nil {
			g.writeError(w, http.StatusInternalServerError, "server_error", "id token issuance failed")
			return
		}
		idToken = id
	}

	// Rotate the refresh token. SPEC: only issue a new one if the
	// original grant included offline_access.
	var newRefresh string
	if client.AllowRefreshTokens && slices.Contains(granted, "offline_access") {
		newRaw, newHash, err := token.NewOpaqueToken()
		if err != nil {
			g.writeError(w, http.StatusInternalServerError, "server_error", "refresh token mint failed")
			return
		}
		parent := existing.ID
		
		var expiresAt time.Time
		if client.RefreshTokenExpiration == domain.TokenExpirationAbsolute {
			expiresAt = existing.ExpiresAt // Carry forward existing expiry for absolute
		} else {
			expiresAt = now.Add(client.RefreshTokenLifetime())
			if expiresAt.After(existing.AbsoluteExpiresAt) {
				expiresAt = existing.AbsoluteExpiresAt
			}
		}

		rt := &domain.RefreshToken{
			ID:                newID(),
			TokenHash:         newHash,
			ClientID:          client.ClientID,
			UserID:            existing.UserID,
			SessionID:         existing.SessionID,
			ParentTokenID:     &parent,
			Scope:             scope,
			ExpiresAt:         expiresAt,
			AbsoluteExpiresAt: existing.AbsoluteExpiresAt, // rotation never extends the hard ceiling
			CreatedAt:         now,
		}
		if err := g.RefreshTokens.Store(ctx, rt); err != nil {
			g.writeError(w, http.StatusInternalServerError, "server_error", "refresh token store failed")
			return
		}
		newRefresh = newRaw
	}

	resp := TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(client.AccessTokenLifetime().Seconds()),
		RefreshToken: newRefresh,
		IDToken:      idToken,
		Scope:        scope,
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleReuse is invoked when a previously-consumed refresh token is
// presented again. We revoke every token in the session chain and write
// a RefreshTokenReuseDetected audit entry. Always returns invalid_grant.
func (g *RefreshGrant) handleReuse(ctx context.Context, w http.ResponseWriter, old *domain.RefreshToken, now time.Time) {
	if old.SessionID != nil {
		if err := g.RefreshTokens.RevokeBySessionID(ctx, *old.SessionID, now); err != nil {
			if g.Logger != nil {
				g.Logger.Warn("refresh chain revoke by session failed", "err", err)
			}
		}
	} else {
		// Fallback for older tokens that pre-date the SessionID field:
		// revoke just the consumed token. The CAS still prevents further
		// rotation, and any chain ancestor remains effectively dead
		// because its successor (this token) can never be used to mint
		// a new one.
		_ = g.RefreshTokens.Revoke(ctx, old.ID, now)
	}

	if g.AuditLogs != nil {
		md := ""
		if old.SessionID != nil {
			md = `{"session_id":"` + old.SessionID.String() + `"}`
		}
		_ = g.AuditLogs.Store(ctx, &domain.AuditLog{
			ID:          uuid.New(),
			Action:      RefreshTokenReuseAudit,
			ActorUserID: old.UserID,
			TargetType:  "RefreshToken",
			TargetID:    old.ID.String(),
			Timestamp:   now,
			Metadata:    md,
		})
	}

	if g.Logger != nil {
		g.Logger.Warn("refresh token reuse detected", "client_id", old.ClientID, "user_id", old.UserID)
	}

	g.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
}

func (g *RefreshGrant) writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: code, ErrorDescription: desc})
}

// subset returns true when every element of a is also in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
