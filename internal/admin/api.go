package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// API bundles the dependencies the JSON handlers need.
type API struct {
	Clients       store.ClientStore
	Scopes        store.ScopeStore
	Sessions      store.SessionStore
	RefreshTokens store.RefreshTokenStore
	SigningKeys   store.SigningKeyStore
	AuditLogs     store.AuditLogStore
	Clock         clock.Clock
	Logger        *slog.Logger
}

// Mount wires the admin API onto the supplied mux. The caller is
// expected to have already wrapped the mux with AuthMiddleware and
// the CSRF middleware.
func (a *API) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/clients", a.listClients)
	mux.HandleFunc("POST /api/clients", a.createClient)
	mux.HandleFunc("DELETE /api/clients/{id}", a.deleteClient)
	mux.HandleFunc("GET /api/scopes", a.listScopes)
	mux.HandleFunc("POST /api/scopes", a.createScope)
	mux.HandleFunc("DELETE /api/scopes/{name}", a.deleteScope)
	mux.HandleFunc("GET /api/sessions", a.listSessions)
	mux.HandleFunc("POST /api/sessions/{id}/revoke", a.revokeSession)
	mux.HandleFunc("GET /api/refresh-tokens", a.listRefreshTokens)
	mux.HandleFunc("POST /api/refresh-tokens/{id}/revoke", a.revokeRefreshToken)
	mux.HandleFunc("GET /api/keys", a.listSigningKeys)
	mux.HandleFunc("GET /api/audit", a.listAuditLogs)
}

// --- Clients ---

type clientView struct {
	ClientID                            string            `json:"client_id"`
	DisplayName                         string            `json:"display_name"`
	RedirectURIs                        []string          `json:"redirect_uris"`
	PostLogoutRedirectURIs              []string          `json:"post_logout_redirect_uris"`
	AllowedScopes                       []string          `json:"allowed_scopes"`
	RequirePKCE                         bool              `json:"require_pkce"`
	AllowRefreshTokens                  bool              `json:"allow_refresh_tokens"`
	AllowClientCredentials              bool              `json:"allow_client_credentials"`
	TokenEndpointAuthMethod             string            `json:"token_endpoint_auth_method"`
	HasJWKS                             bool              `json:"has_jwks"`
	AccessTokenLifetimeSeconds          int               `json:"access_token_lifetime_seconds"`
	RefreshTokenLifetimeSeconds         int               `json:"refresh_token_lifetime_seconds"`
	RefreshTokenAbsoluteLifetimeSeconds int               `json:"refresh_token_absolute_lifetime_seconds"`
	Properties                          map[string]string `json:"properties,omitempty"`
}

func toClientView(c *domain.Client) clientView {
	return clientView{
		ClientID:                            c.ClientID,
		DisplayName:                         c.DisplayName,
		RedirectURIs:                        c.RedirectURIs,
		PostLogoutRedirectURIs:              c.PostLogoutRedirectURIs,
		AllowedScopes:                       c.AllowedScopes,
		RequirePKCE:                         c.RequirePKCE,
		AllowRefreshTokens:                  c.AllowRefreshTokens,
		AllowClientCredentials:              c.AllowClientCredentials,
		TokenEndpointAuthMethod:             string(c.TokenEndpointAuthMethod),
		HasJWKS:                             c.JWKSJSON != "",
		AccessTokenLifetimeSeconds:          c.AccessTokenLifetimeSeconds,
		RefreshTokenLifetimeSeconds:         c.RefreshTokenLifetimeSeconds,
		RefreshTokenAbsoluteLifetimeSeconds: c.RefreshTokenAbsoluteLifetimeSeconds,
		Properties:                          c.Properties,
	}
}

func (a *API) listClients(w http.ResponseWriter, r *http.Request) {
	res, err := a.Clients.GetPaged(r.Context(), parsePage(r))
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]clientView, 0, len(res.Items))
	for i := range res.Items {
		items = append(items, toClientView(&res.Items[i]))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": res.TotalCount})
}

func (a *API) createClient(w http.ResponseWriter, r *http.Request) {
	var body clientView
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid json", err)
		return
	}
	if body.ClientID == "" {
		a.writeError(w, http.StatusBadRequest, "client_id is required", nil)
		return
	}
	method := domain.TokenEndpointAuthMethod(body.TokenEndpointAuthMethod)
	if method == "" {
		method = domain.TokenEndpointAuthMethodNone
	}
	if !method.Valid() {
		a.writeError(w, http.StatusBadRequest, "unknown token_endpoint_auth_method", nil)
		return
	}
	c := &domain.Client{
		ClientID:                            body.ClientID,
		DisplayName:                         body.DisplayName,
		RedirectURIs:                        body.RedirectURIs,
		PostLogoutRedirectURIs:              body.PostLogoutRedirectURIs,
		AllowedScopes:                       body.AllowedScopes,
		RequirePKCE:                         body.RequirePKCE,
		AllowRefreshTokens:                  body.AllowRefreshTokens,
		AllowClientCredentials:              body.AllowClientCredentials,
		TokenEndpointAuthMethod:             method,
		AccessTokenLifetimeSeconds:          body.AccessTokenLifetimeSeconds,
		RefreshTokenLifetimeSeconds:         body.RefreshTokenLifetimeSeconds,
		RefreshTokenAbsoluteLifetimeSeconds: body.RefreshTokenAbsoluteLifetimeSeconds,
		Properties:                          body.Properties,
	}
	// Enforce the AllowRefreshTokens → offline_access constraint.
	if c.AllowRefreshTokens && !containsString(c.AllowedScopes, "offline_access") {
		c.AllowedScopes = append(c.AllowedScopes, "offline_access")
	}
	if err := a.Clients.Store(r.Context(), c); err != nil {
		a.writeError(w, http.StatusBadRequest, "store failed", err)
		return
	}
	a.writeJSON(w, http.StatusCreated, toClientView(c))
}

func (a *API) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Clients.Delete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.writeError(w, http.StatusNotFound, "not found", err)
			return
		}
		a.writeError(w, http.StatusInternalServerError, "delete failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Scopes ---

type scopeView struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Required    bool              `json:"required"`
	Emphasize   bool              `json:"emphasize"`
	Properties  map[string]string `json:"properties,omitempty"`
}

func toScopeView(s *domain.Scope) scopeView {
	return scopeView{
		Name:        s.Name,
		DisplayName: s.DisplayName,
		Description: s.Description,
		Required:    s.Required,
		Emphasize:   s.Emphasize,
		Properties:  s.Properties,
	}
}

func (a *API) listScopes(w http.ResponseWriter, r *http.Request) {
	all, err := a.Scopes.GetAll(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]scopeView, 0, len(all))
	for i := range all {
		items = append(items, toScopeView(&all[i]))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": len(items)})
}

func (a *API) createScope(w http.ResponseWriter, r *http.Request) {
	var body scopeView
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid json", err)
		return
	}
	if body.Name == "" {
		a.writeError(w, http.StatusBadRequest, "name is required", nil)
		return
	}
	s := &domain.Scope{
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		Required:    body.Required,
		Emphasize:   body.Emphasize,
		Properties:  body.Properties,
	}
	if err := a.Scopes.Store(r.Context(), s); err != nil {
		a.writeError(w, http.StatusBadRequest, "store failed", err)
		return
	}
	a.writeJSON(w, http.StatusCreated, toScopeView(s))
}

func (a *API) deleteScope(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.Scopes.Delete(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.writeError(w, http.StatusNotFound, "not found", err)
			return
		}
		a.writeError(w, http.StatusInternalServerError, "delete failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Sessions ---

type sessionView struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func toSessionView(s *domain.Session) sessionView {
	return sessionView{
		ID:        s.ID.String(),
		UserID:    s.UserID,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		RevokedAt: s.RevokedAt,
	}
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	res, err := a.Sessions.GetPaged(r.Context(), parsePage(r))
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]sessionView, 0, len(res.Items))
	for i := range res.Items {
		items = append(items, toSessionView(&res.Items[i]))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": res.TotalCount})
}

func (a *API) revokeSession(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid id", err)
		return
	}
	now := a.Clock.Now().UTC()
	if err := a.Sessions.Revoke(r.Context(), id, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.writeError(w, http.StatusNotFound, "not found", err)
			return
		}
		a.writeError(w, http.StatusInternalServerError, "revoke failed", err)
		return
	}
	// Also revoke the refresh-token chain for this session so a
	// stolen cookie + a copied refresh token cannot outlive the
	// session revocation.
	if err := a.RefreshTokens.RevokeBySessionID(r.Context(), id, now); err != nil {
		if a.Logger != nil {
			a.Logger.Warn("session revoke: chain revoke failed", "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Refresh tokens ---

type refreshTokenView struct {
	ID                string     `json:"id"`
	ClientID          string     `json:"client_id"`
	UserID            string     `json:"user_id"`
	SessionID         *string    `json:"session_id,omitempty"`
	ParentTokenID     *string    `json:"parent_token_id,omitempty"`
	Scope             string     `json:"scope"`
	ExpiresAt         time.Time  `json:"expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	ConsumedAt        *time.Time `json:"consumed_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

func toRefreshTokenView(t *domain.RefreshToken) refreshTokenView {
	v := refreshTokenView{
		ID:                t.ID.String(),
		ClientID:          t.ClientID,
		UserID:            t.UserID,
		Scope:             t.Scope,
		ExpiresAt:         t.ExpiresAt,
		AbsoluteExpiresAt: t.AbsoluteExpiresAt,
		ConsumedAt:        t.ConsumedAt,
		RevokedAt:         t.RevokedAt,
		CreatedAt:         t.CreatedAt,
	}
	if t.SessionID != nil {
		s := t.SessionID.String()
		v.SessionID = &s
	}
	if t.ParentTokenID != nil {
		p := t.ParentTokenID.String()
		v.ParentTokenID = &p
	}
	return v
}

func (a *API) listRefreshTokens(w http.ResponseWriter, r *http.Request) {
	res, err := a.RefreshTokens.GetPaged(r.Context(), parsePage(r))
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]refreshTokenView, 0, len(res.Items))
	for i := range res.Items {
		items = append(items, toRefreshTokenView(&res.Items[i]))
	}
	// TokenHash is intentionally NOT serialised.
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": res.TotalCount})
}

func (a *API) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid id", err)
		return
	}
	now := a.Clock.Now().UTC()
	if err := a.RefreshTokens.Revoke(r.Context(), id, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.writeError(w, http.StatusNotFound, "not found", err)
			return
		}
		a.writeError(w, http.StatusInternalServerError, "revoke failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Signing keys ---

// keyView is the public projection of a signing key. The private
// PEM is NEVER serialised — that's the security property the spec
// pins on this endpoint.
type keyView struct {
	KeyID     string     `json:"kid"`
	Algorithm string     `json:"alg"`
	PublicPEM string     `json:"public_pem"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	IsActive  bool       `json:"is_active"`
}

func toKeyView(k *domain.SigningKey) keyView {
	return keyView{
		KeyID:     k.KeyID,
		Algorithm: k.Algorithm,
		PublicPEM: k.PublicKeyPEM,
		CreatedAt: k.CreatedAt,
		RetiredAt: k.RetiredAt,
		IsActive:  k.IsActive,
	}
}

func (a *API) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	all, err := a.SigningKeys.GetAll(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]keyView, 0, len(all))
	for i := range all {
		items = append(items, toKeyView(&all[i]))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": len(items)})
}

// --- Audit ---

type auditView struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	ActorUserID string    `json:"actor_user_id"`
	TargetType  string    `json:"target_type"`
	TargetID    string    `json:"target_id"`
	Timestamp   time.Time `json:"timestamp"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Metadata    string    `json:"metadata,omitempty"`
}

func toAuditView(l *domain.AuditLog) auditView {
	return auditView{
		ID:          l.ID.String(),
		Action:      l.Action,
		ActorUserID: l.ActorUserID,
		TargetType:  l.TargetType,
		TargetID:    l.TargetID,
		Timestamp:   l.Timestamp,
		IPAddress:   l.IPAddress,
		UserAgent:   l.UserAgent,
		Metadata:    l.Metadata,
	}
}

func (a *API) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	res, err := a.AuditLogs.GetPaged(r.Context(), parsePage(r))
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	items := make([]auditView, 0, len(res.Items))
	for i := range res.Items {
		items = append(items, toAuditView(&res.Items[i]))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total_count": res.TotalCount})
}

// --- helpers ---

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) writeError(w http.ResponseWriter, status int, msg string, err error) {
	body := map[string]any{"error": msg}
	if err != nil {
		body["detail"] = err.Error()
	}
	if a.Logger != nil && status >= 500 {
		a.Logger.Error("admin api error", "status", status, "msg", msg, "err", err)
	}
	a.writeJSON(w, status, body)
}

func parsePage(r *http.Request) domain.PagedRequest {
	page := 1
	size := 50
	if p := r.URL.Query().Get("page"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &page); err != nil {
			page = 1
		}
	}
	if s := r.URL.Query().Get("page_size"); s != "" {
		if _, err := fmt.Sscanf(s, "%d", &size); err != nil {
			size = 50
		}
	}
	return domain.PagedRequest{Page: page, PageSize: size}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// keep ctx unused; the helper exists for symmetry with future
// per-request audit writes.
var _ = context.Background
