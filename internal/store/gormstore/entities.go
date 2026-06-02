// Package gormstore provides GORM-backed implementations of the store
// interfaces declared in internal/store.
//
// Each store type in this package is a thin adapter that translates
// between the domain model (kept free of GORM tags) and the GORM
// entity types declared in entities.go. The split lets the domain
// package stay portable and free of persistence concerns, mirroring
// the memory/ adapter's role.
//
// Two drivers are supported, selected at Open() time:
//   - sqlite (default; used for dev and tests)
//   - postgres (production)
//
// The atomic MarkConsumed CAS is implemented as a single conditional
// UPDATE with a RowsAffected check — never read-then-write. The same
// rule applies to the memory adapter.
package gormstore

import (
	"errors"
	"fmt"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// All entities live in this file as a single package-private surface.
// Keeping them together makes the AutoMigrate call (and any future
// schema review) a one-stop read.

// --- Client ---

// clientEntity is the GORM projection of domain.Client. Slice/map
// fields are persisted as JSON for portability between SQLite and
// Postgres.
type clientEntity struct {
	ClientID                            string `gorm:"primaryKey;size:128"`
	DisplayName                         string
	RedirectURIs                        string `gorm:"type:text"` // JSON-encoded []string
	PostLogoutRedirectURIs              string `gorm:"type:text"`
	AllowedScopes                       string `gorm:"type:text"`
	RequirePKCE                         bool
	AllowRefreshTokens                  bool
	AllowClientCredentials              bool
	TokenEndpointAuthMethod             string `gorm:"size:32"`
	JWKSJSON                            string `gorm:"type:text"`
	AccessTokenLifetimeSeconds          int
	RefreshTokenLifetimeSeconds         int
	RefreshTokenAbsoluteLifetimeSeconds int
	Properties                          string `gorm:"type:text"` // JSON map[string]string
}

func (clientEntity) TableName() string { return "oauth_clients" }

func toClientEntity(c *domain.Client) (*clientEntity, error) {
	uris, err := encodeStringSlice(c.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("client %q: redirect_uris: %w", c.ClientID, err)
	}
	logout, err := encodeStringSlice(c.PostLogoutRedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("client %q: post_logout_redirect_uris: %w", c.ClientID, err)
	}
	scopes, err := encodeStringSlice(c.AllowedScopes)
	if err != nil {
		return nil, fmt.Errorf("client %q: allowed_scopes: %w", c.ClientID, err)
	}
	props, err := encodeStringMap(c.Properties)
	if err != nil {
		return nil, fmt.Errorf("client %q: properties: %w", c.ClientID, err)
	}
	auth := string(c.TokenEndpointAuthMethod)
	if auth == "" {
		auth = string(domain.TokenEndpointAuthMethodNone)
	}
	return &clientEntity{
		ClientID:                            c.ClientID,
		DisplayName:                         c.DisplayName,
		RedirectURIs:                        uris,
		PostLogoutRedirectURIs:              logout,
		AllowedScopes:                       scopes,
		RequirePKCE:                         c.RequirePKCE,
		AllowRefreshTokens:                  c.AllowRefreshTokens,
		AllowClientCredentials:              c.AllowClientCredentials,
		TokenEndpointAuthMethod:             auth,
		JWKSJSON:                            c.JWKSJSON,
		AccessTokenLifetimeSeconds:          c.AccessTokenLifetimeSeconds,
		RefreshTokenLifetimeSeconds:         c.RefreshTokenLifetimeSeconds,
		RefreshTokenAbsoluteLifetimeSeconds: c.RefreshTokenAbsoluteLifetimeSeconds,
		Properties:                          props,
	}, nil
}

func (e *clientEntity) toDomain() (*domain.Client, error) {
	uris, err := decodeStringSlice(e.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("client %q: redirect_uris decode: %w", e.ClientID, err)
	}
	logout, err := decodeStringSlice(e.PostLogoutRedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("client %q: post_logout_redirect_uris decode: %w", e.ClientID, err)
	}
	scopes, err := decodeStringSlice(e.AllowedScopes)
	if err != nil {
		return nil, fmt.Errorf("client %q: allowed_scopes decode: %w", e.ClientID, err)
	}
	props, err := decodeStringMap(e.Properties)
	if err != nil {
		return nil, fmt.Errorf("client %q: properties decode: %w", e.ClientID, err)
	}
	return &domain.Client{
		ClientID:                            e.ClientID,
		DisplayName:                         e.DisplayName,
		RedirectURIs:                        uris,
		PostLogoutRedirectURIs:              logout,
		AllowedScopes:                       scopes,
		RequirePKCE:                         e.RequirePKCE,
		AllowRefreshTokens:                  e.AllowRefreshTokens,
		AllowClientCredentials:              e.AllowClientCredentials,
		TokenEndpointAuthMethod:             domain.TokenEndpointAuthMethod(e.TokenEndpointAuthMethod),
		JWKSJSON:                            e.JWKSJSON,
		AccessTokenLifetimeSeconds:          e.AccessTokenLifetimeSeconds,
		RefreshTokenLifetimeSeconds:         e.RefreshTokenLifetimeSeconds,
		RefreshTokenAbsoluteLifetimeSeconds: e.RefreshTokenAbsoluteLifetimeSeconds,
		Properties:                          props,
	}, nil
}

// --- AuthorizationCode ---

type authCodeEntity struct {
	ID                  string  `gorm:"primaryKey;size:36"`
	CodeHash            string  `gorm:"uniqueIndex;size:128"`
	ClientID            string  `gorm:"index;size:128"`
	UserID              string  `gorm:"index;size:128"`
	SessionID           *string `gorm:"size:36"`
	RedirectURI         string
	CodeChallenge       *string
	CodeChallengeMethod *string `gorm:"size:16"`
	Scope               string
	Nonce               *string
	ExpiresAt           time.Time `gorm:"index"`
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}

func (authCodeEntity) TableName() string { return "oauth_authorization_codes" }

func toAuthCodeEntity(c *domain.AuthorizationCode) (*authCodeEntity, error) {
	if c.ID == uuid.Nil {
		return nil, errors.New("auth code: zero id")
	}
	return &authCodeEntity{
		ID:                  c.ID.String(),
		CodeHash:            c.CodeHash,
		ClientID:            c.ClientID,
		UserID:              c.UserID,
		SessionID:           uuidPtrString(c.SessionID),
		RedirectURI:         c.RedirectURI,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		Scope:               c.Scope,
		Nonce:               c.Nonce,
		ExpiresAt:           c.ExpiresAt,
		ConsumedAt:          c.ConsumedAt,
		CreatedAt:           c.CreatedAt,
	}, nil
}

func (e *authCodeEntity) toDomain() (*domain.AuthorizationCode, error) {
	id, err := uuid.Parse(e.ID)
	if err != nil {
		return nil, fmt.Errorf("auth code %q: parse id: %w", e.ID, err)
	}
	var sid *uuid.UUID
	if e.SessionID != nil {
		v, err := uuid.Parse(*e.SessionID)
		if err != nil {
			return nil, fmt.Errorf("auth code %q: parse session_id: %w", e.ID, err)
		}
		sid = &v
	}
	return &domain.AuthorizationCode{
		ID:                  id,
		CodeHash:            e.CodeHash,
		ClientID:            e.ClientID,
		UserID:              e.UserID,
		SessionID:           sid,
		RedirectURI:         e.RedirectURI,
		CodeChallenge:       e.CodeChallenge,
		CodeChallengeMethod: e.CodeChallengeMethod,
		Scope:               e.Scope,
		Nonce:               e.Nonce,
		ExpiresAt:           e.ExpiresAt,
		ConsumedAt:          e.ConsumedAt,
		CreatedAt:           e.CreatedAt,
	}, nil
}

// --- RefreshToken ---

type refreshTokenEntity struct {
	ID                string  `gorm:"primaryKey;size:36"`
	TokenHash         string  `gorm:"uniqueIndex;size:128"`
	ClientID          string  `gorm:"index;size:128"`
	UserID            string  `gorm:"index;size:128"`
	SessionID         *string `gorm:"size:36;index"`
	ParentTokenID     *string `gorm:"size:36"`
	Scope             string
	ExpiresAt         time.Time `gorm:"index"`
	AbsoluteExpiresAt time.Time
	ConsumedAt        *time.Time
	RevokedAt         *time.Time `gorm:"index"`
	CreatedAt         time.Time
}

func (refreshTokenEntity) TableName() string { return "oauth_refresh_tokens" }

func toRefreshTokenEntity(t *domain.RefreshToken) (*refreshTokenEntity, error) {
	if t.ID == uuid.Nil {
		return nil, errors.New("refresh token: zero id")
	}
	return &refreshTokenEntity{
		ID:                t.ID.String(),
		TokenHash:         t.TokenHash,
		ClientID:          t.ClientID,
		UserID:            t.UserID,
		SessionID:         uuidPtrString(t.SessionID),
		ParentTokenID:     uuidPtrString(t.ParentTokenID),
		Scope:             t.Scope,
		ExpiresAt:         t.ExpiresAt,
		AbsoluteExpiresAt: t.AbsoluteExpiresAt,
		ConsumedAt:        t.ConsumedAt,
		RevokedAt:         t.RevokedAt,
		CreatedAt:         t.CreatedAt,
	}, nil
}

func (e *refreshTokenEntity) toDomain() (*domain.RefreshToken, error) {
	id, err := uuid.Parse(e.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh token %q: parse id: %w", e.ID, err)
	}
	sid, err := parseUUIDPtr(e.SessionID, "session_id")
	if err != nil {
		return nil, err
	}
	parent, err := parseUUIDPtr(e.ParentTokenID, "parent_token_id")
	if err != nil {
		return nil, err
	}
	return &domain.RefreshToken{
		ID:                id,
		TokenHash:         e.TokenHash,
		ClientID:          e.ClientID,
		UserID:            e.UserID,
		SessionID:         sid,
		ParentTokenID:     parent,
		Scope:             e.Scope,
		ExpiresAt:         e.ExpiresAt,
		AbsoluteExpiresAt: e.AbsoluteExpiresAt,
		ConsumedAt:        e.ConsumedAt,
		RevokedAt:         e.RevokedAt,
		CreatedAt:         e.CreatedAt,
	}, nil
}

// --- Session ---

type sessionEntity struct {
	ID         string `gorm:"primaryKey;size:36"`
	UserID     string `gorm:"index;size:128"`
	CreatedAt  time.Time
	ExpiresAt  time.Time  `gorm:"index"`
	RevokedAt  *time.Time `gorm:"index"`
	Properties string     `gorm:"type:text"` // JSON map[string]string
}

func (sessionEntity) TableName() string { return "oauth_sessions" }

func toSessionEntity(s *domain.Session) (*sessionEntity, error) {
	props, err := encodeStringMap(s.Properties)
	if err != nil {
		return nil, fmt.Errorf("session %s: properties: %w", s.ID, err)
	}
	return &sessionEntity{
		ID:         s.ID.String(),
		UserID:     s.UserID,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
		Properties: props,
	}, nil
}

func (e *sessionEntity) toDomain() (*domain.Session, error) {
	id, err := uuid.Parse(e.ID)
	if err != nil {
		return nil, fmt.Errorf("session %q: parse id: %w", e.ID, err)
	}
	props, err := decodeStringMap(e.Properties)
	if err != nil {
		return nil, fmt.Errorf("session %q: properties: %w", e.ID, err)
	}
	return &domain.Session{
		ID:         id,
		UserID:     e.UserID,
		CreatedAt:  e.CreatedAt,
		ExpiresAt:  e.ExpiresAt,
		RevokedAt:  e.RevokedAt,
		Properties: props,
	}, nil
}

// --- SigningKey ---

type signingKeyEntity struct {
	KeyID         string `gorm:"primaryKey;size:128"`
	Algorithm     string `gorm:"size:16"`
	PrivateKeyPEM string `gorm:"type:text"`
	PublicKeyPEM  string `gorm:"type:text"`
	CreatedAt     time.Time
	RetiredAt     *time.Time
	IsActive      bool `gorm:"index"`
}

func (signingKeyEntity) TableName() string { return "oauth_signing_keys" }

func toSigningKeyEntity(k *domain.SigningKey) *signingKeyEntity {
	alg := k.Algorithm
	if alg == "" {
		alg = domain.DefaultSigningAlgorithm
	}
	return &signingKeyEntity{
		KeyID:         k.KeyID,
		Algorithm:     alg,
		PrivateKeyPEM: k.PrivateKeyPEM,
		PublicKeyPEM:  k.PublicKeyPEM,
		CreatedAt:     k.CreatedAt,
		RetiredAt:     k.RetiredAt,
		IsActive:      k.IsActive,
	}
}

func (e *signingKeyEntity) toDomain() *domain.SigningKey {
	return &domain.SigningKey{
		KeyID:         e.KeyID,
		Algorithm:     e.Algorithm,
		PrivateKeyPEM: e.PrivateKeyPEM,
		PublicKeyPEM:  e.PublicKeyPEM,
		CreatedAt:     e.CreatedAt,
		RetiredAt:     e.RetiredAt,
		IsActive:      e.IsActive,
	}
}

// --- Scope ---

type scopeEntity struct {
	Name        string `gorm:"primaryKey;size:64"`
	DisplayName string
	Description string
	Required    bool
	Emphasize   bool
	Properties  string `gorm:"type:text"` // JSON map[string]string
}

func (scopeEntity) TableName() string { return "oauth_scopes" }

func toScopeEntity(s *domain.Scope) (*scopeEntity, error) {
	props, err := encodeStringMap(s.Properties)
	if err != nil {
		return nil, fmt.Errorf("scope %q: properties: %w", s.Name, err)
	}
	return &scopeEntity{
		Name:        s.Name,
		DisplayName: s.DisplayName,
		Description: s.Description,
		Required:    s.Required,
		Emphasize:   s.Emphasize,
		Properties:  props,
	}, nil
}

func (e *scopeEntity) toDomain() (*domain.Scope, error) {
	props, err := decodeStringMap(e.Properties)
	if err != nil {
		return nil, fmt.Errorf("scope %q: properties: %w", e.Name, err)
	}
	return &domain.Scope{
		Name:        e.Name,
		DisplayName: e.DisplayName,
		Description: e.Description,
		Required:    e.Required,
		Emphasize:   e.Emphasize,
		Properties:  props,
	}, nil
}

// --- User (host directory) ---

// userEntity is the GORM backing of the in-process user directory. The
// user store is host-owned; this entity is here so the same SQLite
// file can carry the demo user. Real deployments point UserStore at
// LDAP/SSO/etc., not this table.
type userEntity struct {
	UserID       string `gorm:"primaryKey;size:128"`
	Username     string `gorm:"uniqueIndex;size:128"`
	PasswordHash string `gorm:"type:text"`
	Claims       string `gorm:"type:text"` // JSON map[string]any
}

func (userEntity) TableName() string { return "oauth_users" }

func toUserEntity(u *domain.UserInfo, password string) (*userEntity, error) {
	claims, err := encodeAnyMap(u.Claims)
	if err != nil {
		return nil, fmt.Errorf("user %q: claims: %w", u.UserID, err)
	}
	return &userEntity{
		UserID:       u.UserID,
		Username:     usernameFromClaims(u.Claims, u.UserID),
		PasswordHash: password,
		Claims:       claims,
	}, nil
}

func (e *userEntity) toDomain() (*domain.UserInfo, error) {
	claims, err := decodeAnyMap(e.Claims)
	if err != nil {
		return nil, fmt.Errorf("user %q: claims: %w", e.UserID, err)
	}
	return &domain.UserInfo{UserID: e.UserID, Claims: claims}, nil
}

// --- AuditLog ---

type auditLogEntity struct {
	ID          string    `gorm:"primaryKey;size:36"`
	Action      string    `gorm:"index;size:64"`
	ActorUserID string    `gorm:"index;size:128"`
	TargetType  string    `gorm:"size:64"`
	TargetID    string    `gorm:"size:128"`
	Timestamp   time.Time `gorm:"index"`
	IPAddress   string    `gorm:"size:64"`
	UserAgent   string    `gorm:"size:512"`
	Metadata    string    `gorm:"type:text"`
}

func (auditLogEntity) TableName() string { return "oauth_audit_logs" }

func toAuditLogEntity(l *domain.AuditLog) (*auditLogEntity, error) {
	if l.ID == uuid.Nil {
		return nil, errors.New("audit log: zero id")
	}
	return &auditLogEntity{
		ID:          l.ID.String(),
		Action:      l.Action,
		ActorUserID: l.ActorUserID,
		TargetType:  l.TargetType,
		TargetID:    l.TargetID,
		Timestamp:   l.Timestamp,
		IPAddress:   l.IPAddress,
		UserAgent:   l.UserAgent,
		Metadata:    l.Metadata,
	}, nil
}

func (e *auditLogEntity) toDomain() (*domain.AuditLog, error) {
	id, err := uuid.Parse(e.ID)
	if err != nil {
		return nil, fmt.Errorf("audit log %q: parse id: %w", e.ID, err)
	}
	return &domain.AuditLog{
		ID:          id,
		Action:      e.Action,
		ActorUserID: e.ActorUserID,
		TargetType:  e.TargetType,
		TargetID:    e.TargetID,
		Timestamp:   e.Timestamp,
		IPAddress:   e.IPAddress,
		UserAgent:   e.UserAgent,
		Metadata:    e.Metadata,
	}, nil
}

// --- helpers ---

// allEntities is the slice AutoMigrate iterates over. Adding a new
// entity to the package is a one-liner: append it here.
func allEntities() []any {
	return []any{
		&clientEntity{},
		&authCodeEntity{},
		&refreshTokenEntity{},
		&sessionEntity{},
		&signingKeyEntity{},
		&scopeEntity{},
		&userEntity{},
		&auditLogEntity{},
	}
}

// Migrate runs AutoMigrate for every entity in this package. It is
// idempotent: existing tables are not modified beyond additive
// column/index changes.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(allEntities()...)
}

// uuidPtrString converts a *uuid.UUID to a *string in 36-char form.
// Returns nil when the pointer is nil.
func uuidPtrString(p *uuid.UUID) *string {
	if p == nil {
		return nil
	}
	s := p.String()
	return &s
}

// parseUUIDPtr parses a *string carrying a 36-char uuid into a
// *uuid.UUID. Returns nil when the input is nil.
func parseUUIDPtr(p *string, field string) (*uuid.UUID, error) {
	if p == nil {
		return nil, nil
	}
	id, err := uuid.Parse(*p)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", field, err)
	}
	return &id, nil
}
