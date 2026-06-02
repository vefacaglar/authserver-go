// Package domain contains the plain data models used across the auth server.
//
// These structs are intentionally free of HTTP, persistence, and JOSE concerns.
// All times are stored in UTC. Code outside this package must obtain the
// current time through a clock.Clock implementation instead of calling
// time.Now directly so that tests can advance time deterministically.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken is the persisted record of a long-lived refresh token.
//
// Expiry semantics depend on the issuing Client.RefreshTokenExpiration
// policy. The two expiry fields are NOT redundant:
//
//   - Sliding mode (Client.RefreshTokenExpiration == TokenExpirationSliding):
//     ExpiresAt is a sliding deadline that is reset on every successful
//     rotation; the token is valid until the later of (now + sliding
//     lifetime) and AbsoluteExpiresAt. AbsoluteExpiresAt is the hard
//     ceiling that bounds the chain regardless of rotation activity.
//
//   - Absolute mode (Client.RefreshTokenExpiration == TokenExpirationAbsolute):
//     ExpiresAt is an absolute deadline that is recomputed on every
//     rotation as (now + client.RefreshTokenAbsoluteLifetime()). The
//     ceiling still comes from AbsoluteExpiresAt and is set on the
//     initial issuance, not recomputed on rotation.
//
// In both modes AbsoluteExpiresAt is set once at initial issuance and
// never moves; it caps how far the chain can be extended.
type RefreshToken struct {
	ID                uuid.UUID
	TokenHash         string
	ClientID          string
	UserID            string
	SessionID         *uuid.UUID
	ParentTokenID     *uuid.UUID
	Scope             string
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	ConsumedAt        *time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
}
