package domain

import (
	"time"

	"github.com/google/uuid"
)

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
