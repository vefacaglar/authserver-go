package domain

import (
	"time"

	"github.com/google/uuid"
)

type AuthorizationCode struct {
	ID                  uuid.UUID
	CodeHash            string
	ClientID            string
	UserID              string
	SessionID           *uuid.UUID
	RedirectURI         string
	CodeChallenge       *string
	CodeChallengeMethod *string
	Scope               string
	Nonce               *string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}
