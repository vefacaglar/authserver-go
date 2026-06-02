package domain

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID         uuid.UUID
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	Properties map[string]string
}
