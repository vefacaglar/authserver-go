package domain

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken is a single-use, time-limited credential that lets
// its holder set a new password. Only the SHA-256 hash of the raw token
// is stored; the raw value exists only in the email sent to the user.
type PasswordResetToken struct {
	ID         uuid.UUID
	UserID     string
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}
