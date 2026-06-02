package domain

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID          uuid.UUID
	Action      string
	ActorUserID string
	TargetType  string
	TargetID    string
	Timestamp   time.Time
	IPAddress   string
	UserAgent   string
	Metadata    string
}
