package domain

import (
	"time"

	"github.com/google/uuid"
)

// Audit actions written by the browser-facing account flows.
const (
	AuditLoginSucceeded = "login_succeeded"
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
