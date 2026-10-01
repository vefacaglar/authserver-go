package domain

import (
	"time"

	"github.com/google/uuid"
)

// Audit actions written by the browser-facing account flows.
const (
	AuditLoginSucceeded  = "login_succeeded"
	AuditLoginFailed     = "login_failed"
	AuditProfileUpdated  = "profile_updated"
	AuditSessionRevoked  = "session_revoked"
	AuditPasswordChanged = "password_changed"
	AuditResetRequested  = "password_reset_requested"
	AuditResetCompleted  = "password_reset_completed"
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
