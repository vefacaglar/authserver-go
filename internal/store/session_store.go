package store

import (
	"context"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

type SessionStore interface {
	Find(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Session], error)
	Store(ctx context.Context, s *domain.Session) error
	Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error

	// ListByUserID returns the user's sessions that are neither revoked
	// nor expired at now, newest first.
	ListByUserID(ctx context.Context, userID string, now time.Time) ([]domain.Session, error)

	// RevokeByUserIDExcept revokes every still-active session of the user
	// except keep (pass uuid.Nil to keep none) and returns the ids it
	// revoked so the caller can cascade to refresh tokens.
	RevokeByUserIDExcept(ctx context.Context, userID string, keep uuid.UUID, revokedAt time.Time) ([]uuid.UUID, error)
}
