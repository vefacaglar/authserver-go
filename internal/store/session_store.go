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
}
