package store

import (
	"context"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

type AuthorizationCodeStore interface {
	Store(ctx context.Context, code *domain.AuthorizationCode) error
	FindByHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)

	// MarkConsumed is an atomic compare-and-set that transitions ConsumedAt
	// from nil to consumedAt. It returns true only for the single caller that
	// wins the race; every other caller gets (false, nil). Implementations
	// must guarantee this is one conditional write, never read-then-write.
	MarkConsumed(ctx context.Context, id uuid.UUID, consumedAt time.Time) (bool, error)
}
