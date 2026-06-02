package store

import (
	"context"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

type RefreshTokenStore interface {
	Store(ctx context.Context, t *domain.RefreshToken) error
	FindByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
	GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.RefreshToken], error)

	// MarkConsumed is an atomic CAS — see AuthorizationCodeStore.MarkConsumed.
	MarkConsumed(ctx context.Context, id uuid.UUID, consumedAt time.Time) (bool, error)

	Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error
	RevokeBySessionID(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error
}
