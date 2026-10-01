package store

import (
	"context"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

type PasswordResetStore interface {
	Create(ctx context.Context, t *domain.PasswordResetToken) error
	FindByHash(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error)

	// Consume is an atomic CAS — see AuthorizationCodeStore.MarkConsumed.
	// It returns true only for the single caller that moves the token
	// from unconsumed to consumed while it is still unexpired at now.
	Consume(ctx context.Context, id uuid.UUID, now time.Time) (bool, error)

	// InvalidateForUser consumes every outstanding token of the user, so a
	// completed reset kills any other reset link still in flight.
	InvalidateForUser(ctx context.Context, userID string, now time.Time) error

	// DeleteExpired removes tokens that expired before the cutoff.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
