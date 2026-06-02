package store

import (
	"context"

	"go-authserver/internal/domain"
)

type SigningKeyStore interface {
	GetActive(ctx context.Context) (*domain.SigningKey, error)
	GetAll(ctx context.Context) ([]domain.SigningKey, error)
	Store(ctx context.Context, k *domain.SigningKey) error
}
