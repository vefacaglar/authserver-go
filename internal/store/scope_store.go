package store

import (
	"context"

	"go-authserver/internal/domain"
)

type ScopeStore interface {
	FindByName(ctx context.Context, name string) (*domain.Scope, error)
	GetAll(ctx context.Context) ([]domain.Scope, error)
	Store(ctx context.Context, s *domain.Scope) error
	Delete(ctx context.Context, name string) error
}
