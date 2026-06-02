package store

import (
	"context"

	"go-authserver/internal/domain"
)

type ClientStore interface {
	FindByClientID(ctx context.Context, clientID string) (*domain.Client, error)
	GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Client], error)
	Store(ctx context.Context, c *domain.Client) error
	Delete(ctx context.Context, clientID string) error
}
