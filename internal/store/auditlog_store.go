package store

import (
	"context"

	"go-authserver/internal/domain"
)

type AuditLogStore interface {
	Store(ctx context.Context, l *domain.AuditLog) error
	GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.AuditLog], error)
}
