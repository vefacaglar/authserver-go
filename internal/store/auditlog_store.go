package store

import (
	"context"

	"go-authserver/internal/domain"
)

type AuditLogStore interface {
	Store(ctx context.Context, l *domain.AuditLog) error
	GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.AuditLog], error)

	// ListByActor returns the actor's entries for one action, newest
	// first, capped at limit (limit <= 0 means 10).
	ListByActor(ctx context.Context, actorUserID, action string, limit int) ([]domain.AuditLog, error)
}
