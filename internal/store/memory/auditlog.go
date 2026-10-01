package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"go-authserver/internal/domain"
)

type AuditLogStore struct {
	mu    sync.RWMutex
	items []domain.AuditLog
}

func NewAuditLogStore() *AuditLogStore {
	return &AuditLogStore{}
}

func (s *AuditLogStore) Store(_ context.Context, l *domain.AuditLog) error {
	if l == nil {
		return fmt.Errorf("audit log: %w", errNil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, *l)
	return nil
}

func (s *AuditLogStore) GetPaged(_ context.Context, req domain.PagedRequest) (domain.PagedResult[domain.AuditLog], error) {
	req = req.Normalized()
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.items)
	start := (req.Page - 1) * req.PageSize
	if start > total {
		start = total
	}
	end := start + req.PageSize
	if end > total {
		end = total
	}
	items := make([]domain.AuditLog, end-start)
	copy(items, s.items[start:end])
	return domain.PagedResult[domain.AuditLog]{
		Items:      items,
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *AuditLogStore) ListByActor(_ context.Context, actorUserID, action string, limit int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 10
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.AuditLog
	for _, l := range s.items {
		if l.ActorUserID == actorUserID && l.Action == action {
			out = append(out, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
