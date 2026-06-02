package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]domain.Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[uuid.UUID]domain.Session)}
}

func (s *SessionStore) Find(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s: %w", id, store.ErrNotFound)
	}
	return &sess, nil
}

func (s *SessionStore) GetPaged(_ context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Session], error) {
	req = req.Normalized()
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Session, 0, len(s.sessions))
	for _, s := range s.sessions {
		items = append(items, s)
	}
	total := len(items)
	start := (req.Page - 1) * req.PageSize
	if start > total {
		start = total
	}
	end := start + req.PageSize
	if end > total {
		end = total
	}
	return domain.PagedResult[domain.Session]{
		Items:      items[start:end],
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *SessionStore) Store(_ context.Context, sess *domain.Session) error {
	if sess == nil {
		return fmt.Errorf("session: %w", errNil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = *sess
	return nil
}

func (s *SessionStore) Revoke(_ context.Context, id uuid.UUID, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return fmt.Errorf("session %s: %w", id, store.ErrNotFound)
	}
	if sess.RevokedAt != nil {
		return nil
	}
	t := revokedAt
	sess.RevokedAt = &t
	s.sessions[id] = sess
	return nil
}
