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

type RefreshTokenStore struct {
	mu     sync.RWMutex
	tokens map[uuid.UUID]domain.RefreshToken
	byHash map[string]uuid.UUID
	locks  *casLocks[uuid.UUID]
}

func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{
		tokens: make(map[uuid.UUID]domain.RefreshToken),
		byHash: make(map[string]uuid.UUID),
		locks:  newCASLocks[uuid.UUID](),
	}
}

func (s *RefreshTokenStore) Store(_ context.Context, t *domain.RefreshToken) error {
	if t == nil {
		return fmt.Errorf("refresh token: %w", errNil)
	}
	if t.TokenHash == "" {
		return fmt.Errorf("refresh token: %w", errEmptyHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.ID] = *t
	s.byHash[t.TokenHash] = t.ID
	return nil
}

func (s *RefreshTokenStore) FindByHash(_ context.Context, tokenHash string) (*domain.RefreshToken, error) {
	s.mu.RLock()
	id, ok := s.byHash[tokenHash]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("refresh token: %w", store.ErrNotFound)
	}
	t := s.tokens[id]
	s.mu.RUnlock()
	return &t, nil
}

func (s *RefreshTokenStore) GetPaged(_ context.Context, req domain.PagedRequest) (domain.PagedResult[domain.RefreshToken], error) {
	req = req.Normalized()
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.RefreshToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		items = append(items, t)
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
	return domain.PagedResult[domain.RefreshToken]{
		Items:      items[start:end],
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *RefreshTokenStore) MarkConsumed(_ context.Context, id uuid.UUID, consumedAt time.Time) (bool, error) {
	lock := s.locks.get(id)
	lock.Lock()
	defer lock.Unlock()

	s.mu.Lock()
	tok, ok := s.tokens[id]
	if !ok {
		s.mu.Unlock()
		return false, fmt.Errorf("refresh token %s: %w", id, store.ErrNotFound)
	}
	if tok.ConsumedAt != nil {
		s.mu.Unlock()
		return false, nil
	}
	t := consumedAt
	tok.ConsumedAt = &t
	s.tokens[id] = tok
	s.mu.Unlock()
	return true, nil
}

func (s *RefreshTokenStore) Revoke(_ context.Context, id uuid.UUID, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[id]
	if !ok {
		return fmt.Errorf("refresh token %s: %w", id, store.ErrNotFound)
	}
	if tok.RevokedAt != nil {
		return nil
	}
	t := revokedAt
	tok.RevokedAt = &t
	s.tokens[id] = tok
	return nil
}

func (s *RefreshTokenStore) RevokeBySessionID(_ context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := revokedAt
	for id, tok := range s.tokens {
		if tok.SessionID != nil && *tok.SessionID == sessionID && tok.RevokedAt == nil {
			tok.RevokedAt = &t
			s.tokens[id] = tok
		}
	}
	return nil
}
