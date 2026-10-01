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

// PasswordResetStore is the in-memory store.PasswordResetStore. A single
// mutex makes Consume a true compare-and-set.
type PasswordResetStore struct {
	mu     sync.Mutex
	tokens map[uuid.UUID]domain.PasswordResetToken
}

func NewPasswordResetStore() *PasswordResetStore {
	return &PasswordResetStore{tokens: make(map[uuid.UUID]domain.PasswordResetToken)}
}

func (s *PasswordResetStore) Create(_ context.Context, t *domain.PasswordResetToken) error {
	if t == nil {
		return fmt.Errorf("password reset token: %w", errNil)
	}
	if t.TokenHash == "" {
		return fmt.Errorf("password reset token: %w", errEmptyHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tokens {
		if existing.TokenHash == t.TokenHash {
			return fmt.Errorf("password reset token: %w", store.ErrDuplicate)
		}
	}
	s.tokens[t.ID] = *t
	return nil
}

func (s *PasswordResetStore) FindByHash(_ context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.TokenHash == tokenHash {
			c := t
			return &c, nil
		}
	}
	return nil, fmt.Errorf("password reset token: %w", store.ErrNotFound)
}

func (s *PasswordResetStore) Consume(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok || t.ConsumedAt != nil || !now.Before(t.ExpiresAt) {
		return false, nil
	}
	c := now
	t.ConsumedAt = &c
	s.tokens[id] = t
	return true, nil
}

func (s *PasswordResetStore) InvalidateForUser(_ context.Context, userID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.tokens {
		if t.UserID == userID && t.ConsumedAt == nil {
			c := now
			t.ConsumedAt = &c
			s.tokens[id] = t
		}
	}
	return nil
}

func (s *PasswordResetStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.tokens {
		if t.ExpiresAt.Before(before) {
			delete(s.tokens, id)
			n++
		}
	}
	return n, nil
}
