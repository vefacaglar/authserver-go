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

type AuthorizationCodeStore struct {
	mu     sync.RWMutex
	codes  map[uuid.UUID]domain.AuthorizationCode
	byHash map[string]uuid.UUID
	locks  *casLocks[uuid.UUID]
}

func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{
		codes:  make(map[uuid.UUID]domain.AuthorizationCode),
		byHash: make(map[string]uuid.UUID),
		locks:  newCASLocks[uuid.UUID](),
	}
}

func (s *AuthorizationCodeStore) Store(_ context.Context, code *domain.AuthorizationCode) error {
	if code == nil {
		return fmt.Errorf("authcode: %w", errNil)
	}
	if code.CodeHash == "" {
		return fmt.Errorf("authcode: %w", errEmptyHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.ID] = *code
	s.byHash[code.CodeHash] = code.ID
	return nil
}

func (s *AuthorizationCodeStore) FindByHash(_ context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	s.mu.RLock()
	id, ok := s.byHash[codeHash]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("authcode: %w", store.ErrNotFound)
	}
	code := s.codes[id]
	s.mu.RUnlock()
	return &code, nil
}

// MarkConsumed atomically transitions ConsumedAt from nil to consumedAt.
// Only the single caller that observes the nil→set transition wins (true).
// Per-entity mutex serialises concurrent attempts on the same id, while the
// outer RWMutex still guards the map reads.
func (s *AuthorizationCodeStore) MarkConsumed(_ context.Context, id uuid.UUID, consumedAt time.Time) (bool, error) {
	lock := s.locks.get(id)
	lock.Lock()
	defer lock.Unlock()

	s.mu.Lock()
	code, ok := s.codes[id]
	if !ok {
		s.mu.Unlock()
		return false, fmt.Errorf("authcode %s: %w", id, store.ErrNotFound)
	}
	if code.ConsumedAt != nil {
		s.mu.Unlock()
		return false, nil
	}
	t := consumedAt
	code.ConsumedAt = &t
	s.codes[id] = code
	s.mu.Unlock()
	return true, nil
}
