package memory

import (
	"context"
	"fmt"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

type SigningKeyStore struct {
	mu    sync.RWMutex
	keys  map[string]domain.SigningKey
	order []string
}

func NewSigningKeyStore() *SigningKeyStore {
	return &SigningKeyStore{keys: make(map[string]domain.SigningKey)}
}

func (s *SigningKeyStore) GetActive(_ context.Context) (*domain.SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, kid := range s.order {
		k := s.keys[kid]
		if k.IsActive {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("signing key: %w", store.ErrNotFound)
}

func (s *SigningKeyStore) GetAll(_ context.Context) ([]domain.SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.SigningKey, 0, len(s.order))
	for _, kid := range s.order {
		out = append(out, s.keys[kid])
	}
	return out, nil
}

func (s *SigningKeyStore) Store(_ context.Context, k *domain.SigningKey) error {
	if k == nil {
		return fmt.Errorf("signing key: %w", errNil)
	}
	if k.KeyID == "" {
		return fmt.Errorf("signing key: %w", errEmptyID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.KeyID]; !ok {
		s.order = append(s.order, k.KeyID)
	}
	s.keys[k.KeyID] = *k
	return nil
}
