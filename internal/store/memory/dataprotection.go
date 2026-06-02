package memory

import (
	"context"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"sync"
)

// DataProtectionKeyStore is the in-memory cookie data-protection key ring,
// used by tests. Mirrors the signing-key store: GetActive returns the row
// flagged active, GetAll returns all keys, Store upserts by KeyID.
type DataProtectionKeyStore struct {
	mu    sync.RWMutex
	keys  map[string]domain.DataProtectionKey
	order []string
}

func NewDataProtectionKeyStore() *DataProtectionKeyStore {
	return &DataProtectionKeyStore{keys: make(map[string]domain.DataProtectionKey)}
}

func (s *DataProtectionKeyStore) GetActive(_ context.Context) (*domain.DataProtectionKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, kid := range s.order {
		k := s.keys[kid]
		if k.IsActive {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("data protection key: %w", store.ErrNotFound)
}

func (s *DataProtectionKeyStore) GetAll(_ context.Context) ([]domain.DataProtectionKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.DataProtectionKey, 0, len(s.order))
	// Newest first, to match the GORM store's ordering.
	for i := len(s.order) - 1; i >= 0; i-- {
		out = append(out, s.keys[s.order[i]])
	}
	return out, nil
}

func (s *DataProtectionKeyStore) Store(_ context.Context, k *domain.DataProtectionKey) error {
	if k == nil {
		return fmt.Errorf("data protection key: %w", errNil)
	}
	if k.KeyID == "" {
		return fmt.Errorf("data protection key: %w", errEmptyID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.KeyID]; !ok {
		s.order = append(s.order, k.KeyID)
	}
	s.keys[k.KeyID] = *k
	return nil
}
