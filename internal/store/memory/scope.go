package memory

import (
	"context"
	"fmt"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

type ScopeStore struct {
	mu     sync.RWMutex
	scopes map[string]domain.Scope
	order  []string
}

func NewScopeStore() *ScopeStore {
	return &ScopeStore{scopes: make(map[string]domain.Scope)}
}

func (s *ScopeStore) FindByName(_ context.Context, name string) (*domain.Scope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scopes[name]
	if !ok {
		return nil, fmt.Errorf("scope %q: %w", name, store.ErrNotFound)
	}
	return &sc, nil
}

func (s *ScopeStore) GetAll(_ context.Context) ([]domain.Scope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Scope, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.scopes[name])
	}
	return out, nil
}

func (s *ScopeStore) Store(_ context.Context, sc *domain.Scope) error {
	if sc == nil {
		return fmt.Errorf("scope: %w", errNil)
	}
	if sc.Name == "" {
		return fmt.Errorf("scope: %w", errEmptyID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scopes[sc.Name]; !ok {
		s.order = append(s.order, sc.Name)
	}
	s.scopes[sc.Name] = *sc
	return nil
}

func (s *ScopeStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scopes[name]; !ok {
		return fmt.Errorf("scope %q: %w", name, store.ErrNotFound)
	}
	delete(s.scopes, name)
	for i, n := range s.order {
		if n == name {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}
