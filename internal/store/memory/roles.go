package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

type RoleStore struct {
	mu     sync.RWMutex
	roles  map[string]*domain.Role
	claims map[string][]domain.RoleClaim
}

func NewRoleStore() *RoleStore {
	return &RoleStore{
		roles:  make(map[string]*domain.Role),
		claims: make(map[string][]domain.RoleClaim),
	}
}

func (s *RoleStore) CreateRole(_ context.Context, role *domain.Role) error {
	if role.ID == "" {
		return fmt.Errorf("role: empty id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[role.ID]; exists {
		return fmt.Errorf("role %q: %w", role.ID, store.ErrDuplicate)
	}
	r := *role
	s.roles[role.ID] = &r
	return nil
}

func (s *RoleStore) DeleteRole(_ context.Context, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	delete(s.roles, roleID)
	delete(s.claims, roleID)
	return nil
}

func (s *RoleStore) FindRoleByID(_ context.Context, roleID string) (*domain.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, exists := s.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	copy := *r
	return &copy, nil
}

func (s *RoleStore) FindRoleByName(_ context.Context, name string) (*domain.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.roles {
		if strings.EqualFold(r.Name, name) {
			copy := *r
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("role %q: %w", name, store.ErrNotFound)
}

func (s *RoleStore) GetAllRoles(_ context.Context) ([]domain.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.Role, 0, len(s.roles))
	for _, r := range s.roles {
		result = append(result, *r)
	}
	return result, nil
}

func (s *RoleStore) GetRoleClaims(_ context.Context, roleID string) ([]domain.RoleClaim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.roles[roleID]; !exists {
		return nil, fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	result := make([]domain.RoleClaim, len(s.claims[roleID]))
	copy(result, s.claims[roleID])
	return result, nil
}

func (s *RoleStore) AddRoleClaims(_ context.Context, roleID string, claims []domain.RoleClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	s.claims[roleID] = append(s.claims[roleID], claims...)
	return nil
}

func (s *RoleStore) RemoveRoleClaims(_ context.Context, roleID string, claims []domain.RoleClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	existing := s.claims[roleID]
	for _, toRemove := range claims {
		for i := len(existing) - 1; i >= 0; i-- {
			if existing[i].Type == toRemove.Type && existing[i].Value == toRemove.Value {
				existing = append(existing[:i], existing[i+1:]...)
				break
			}
		}
	}
	s.claims[roleID] = existing
	return nil
}

func (s *RoleStore) ReplaceRoleClaims(_ context.Context, roleID string, claims []domain.RoleClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	s.claims[roleID] = claims
	return nil
}
