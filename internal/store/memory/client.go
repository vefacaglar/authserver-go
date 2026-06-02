package memory

import (
	"context"
	"fmt"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

type ClientStore struct {
	mu      sync.RWMutex
	clients map[string]domain.Client
}

func NewClientStore() *ClientStore {
	return &ClientStore{clients: make(map[string]domain.Client)}
}

func (s *ClientStore) FindByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client %q: %w", clientID, store.ErrNotFound)
	}
	clone := c
	return &clone, nil
}

func (s *ClientStore) GetPaged(_ context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Client], error) {
	req = req.Normalized()
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Client, 0, len(s.clients))
	for _, c := range s.clients {
		items = append(items, c)
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
	return domain.PagedResult[domain.Client]{
		Items:      items[start:end],
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *ClientStore) Store(_ context.Context, c *domain.Client) error {
	if c == nil {
		return fmt.Errorf("client: %w", errNil)
	}
	if c.ClientID == "" {
		return fmt.Errorf("client: %w", errEmptyID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = *c
	return nil
}

func (s *ClientStore) Delete(_ context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return fmt.Errorf("client %q: %w", clientID, store.ErrNotFound)
	}
	delete(s.clients, clientID)
	return nil
}
