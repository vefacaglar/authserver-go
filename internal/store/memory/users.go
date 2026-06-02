package memory

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
)

// UserStore is an in-memory, pluggable credential directory intended for
// tests and the M3 bring-up. Passwords are stored as plain strings here only
// because the store is process-local; real deployments use a host directory.
type UserStore struct {
	mu    sync.RWMutex
	users map[string]userRecord
}

type userRecord struct {
	info     domain.UserInfo
	password string
}

func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]userRecord)}
}

func (s *UserStore) Add(u domain.UserInfo, password string) error {
	if u.UserID == "" {
		return errors.New("memory user: empty user id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.UserID] = userRecord{info: u, password: password}
	return nil
}

func (s *UserStore) ValidateCredentials(_ context.Context, username, password string) (*domain.UserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.info.UserID == username || claimString(u.info.Claims["preferred_username"]) == username {
			if subtle.ConstantTimeCompare([]byte(u.password), []byte(password)) == 1 {
				info := u.info
				return &info, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

func (s *UserStore) FindByID(_ context.Context, userID string) (*domain.UserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	info := u.info
	return &info, nil
}

func claimString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
