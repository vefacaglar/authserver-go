package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"golang.org/x/crypto/bcrypt"
)

type UserStore struct {
	mu     sync.RWMutex
	users  map[string]*domain.User
	hashes map[string]string
	claims map[string][]domain.UserClaim
	roles  map[string][]string
	logins map[string][]domain.UserLogin
	tokens map[string]domain.UserToken
}

func NewUserStore() *UserStore {
	return &UserStore{
		users:  make(map[string]*domain.User),
		hashes: make(map[string]string),
		claims: make(map[string][]domain.UserClaim),
		roles:  make(map[string][]string),
		logins: make(map[string][]domain.UserLogin),
		tokens: make(map[string]domain.UserToken),
	}
}

func (s *UserStore) CreateUser(_ context.Context, user *domain.User, password string) error {
	if user.ID == "" {
		return errors.New("user: empty id")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user %q: %w", user.ID, store.ErrDuplicate)
	}
	u := *user
	u.PasswordHash = ""
	s.users[user.ID] = &u
	s.hashes[user.ID] = string(hash)
	return nil
}

func (s *UserStore) UpdateUser(_ context.Context, user *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; !exists {
		return fmt.Errorf("user %q: %w", user.ID, store.ErrNotFound)
	}
	u := *user
	u.PasswordHash = ""
	s.users[user.ID] = &u
	return nil
}

func (s *UserStore) DeleteUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	delete(s.users, userID)
	delete(s.hashes, userID)
	delete(s.claims, userID)
	delete(s.roles, userID)
	delete(s.logins, userID)
	for k := range s.tokens {
		if strings.HasPrefix(k, userID+":") {
			delete(s.tokens, k)
		}
	}
	return nil
}

func (s *UserStore) FindUserByID(_ context.Context, userID string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, exists := s.users[userID]
	if !exists {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	copy := *u
	return &copy, nil
}

func (s *UserStore) FindUserByUsername(_ context.Context, username string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Username, username) {
			copy := *u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user %q: %w", username, store.ErrNotFound)
}

func (s *UserStore) FindUserByEmail(_ context.Context, email string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			copy := *u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user %q: %w", email, store.ErrNotFound)
}

func (s *UserStore) GetPagedUsers(_ context.Context, req domain.PagedRequest) (domain.PagedResult[domain.User], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req = req.Normalized()
	all := make([]domain.User, 0, len(s.users))
	for _, u := range s.users {
		all = append(all, *u)
	}
	start := (req.Page - 1) * req.PageSize
	if start >= len(all) {
		return domain.PagedResult[domain.User]{Page: req.Page, PageSize: req.PageSize, TotalCount: len(all)}, nil
	}
	end := start + req.PageSize
	if end > len(all) {
		end = len(all)
	}
	return domain.PagedResult[domain.User]{
		Items:      all[start:end],
		TotalCount: len(all),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *UserStore) SetPassword(_ context.Context, userID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	s.hashes[userID] = string(hash)
	return nil
}

func (s *UserStore) ValidateCredentials(_ context.Context, username, password string) (*domain.UserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == username || strings.EqualFold(u.Username, username) || strings.EqualFold(u.Email, username) {
			hash := s.hashes[u.ID]
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
				return nil, nil
			}
			claims := s.buildClaimsMap(u.ID)
			return &domain.UserInfo{UserID: u.ID, Claims: claims}, nil
		}
	}
	return nil, nil
}

func (s *UserStore) FindByID(_ context.Context, userID string) (*domain.UserInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, exists := s.users[userID]
	if !exists {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	claims := s.buildClaimsMap(userID)
	claims["preferred_username"] = u.Username
	if u.Email != "" {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailConfirmed
	}
	if u.PhoneNumber != "" {
		claims["phone_number"] = u.PhoneNumber
		claims["phone_number_verified"] = u.PhoneNumberConfirmed
	}
	return &domain.UserInfo{UserID: u.ID, Claims: claims}, nil
}

func (s *UserStore) buildClaimsMap(userID string) map[string]any {
	claims := make(map[string]any)
	for _, c := range s.claims[userID] {
		claims[c.Type] = c.Value
	}
	return claims
}

func (s *UserStore) GetUserClaims(_ context.Context, userID string) ([]domain.UserClaim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.users[userID]; !exists {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	result := make([]domain.UserClaim, len(s.claims[userID]))
	copy(result, s.claims[userID])
	return result, nil
}

func (s *UserStore) AddUserClaims(_ context.Context, userID string, claims []domain.UserClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	s.claims[userID] = append(s.claims[userID], claims...)
	return nil
}

func (s *UserStore) RemoveUserClaims(_ context.Context, userID string, claims []domain.UserClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	existing := s.claims[userID]
	for _, toRemove := range claims {
		for i := len(existing) - 1; i >= 0; i-- {
			if existing[i].Type == toRemove.Type && existing[i].Value == toRemove.Value {
				existing = append(existing[:i], existing[i+1:]...)
				break
			}
		}
	}
	s.claims[userID] = existing
	return nil
}

func (s *UserStore) ReplaceUserClaims(_ context.Context, userID string, claims []domain.UserClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	s.claims[userID] = claims
	return nil
}

func (s *UserStore) GetUserRoles(_ context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.users[userID]; !exists {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	result := make([]string, len(s.roles[userID]))
	copy(result, s.roles[userID])
	return result, nil
}

func (s *UserStore) AddToRoles(_ context.Context, userID string, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	existing := s.roles[userID]
	for _, role := range roles {
		found := false
		for _, r := range existing {
			if strings.EqualFold(r, role) {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, role)
		}
	}
	s.roles[userID] = existing
	return nil
}

func (s *UserStore) RemoveFromRoles(_ context.Context, userID string, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	existing := s.roles[userID]
	for _, toRemove := range roles {
		for i := len(existing) - 1; i >= 0; i-- {
			if strings.EqualFold(existing[i], toRemove) {
				existing = append(existing[:i], existing[i+1:]...)
				break
			}
		}
	}
	s.roles[userID] = existing
	return nil
}

func (s *UserStore) GetUsersInRole(_ context.Context, role string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []string
	for userID, roles := range s.roles {
		for _, r := range roles {
			if strings.EqualFold(r, role) {
				result = append(result, userID)
				break
			}
		}
	}
	return result, nil
}

func (s *UserStore) GetUserLogins(_ context.Context, userID string) ([]domain.UserLogin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.users[userID]; !exists {
		return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	result := make([]domain.UserLogin, len(s.logins[userID]))
	copy(result, s.logins[userID])
	return result, nil
}

func (s *UserStore) AddLogin(_ context.Context, login *domain.UserLogin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[login.UserID]; !exists {
		return fmt.Errorf("user %q: %w", login.UserID, store.ErrNotFound)
	}
	s.logins[login.UserID] = append(s.logins[login.UserID], *login)
	return nil
}

func (s *UserStore) RemoveLogin(_ context.Context, userID, provider, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
	}
	existing := s.logins[userID]
	for i := len(existing) - 1; i >= 0; i-- {
		if existing[i].LoginProvider == provider && existing[i].ProviderKey == key {
			existing = append(existing[:i], existing[i+1:]...)
			break
		}
	}
	s.logins[userID] = existing
	return nil
}

func (s *UserStore) FindByLogin(_ context.Context, provider, key string) (*domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, logins := range s.logins {
		for _, l := range logins {
			if l.LoginProvider == provider && l.ProviderKey == key {
				u := s.users[l.UserID]
				copy := *u
				return &copy, nil
			}
		}
	}
	return nil, fmt.Errorf("login %s/%s: %w", provider, key, store.ErrNotFound)
}

func (s *UserStore) SetUserToken(_ context.Context, token *domain.UserToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[token.UserID]; !exists {
		return fmt.Errorf("user %q: %w", token.UserID, store.ErrNotFound)
	}
	key := token.UserID + ":" + token.LoginProvider + ":" + token.Name
	s.tokens[key] = *token
	return nil
}

func (s *UserStore) GetUserToken(_ context.Context, userID, provider, name string) (*domain.UserToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := userID + ":" + provider + ":" + name
	t, exists := s.tokens[key]
	if !exists {
		return nil, fmt.Errorf("token %s: %w", key, store.ErrNotFound)
	}
	copy := t
	return &copy, nil
}

func (s *UserStore) RemoveUserToken(_ context.Context, userID, provider, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := userID + ":" + provider + ":" + name
	if _, exists := s.tokens[key]; !exists {
		return fmt.Errorf("token %s: %w", key, store.ErrNotFound)
	}
	delete(s.tokens, key)
	return nil
}
