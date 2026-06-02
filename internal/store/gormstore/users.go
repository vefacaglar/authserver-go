package gormstore

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

// UserStore is the GORM-backed implementation of store.UserStore.
// Passwords are stored opaque (the directory is host-owned); the
// sample/demo flow simply stores a plaintext password because the
// real-world directory will replace this with bcrypt/SSO/LDAP. The
// comparison is constant-time.
type UserStore struct{ db *gorm.DB }

func NewUserStore(db *gorm.DB) *UserStore { return &UserStore{db: db} }

// Add is a convenience for the seed/bootstrap path. The interface
// itself only requires ValidateCredentials + FindByID; Add is a
// gormstore-specific extension to keep the seed flow simple.
func (s *UserStore) Add(u domain.UserInfo, password string) error {
	ent, err := toUserEntity(&u, password)
	if err != nil {
		return err
	}
	return s.db.Save(ent).Error
}

func (s *UserStore) FindByID(ctx context.Context, userID string) (*domain.UserInfo, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user %q: %w", userID, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

// ValidateCredentials returns (info, nil) on success, (nil, nil) on
// wrong credentials (caller MUST treat as failure to avoid user
// enumeration), and (nil, err) on backend errors. The compare is
// constant-time on the password bytes.
func (s *UserStore) ValidateCredentials(ctx context.Context, username, password string) (*domain.UserInfo, error) {
	var ent userEntity
	if err := s.db.WithContext(ctx).Where("user_id = ? OR username = ?", username, username).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("user lookup: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(ent.PasswordHash), []byte(password)) != 1 {
		return nil, nil
	}
	info, err := ent.toDomain()
	if err != nil {
		return nil, err
	}
	return info, nil
}
