package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PasswordResetStore is the GORM-backed store.PasswordResetStore. Like
// the authorization-code CAS, Consume is one conditional UPDATE so
// concurrent attempts race in the database, not in the application.
type PasswordResetStore struct{ db *gorm.DB }

func NewPasswordResetStore(db *gorm.DB) *PasswordResetStore { return &PasswordResetStore{db: db} }

func (s *PasswordResetStore) Create(ctx context.Context, t *domain.PasswordResetToken) error {
	if t == nil || t.ID == uuid.Nil || t.TokenHash == "" {
		return errors.New("password reset token: missing id or hash")
	}
	ent := toPasswordResetEntity(t)
	if err := s.db.WithContext(ctx).Create(ent).Error; err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("password reset token: %w", store.ErrDuplicate)
		}
		return err
	}
	return nil
}

func (s *PasswordResetStore) FindByHash(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	var ent passwordResetEntity
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("password reset token: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

// Consume is the atomic CAS:
//
//	UPDATE oauth_password_reset_tokens
//	   SET consumed_at = ?
//	 WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
func (s *PasswordResetStore) Consume(ctx context.Context, id uuid.UUID, now time.Time) (bool, error) {
	res := s.db.WithContext(ctx).Model(&passwordResetEntity{}).
		Where("id = ? AND consumed_at IS NULL AND expires_at > ?", id.String(), now.UTC()).
		Update("consumed_at", now.UTC())
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (s *PasswordResetStore) InvalidateForUser(ctx context.Context, userID string, now time.Time) error {
	return s.db.WithContext(ctx).Model(&passwordResetEntity{}).
		Where("user_id = ? AND consumed_at IS NULL", userID).
		Update("consumed_at", now.UTC()).Error
}

func (s *PasswordResetStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res := s.db.WithContext(ctx).Where("expires_at < ?", before.UTC()).Delete(&passwordResetEntity{})
	return int(res.RowsAffected), res.Error
}

// isUniqueViolation recognises unique-constraint failures from both
// supported drivers (Postgres in production, SQLite in tests), matching
// the check the user store uses.
func isUniqueViolation(err error) bool {
	return errors.Is(err, gorm.ErrDuplicatedKey) ||
		strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "duplicate key value violates unique constraint")
}
