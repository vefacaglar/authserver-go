package gormstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuthorizationCodeStore is the GORM-backed implementation of
// store.AuthorizationCodeStore. The MarkConsumed CAS is the single
// most important security primitive in the system — it must be a
// one-statement UPDATE so concurrent attempts race in the database,
// not in the application.
type AuthorizationCodeStore struct{ db *gorm.DB }

func NewAuthorizationCodeStore(db *gorm.DB) *AuthorizationCodeStore {
	return &AuthorizationCodeStore{db: db}
}

func (s *AuthorizationCodeStore) Store(ctx context.Context, c *domain.AuthorizationCode) error {
	ent, err := toAuthCodeEntity(c)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *AuthorizationCodeStore) FindByHash(ctx context.Context, hash string) (*domain.AuthorizationCode, error) {
	var ent authCodeEntity
	if err := s.db.WithContext(ctx).Where("code_hash = ?", hash).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("authcode: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

// MarkConsumed is the atomic CAS. The query is:
//
//	UPDATE oauth_authorization_codes
//	   SET consumed_at = ?
//	 WHERE id = ? AND consumed_at IS NULL
//
// RowsAffected == 1 means we won the race and the row is now
// consumed; RowsAffected == 0 means another caller already consumed
// it (or the id does not exist).
func (s *AuthorizationCodeStore) MarkConsumed(ctx context.Context, id uuid.UUID, consumedAt time.Time) (bool, error) {
	idStr := id.String()
	res := s.db.WithContext(ctx).Model(&authCodeEntity{}).
		Where("id = ? AND consumed_at IS NULL", idStr).
		Update("consumed_at", consumedAt.UTC())
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}
