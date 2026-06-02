package gormstore

import (
	"context"
	"errors"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

// SigningKeyStore is the GORM-backed implementation of
// store.SigningKeyStore. The active key is the row whose IsActive
// flag is true; retired keys remain queryable so JWKS rotation
// remains verifiable.
type SigningKeyStore struct{ db *gorm.DB }

func NewSigningKeyStore(db *gorm.DB) *SigningKeyStore {
	return &SigningKeyStore{db: db}
}

func (s *SigningKeyStore) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	var ent signingKeyEntity
	if err := s.db.WithContext(ctx).Where("is_active = ?", true).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("signing key: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *SigningKeyStore) GetAll(ctx context.Context) ([]domain.SigningKey, error) {
	var ents []signingKeyEntity
	if err := s.db.WithContext(ctx).Order("created_at ASC").Find(&ents).Error; err != nil {
		return nil, err
	}
	out := make([]domain.SigningKey, 0, len(ents))
	for i := range ents {
		out = append(out, *ents[i].toDomain())
	}
	return out, nil
}

func (s *SigningKeyStore) Store(ctx context.Context, k *domain.SigningKey) error {
	ent := toSigningKeyEntity(k)
	// Idempotent: the caller may re-store the same key on each
	// boot. Save() is INSERT-or-UPDATE; this matches the in-memory
	// store's behaviour.
	return s.db.WithContext(ctx).Save(ent).Error
}
