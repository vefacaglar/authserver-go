package gormstore

import (
	"context"
	"errors"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

// DataProtectionKeyStore is the GORM-backed implementation of
// store.DataProtectionKeyStore. The active key is the row whose IsActive
// flag is true; retired keys remain queryable so cookies signed under them
// still decode.
type DataProtectionKeyStore struct{ db *gorm.DB }

func NewDataProtectionKeyStore(db *gorm.DB) *DataProtectionKeyStore {
	return &DataProtectionKeyStore{db: db}
}

func (s *DataProtectionKeyStore) GetActive(ctx context.Context) (*domain.DataProtectionKey, error) {
	var ent dataProtectionKeyEntity
	if err := s.db.WithContext(ctx).Where("is_active = ?", true).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("data protection key: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *DataProtectionKeyStore) GetAll(ctx context.Context) ([]domain.DataProtectionKey, error) {
	var ents []dataProtectionKeyEntity
	if err := s.db.WithContext(ctx).Order("created_at DESC").Find(&ents).Error; err != nil {
		return nil, err
	}
	out := make([]domain.DataProtectionKey, 0, len(ents))
	for i := range ents {
		out = append(out, *ents[i].toDomain())
	}
	return out, nil
}

func (s *DataProtectionKeyStore) Store(ctx context.Context, k *domain.DataProtectionKey) error {
	// Idempotent upsert by KeyID, matching the in-memory store.
	return s.db.WithContext(ctx).Save(toDataProtectionKeyEntity(k)).Error
}
