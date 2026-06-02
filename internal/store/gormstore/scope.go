package gormstore

import (
	"context"
	"errors"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

// ScopeStore is the GORM-backed implementation of store.ScopeStore.
type ScopeStore struct{ db *gorm.DB }

func NewScopeStore(db *gorm.DB) *ScopeStore { return &ScopeStore{db: db} }

func (s *ScopeStore) FindByName(ctx context.Context, name string) (*domain.Scope, error) {
	var ent scopeEntity
	if err := s.db.WithContext(ctx).Where("name = ?", name).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("scope %q: %w", name, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

func (s *ScopeStore) GetAll(ctx context.Context) ([]domain.Scope, error) {
	var ents []scopeEntity
	if err := s.db.WithContext(ctx).Order("name ASC").Find(&ents).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Scope, 0, len(ents))
	for i := range ents {
		sc, err := ents[i].toDomain()
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, nil
}

func (s *ScopeStore) Store(ctx context.Context, sc *domain.Scope) error {
	ent, err := toScopeEntity(sc)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *ScopeStore) Delete(ctx context.Context, name string) error {
	res := s.db.WithContext(ctx).Where("name = ?", name).Delete(&scopeEntity{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("scope %q: %w", name, store.ErrNotFound)
	}
	return nil
}
