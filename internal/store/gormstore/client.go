package gormstore

import (
	"context"
	"errors"
	"fmt"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

// ClientStore is the GORM-backed implementation of
// store.ClientStore.
type ClientStore struct{ db *gorm.DB }

// NewClientStore wraps a *gorm.DB. The caller is responsible for
// having run Migrate() at least once.
func NewClientStore(db *gorm.DB) *ClientStore { return &ClientStore{db: db} }

func (s *ClientStore) FindByClientID(ctx context.Context, id string) (*domain.Client, error) {
	var ent clientEntity
	if err := s.db.WithContext(ctx).Where("client_id = ?", id).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("client %q: %w", id, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

func (s *ClientStore) GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Client], error) {
	req = req.Normalized()
	var (
		ents  []clientEntity
		total int64
	)
	q := s.db.WithContext(ctx).Model(&clientEntity{})
	if err := q.Count(&total).Error; err != nil {
		return domain.PagedResult[domain.Client]{}, err
	}
	if err := q.Order("client_id ASC").Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&ents).Error; err != nil {
		return domain.PagedResult[domain.Client]{}, err
	}
	items := make([]domain.Client, 0, len(ents))
	for i := range ents {
		c, err := ents[i].toDomain()
		if err != nil {
			return domain.PagedResult[domain.Client]{}, err
		}
		items = append(items, *c)
	}
	return domain.PagedResult[domain.Client]{
		Items:      items,
		TotalCount: int(total),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *ClientStore) Store(ctx context.Context, c *domain.Client) error {
	ent, err := toClientEntity(c)
	if err != nil {
		return err
	}
	// GORM Save() does INSERT-or-UPDATE on the primary key. For a
	// new client the INSERT path runs; for an existing one the
	// UPDATE path. No "duplicate key" surface to handle.
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *ClientStore) Delete(ctx context.Context, id string) error {
	res := s.db.WithContext(ctx).Where("client_id = ?", id).Delete(&clientEntity{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("client %q: %w", id, store.ErrNotFound)
	}
	return nil
}
