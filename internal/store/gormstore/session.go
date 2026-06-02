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

// SessionStore is the GORM-backed implementation of
// store.SessionStore.
type SessionStore struct{ db *gorm.DB }

func NewSessionStore(db *gorm.DB) *SessionStore { return &SessionStore{db: db} }

func (s *SessionStore) Find(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	var ent sessionEntity
	if err := s.db.WithContext(ctx).Where("id = ?", id.String()).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session %s: %w", id, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

func (s *SessionStore) GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.Session], error) {
	req = req.Normalized()
	var (
		ents  []sessionEntity
		total int64
	)
	q := s.db.WithContext(ctx).Model(&sessionEntity{})
	if err := q.Count(&total).Error; err != nil {
		return domain.PagedResult[domain.Session]{}, err
	}
	if err := q.Order("created_at DESC").Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&ents).Error; err != nil {
		return domain.PagedResult[domain.Session]{}, err
	}
	items := make([]domain.Session, 0, len(ents))
	for i := range ents {
		sess, err := ents[i].toDomain()
		if err != nil {
			return domain.PagedResult[domain.Session]{}, err
		}
		items = append(items, *sess)
	}
	return domain.PagedResult[domain.Session]{
		Items:      items,
		TotalCount: int(total),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *SessionStore) Store(ctx context.Context, sess *domain.Session) error {
	ent, err := toSessionEntity(sess)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *SessionStore) Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error {
	res := s.db.WithContext(ctx).Model(&sessionEntity{}).
		Where("id = ? AND revoked_at IS NULL", id.String()).
		Update("revoked_at", revokedAt.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("session %s: %w", id, store.ErrNotFound)
	}
	return nil
}
