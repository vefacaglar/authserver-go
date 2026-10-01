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

func (s *SessionStore) ListByUserID(ctx context.Context, userID string, now time.Time) ([]domain.Session, error) {
	var ents []sessionEntity
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now.UTC()).
		Order("created_at DESC").Find(&ents).Error
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(ents))
	for i := range ents {
		sess, err := ents[i].toDomain()
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, nil
}

// RevokeByUserIDExcept selects and revokes inside one transaction; the
// revoked_at IS NULL guard on the UPDATE keeps a concurrent revoke from
// being reported twice.
func (s *SessionStore) RevokeByUserIDExcept(ctx context.Context, userID string, keep uuid.UUID, revokedAt time.Time) ([]uuid.UUID, error) {
	var revoked []uuid.UUID
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx.Model(&sessionEntity{}).Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, revokedAt.UTC())
		if keep != uuid.Nil {
			q = q.Where("id <> ?", keep.String())
		}
		var ids []string
		if err := q.Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := tx.Model(&sessionEntity{}).
			Where("id IN ? AND revoked_at IS NULL", ids).
			Update("revoked_at", revokedAt.UTC()).Error; err != nil {
			return err
		}
		for _, id := range ids {
			u, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("session %q: parse id: %w", id, err)
			}
			revoked = append(revoked, u)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}
