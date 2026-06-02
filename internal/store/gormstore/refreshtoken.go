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

// RefreshTokenStore is the GORM-backed implementation of
// store.RefreshTokenStore. MarkConsumed is the atomic CAS that makes
// refresh-token rotation + reuse detection race-safe.
type RefreshTokenStore struct{ db *gorm.DB }

func NewRefreshTokenStore(db *gorm.DB) *RefreshTokenStore {
	return &RefreshTokenStore{db: db}
}

func (s *RefreshTokenStore) Store(ctx context.Context, t *domain.RefreshToken) error {
	ent, err := toRefreshTokenEntity(t)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(ent).Error
}

func (s *RefreshTokenStore) FindByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	var ent refreshTokenEntity
	if err := s.db.WithContext(ctx).Where("token_hash = ?", hash).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("refresh token: %w", store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain()
}

func (s *RefreshTokenStore) GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.RefreshToken], error) {
	req = req.Normalized()
	var (
		ents  []refreshTokenEntity
		total int64
	)
	q := s.db.WithContext(ctx).Model(&refreshTokenEntity{})
	if err := q.Count(&total).Error; err != nil {
		return domain.PagedResult[domain.RefreshToken]{}, err
	}
	if err := q.Order("created_at DESC").Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&ents).Error; err != nil {
		return domain.PagedResult[domain.RefreshToken]{}, err
	}
	items := make([]domain.RefreshToken, 0, len(ents))
	for i := range ents {
		t, err := ents[i].toDomain()
		if err != nil {
			return domain.PagedResult[domain.RefreshToken]{}, err
		}
		items = append(items, *t)
	}
	return domain.PagedResult[domain.RefreshToken]{
		Items:      items,
		TotalCount: int(total),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

// MarkConsumed: the CAS. One UPDATE; RowsAffected == 1 means we won.
// Same shape as AuthorizationCodeStore.MarkConsumed — see that file
// for the rationale.
func (s *RefreshTokenStore) MarkConsumed(ctx context.Context, id uuid.UUID, consumedAt time.Time) (bool, error) {
	idStr := id.String()
	res := s.db.WithContext(ctx).Model(&refreshTokenEntity{}).
		Where("id = ? AND consumed_at IS NULL", idStr).
		Update("consumed_at", consumedAt.UTC())
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (s *RefreshTokenStore) Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error {
	res := s.db.WithContext(ctx).Model(&refreshTokenEntity{}).
		Where("id = ? AND revoked_at IS NULL", id.String()).
		Update("revoked_at", revokedAt.UTC())
	if res.Error != nil {
		return res.Error
	}
	// Idempotent: a row that was already revoked returns 0 rows
	// affected and is not an error. Only an id that does not exist
	// surfaces as ErrNotFound, and the caller already has the
	// RefreshToken from FindByHash, so this branch is mostly a
	// safety net.
	if res.RowsAffected == 0 {
		var n int64
		if err := s.db.WithContext(ctx).Model(&refreshTokenEntity{}).Where("id = ?", id.String()).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("refresh token %s: %w", id, store.ErrNotFound)
		}
	}
	return nil
}

// RevokeBySessionID revokes every refresh token in a session chain in
// a single UPDATE. The refresh grant's reuse-detection path relies
// on this being a one-shot write so the chain is killed atomically.
func (s *RefreshTokenStore) RevokeBySessionID(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	return s.db.WithContext(ctx).Model(&refreshTokenEntity{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID.String()).
		Update("revoked_at", revokedAt.UTC()).Error
}
