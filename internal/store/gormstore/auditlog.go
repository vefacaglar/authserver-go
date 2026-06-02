package gormstore

import (
	"context"

	"go-authserver/internal/domain"

	"gorm.io/gorm"
)

// AuditLogStore is the GORM-backed implementation of
// store.AuditLogStore. Audit logs are append-only by convention; the
// implementation does not expose Update/Delete.
type AuditLogStore struct{ db *gorm.DB }

func NewAuditLogStore(db *gorm.DB) *AuditLogStore { return &AuditLogStore{db: db} }

func (s *AuditLogStore) Store(ctx context.Context, l *domain.AuditLog) error {
	ent, err := toAuditLogEntity(l)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Create(ent).Error
}

func (s *AuditLogStore) GetPaged(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.AuditLog], error) {
	req = req.Normalized()
	var (
		ents  []auditLogEntity
		total int64
	)
	q := s.db.WithContext(ctx).Model(&auditLogEntity{})
	if err := q.Count(&total).Error; err != nil {
		return domain.PagedResult[domain.AuditLog]{}, err
	}
	if err := q.Order("timestamp DESC").Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&ents).Error; err != nil {
		return domain.PagedResult[domain.AuditLog]{}, err
	}
	items := make([]domain.AuditLog, 0, len(ents))
	for i := range ents {
		l, err := ents[i].toDomain()
		if err != nil {
			return domain.PagedResult[domain.AuditLog]{}, err
		}
		items = append(items, *l)
	}
	return domain.PagedResult[domain.AuditLog]{
		Items:      items,
		TotalCount: int(total),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}
