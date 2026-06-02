package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"gorm.io/gorm"
)

type RoleStore struct{ db *gorm.DB }

func NewRoleStore(db *gorm.DB) *RoleStore { return &RoleStore{db: db} }

func (s *RoleStore) CreateRole(ctx context.Context, role *domain.Role) error {
	if role.ID == "" {
		return errors.New("role: empty id")
	}
	ent := toRoleEntity(role)
	return s.db.WithContext(ctx).Create(ent).Error
}

func (s *RoleStore) DeleteRole(ctx context.Context, roleID string) error {
	tx := s.db.WithContext(ctx)
	if err := tx.Where("role_id = ?", roleID).Delete(&userRoleEntity{}).Error; err != nil {
		return err
	}
	if err := tx.Where("role_id = ?", roleID).Delete(&roleClaimEntity{}).Error; err != nil {
		return err
	}
	result := tx.Where("id = ?", roleID).Delete(&roleEntity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
	}
	return nil
}

func (s *RoleStore) FindRoleByID(ctx context.Context, roleID string) (*domain.Role, error) {
	var ent roleEntity
	if err := s.db.WithContext(ctx).Where("id = ?", roleID).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("role %q: %w", roleID, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *RoleStore) FindRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	var ent roleEntity
	if err := s.db.WithContext(ctx).Where("normalized_name = ?", strings.ToUpper(name)).First(&ent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("role %q: %w", name, store.ErrNotFound)
		}
		return nil, err
	}
	return ent.toDomain(), nil
}

func (s *RoleStore) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	var entities []roleEntity
	if err := s.db.WithContext(ctx).Find(&entities).Error; err != nil {
		return nil, err
	}
	result := make([]domain.Role, len(entities))
	for i, e := range entities {
		result[i] = *e.toDomain()
	}
	return result, nil
}

func (s *RoleStore) GetRoleClaims(ctx context.Context, roleID string) ([]domain.RoleClaim, error) {
	var entities []roleClaimEntity
	if err := s.db.WithContext(ctx).Where("role_id = ?", roleID).Find(&entities).Error; err != nil {
		return nil, err
	}
	result := make([]domain.RoleClaim, len(entities))
	for i, e := range entities {
		result[i] = domain.RoleClaim{Type: e.Type, Value: e.Value}
	}
	return result, nil
}

func (s *RoleStore) AddRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error {
	for _, c := range claims {
		ent := roleClaimEntity{RoleID: roleID, Type: c.Type, Value: c.Value}
		if err := s.db.WithContext(ctx).Create(&ent).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *RoleStore) RemoveRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error {
	for _, c := range claims {
		if err := s.db.WithContext(ctx).Where("role_id = ? AND type = ? AND value = ?", roleID, c.Type, c.Value).Delete(&roleClaimEntity{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *RoleStore) ReplaceRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error {
	if err := s.db.WithContext(ctx).Where("role_id = ?", roleID).Delete(&roleClaimEntity{}).Error; err != nil {
		return err
	}
	return s.AddRoleClaims(ctx, roleID, claims)
}
