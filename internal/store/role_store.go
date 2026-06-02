package store

import (
	"context"

	"go-authserver/internal/domain"
)

type RoleStore interface {
	CreateRole(ctx context.Context, role *domain.Role) error
	DeleteRole(ctx context.Context, roleID string) error
	FindRoleByID(ctx context.Context, roleID string) (*domain.Role, error)
	FindRoleByName(ctx context.Context, name string) (*domain.Role, error)
	GetAllRoles(ctx context.Context) ([]domain.Role, error)

	GetRoleClaims(ctx context.Context, roleID string) ([]domain.RoleClaim, error)
	AddRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error
	RemoveRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error
	ReplaceRoleClaims(ctx context.Context, roleID string, claims []domain.RoleClaim) error
}
