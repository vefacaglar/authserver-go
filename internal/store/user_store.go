package store

import (
	"context"

	"go-authserver/internal/domain"
)

type UserStore interface {
	ValidateCredentials(ctx context.Context, username, password string) (*domain.UserInfo, error)
	FindByID(ctx context.Context, userID string) (*domain.UserInfo, error)

	CreateUser(ctx context.Context, user *domain.User, password string) error
	UpdateUser(ctx context.Context, user *domain.User) error
	DeleteUser(ctx context.Context, userID string) error
	FindUserByID(ctx context.Context, userID string) (*domain.User, error)
	FindUserByUsername(ctx context.Context, username string) (*domain.User, error)
	FindUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetPagedUsers(ctx context.Context, req domain.PagedRequest) (domain.PagedResult[domain.User], error)
	SetPassword(ctx context.Context, userID, password string) error

	GetUserClaims(ctx context.Context, userID string) ([]domain.UserClaim, error)
	AddUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error
	RemoveUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error
	ReplaceUserClaims(ctx context.Context, userID string, claims []domain.UserClaim) error

	GetUserRoles(ctx context.Context, userID string) ([]string, error)
	AddToRoles(ctx context.Context, userID string, roles []string) error
	RemoveFromRoles(ctx context.Context, userID string, roles []string) error
	GetUsersInRole(ctx context.Context, role string) ([]string, error)

	GetUserLogins(ctx context.Context, userID string) ([]domain.UserLogin, error)
	AddLogin(ctx context.Context, login *domain.UserLogin) error
	RemoveLogin(ctx context.Context, userID, provider, key string) error
	FindByLogin(ctx context.Context, provider, key string) (*domain.User, error)

	SetUserToken(ctx context.Context, token *domain.UserToken) error
	GetUserToken(ctx context.Context, userID, provider, name string) (*domain.UserToken, error)
	RemoveUserToken(ctx context.Context, userID, provider, name string) error
}
