package store

import (
	"context"

	"go-authserver/internal/domain"
)

type UserStore interface {
	// ValidateCredentials returns (*domain.UserInfo, nil) on success, (nil, nil)
	// on bad credentials, and (nil, err) only on backend errors. Callers MUST
	// treat (nil, nil) the same way as a wrong password to avoid user-enumeration.
	ValidateCredentials(ctx context.Context, username, password string) (*domain.UserInfo, error)
	FindByID(ctx context.Context, userID string) (*domain.UserInfo, error)
}
