package oidc

import "go-authserver/internal/domain"

// The password policy lives in domain so the admin API enforces the same
// rules; these names keep the oidc call sites unchanged.
const (
	PasswordMinLength = domain.PasswordMinLength
	PasswordMaxBytes  = domain.PasswordMaxBytes
)

var (
	ErrPasswordTooShort   = domain.ErrPasswordTooShort
	ErrPasswordTooLong    = domain.ErrPasswordTooLong
	ErrPasswordWhitespace = domain.ErrPasswordWhitespace
)

// ValidatePassword enforces the server-side password policy shared by
// register, change-password and reset-password.
func ValidatePassword(pw string) error {
	return domain.ValidatePassword(pw)
}
