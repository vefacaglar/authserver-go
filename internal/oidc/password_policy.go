package oidc

import (
	"errors"
	"strings"
)

// Password length bounds. The upper bound is bcrypt's 72-byte input
// limit; longer values would be silently truncated.
const (
	PasswordMinLength = 8
	PasswordMaxBytes  = 72
)

var (
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong    = errors.New("password must be at most 72 bytes")
	ErrPasswordWhitespace = errors.New("password must not be blank or start/end with whitespace")
)

// ValidatePassword enforces the server-side password policy shared by
// register, change-password and reset-password.
func ValidatePassword(pw string) error {
	if strings.TrimSpace(pw) == "" || pw != strings.TrimSpace(pw) {
		return ErrPasswordWhitespace
	}
	if len([]rune(pw)) < PasswordMinLength {
		return ErrPasswordTooShort
	}
	if len(pw) > PasswordMaxBytes {
		return ErrPasswordTooLong
	}
	return nil
}
