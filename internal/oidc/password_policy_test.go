package oidc

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		want error
	}{
		{"ok", "correct horse", nil},
		{"ok unicode min runes", "şğüöçıİÖ", nil},
		{"too short", "short", ErrPasswordTooShort},
		{"blank", "        ", ErrPasswordWhitespace},
		{"empty", "", ErrPasswordWhitespace},
		{"leading space", " password1", ErrPasswordWhitespace},
		{"trailing space", "password1 ", ErrPasswordWhitespace},
		{"max ok", strings.Repeat("a", PasswordMaxBytes), nil},
		{"too long", strings.Repeat("a", PasswordMaxBytes+1), ErrPasswordTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidatePassword(tc.pw); !errors.Is(got, tc.want) {
				t.Fatalf("ValidatePassword() = %v, want %v", got, tc.want)
			}
		})
	}
}
