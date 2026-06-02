// Package store defines the persistence ports (interfaces) for the auth server.
//
// Implementations live in subpackages (currently store/memory and, later,
// store/gormstore). All methods accept a context.Context as the first
// argument and return errors wrapped with %w so callers can use errors.Is.
package store

import "errors"

var (
	ErrNotFound  = errors.New("store: not found")
	ErrDuplicate = errors.New("store: duplicate")
)
