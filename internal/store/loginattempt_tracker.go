package store

import "context"

type LoginAttemptTracker interface {
	IsLockedOut(ctx context.Context, key string) (bool, error)
	RecordFailure(ctx context.Context, key string) error
	Reset(ctx context.Context, key string) error
}
