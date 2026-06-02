package memory

import (
	"context"
	"sync"
	"time"
)

// LoginAttemptTracker is a fixed-window failure counter. The window is a
// rolling time window since the first failure; MaxFailures failures inside
// the window lock the key for LockoutDuration.
type LoginAttemptTracker struct {
	mu       sync.Mutex
	attempts map[string]*attempt
	now      func() time.Time

	MaxFailures     int
	LockoutDuration time.Duration
	ResetAfter      time.Duration
}

type attempt struct {
	failures int
	firstAt  time.Time
	lockedAt time.Time
}

func NewLoginAttemptTracker(now func() time.Time) *LoginAttemptTracker {
	if now == nil {
		now = time.Now
	}
	return &LoginAttemptTracker{
		attempts:        make(map[string]*attempt),
		now:             now,
		MaxFailures:     5,
		LockoutDuration: 15 * time.Minute,
		ResetAfter:      15 * time.Minute,
	}
}

func (t *LoginAttemptTracker) IsLockedOut(_ context.Context, key string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.attempts[key]
	if !ok {
		return false, nil
	}
	now := t.now()
	if !a.lockedAt.IsZero() && now.Sub(a.lockedAt) < t.LockoutDuration {
		return true, nil
	}
	if now.Sub(a.firstAt) > t.ResetAfter {
		delete(t.attempts, key)
		return false, nil
	}
	return false, nil
}

func (t *LoginAttemptTracker) RecordFailure(_ context.Context, key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	a, ok := t.attempts[key]
	if !ok {
		t.attempts[key] = &attempt{failures: 1, firstAt: now}
		return nil
	}
	if now.Sub(a.firstAt) > t.ResetAfter {
		a.failures = 1
		a.firstAt = now
		a.lockedAt = time.Time{}
		return nil
	}
	a.failures++
	if a.failures >= t.MaxFailures && a.lockedAt.IsZero() {
		a.lockedAt = now
	}
	return nil
}

func (t *LoginAttemptTracker) Reset(_ context.Context, key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, key)
	return nil
}
