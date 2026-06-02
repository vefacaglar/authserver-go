package gormstore

import (
	"context"
	"testing"
	"time"
)

// TestLoginAttemptTracker_LocksAfterMaxFailures proves the persistent
// tracker reproduces the in-memory semantics: MaxFailures inside the window
// locks the key, Reset clears it, and an elapsed window starts fresh.
func TestLoginAttemptTracker_LocksAfterMaxFailures(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	now := time.Unix(1700000000, 0).UTC()
	tr := NewLoginAttemptTracker(db, func() time.Time { return now })

	const key = "alice"
	for i := 0; i < tr.MaxFailures-1; i++ {
		if err := tr.RecordFailure(ctx, key); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
		if locked, _ := tr.IsLockedOut(ctx, key); locked {
			t.Fatalf("locked after %d failures; want lock only at %d", i+1, tr.MaxFailures)
		}
	}
	// The MaxFailures-th failure locks.
	if err := tr.RecordFailure(ctx, key); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if locked, _ := tr.IsLockedOut(ctx, key); !locked {
		t.Fatalf("not locked after %d failures", tr.MaxFailures)
	}

	// Reset clears the lock.
	if err := tr.Reset(ctx, key); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if locked, _ := tr.IsLockedOut(ctx, key); locked {
		t.Fatalf("still locked after Reset")
	}
}

// TestLoginAttemptTracker_WindowResets proves a failure after the window
// has elapsed starts a new window instead of accumulating toward a lock.
func TestLoginAttemptTracker_WindowResets(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	base := time.Unix(1700000000, 0).UTC()
	now := base
	tr := NewLoginAttemptTracker(db, func() time.Time { return now })

	const key = "bob"
	if err := tr.RecordFailure(ctx, key); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	// Jump past the reset window, then fail again: counter must restart.
	now = base.Add(tr.ResetAfter + time.Minute)
	if err := tr.RecordFailure(ctx, key); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	var e loginAttemptEntity
	if err := db.First(&e, "principal = ?", key).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if e.Failures != 1 {
		t.Fatalf("Failures = %d after window reset; want 1", e.Failures)
	}
}
