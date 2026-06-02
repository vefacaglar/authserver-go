package gormstore

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// LoginAttemptTracker is the GORM-backed, cross-instance equivalent of the
// in-memory tracker: a fixed-window failure counter persisted so that
// brute-force lockout is enforced globally across every instance behind a
// load balancer. The semantics match memory.LoginAttemptTracker exactly.
type LoginAttemptTracker struct {
	db  *gorm.DB
	now func() time.Time

	MaxFailures     int
	LockoutDuration time.Duration
	ResetAfter      time.Duration
}

// NewLoginAttemptTracker returns a tracker with the same defaults as the
// in-memory one (5 failures inside a 15-minute window → 15-minute lock).
func NewLoginAttemptTracker(db *gorm.DB, now func() time.Time) *LoginAttemptTracker {
	if now == nil {
		now = time.Now
	}
	return &LoginAttemptTracker{
		db:              db,
		now:             now,
		MaxFailures:     5,
		LockoutDuration: 15 * time.Minute,
		ResetAfter:      15 * time.Minute,
	}
}

func (t *LoginAttemptTracker) IsLockedOut(ctx context.Context, key string) (bool, error) {
	var e loginAttemptEntity
	err := t.db.WithContext(ctx).First(&e, "principal = ?", key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := t.now()
	if e.LockedAt != nil && now.Sub(*e.LockedAt) < t.LockoutDuration {
		return true, nil
	}
	// Window elapsed with no active lock: clear the stale row so the next
	// failure starts a fresh window.
	if now.Sub(e.FirstAt) > t.ResetAfter {
		if err := t.db.WithContext(ctx).Delete(&loginAttemptEntity{}, "principal = ?", key).Error; err != nil {
			return false, err
		}
		return false, nil
	}
	return false, nil
}

func (t *LoginAttemptTracker) RecordFailure(ctx context.Context, key string) error {
	now := t.now()
	return t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		read := tx
		// On Postgres take a row lock so concurrent failures from
		// different instances can't lose an increment. SQLite (tests only)
		// serialises writers already and doesn't support FOR UPDATE.
		if tx.Dialector.Name() == "postgres" {
			read = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var e loginAttemptEntity
		err := read.First(&e, "principal = ?", key).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&loginAttemptEntity{Principal: key, Failures: 1, FirstAt: now}).Error
		}
		if err != nil {
			return err
		}
		if now.Sub(e.FirstAt) > t.ResetAfter {
			e.Failures = 1
			e.FirstAt = now
			e.LockedAt = nil
		} else {
			e.Failures++
			if e.Failures >= t.MaxFailures && e.LockedAt == nil {
				locked := now
				e.LockedAt = &locked
			}
		}
		return tx.Save(&e).Error
	})
}

func (t *LoginAttemptTracker) Reset(ctx context.Context, key string) error {
	return t.db.WithContext(ctx).Delete(&loginAttemptEntity{}, "principal = ?", key).Error
}
