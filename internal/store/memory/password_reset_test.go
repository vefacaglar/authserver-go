package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

func newResetToken(userID, hash string, now time.Time, ttl time.Duration) *domain.PasswordResetToken {
	return &domain.PasswordResetToken{ID: uuid.New(), UserID: userID, TokenHash: hash, CreatedAt: now, ExpiresAt: now.Add(ttl)}
}

func TestPasswordReset_CreateFindDuplicate(t *testing.T) {
	ctx := context.Background()
	s := NewPasswordResetStore()
	now := time.Unix(1700000000, 0)
	tok := newResetToken("u-1", "hash-1", now, time.Hour)
	if err := s.Create(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindByHash(ctx, "hash-1")
	if err != nil || got.ID != tok.ID || got.UserID != "u-1" {
		t.Fatalf("FindByHash = %+v, %v", got, err)
	}
	if _, err := s.FindByHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown hash err = %v, want ErrNotFound", err)
	}
	if err := s.Create(ctx, newResetToken("u-2", "hash-1", now, time.Hour)); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate hash err = %v, want ErrDuplicate", err)
	}
}

func TestPasswordReset_ConsumeExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	s := NewPasswordResetStore()
	now := time.Unix(1700000000, 0)
	tok := newResetToken("u-1", "h", now, time.Hour)
	_ = s.Create(ctx, tok)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Consume(ctx, tok.ID, now)
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins.Load())
	}
}

func TestPasswordReset_ConsumeRejectsExpiredAndUnknown(t *testing.T) {
	ctx := context.Background()
	s := NewPasswordResetStore()
	now := time.Unix(1700000000, 0)
	tok := newResetToken("u-1", "h", now, time.Minute)
	_ = s.Create(ctx, tok)

	if ok, _ := s.Consume(ctx, tok.ID, now.Add(time.Minute)); ok {
		t.Error("token consumed at its expiry instant")
	}
	if ok, _ := s.Consume(ctx, uuid.New(), now); ok {
		t.Error("unknown id consumed")
	}
	if ok, _ := s.Consume(ctx, tok.ID, now.Add(time.Minute-time.Second)); !ok {
		t.Error("valid token not consumable just before expiry")
	}
}

func TestPasswordReset_InvalidateAndDeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := NewPasswordResetStore()
	now := time.Unix(1700000000, 0)
	a := newResetToken("u-1", "a", now, time.Hour)
	b := newResetToken("u-1", "b", now, time.Hour)
	other := newResetToken("u-2", "c", now, time.Hour)
	old := newResetToken("u-3", "d", now.Add(-48*time.Hour), time.Hour)
	for _, tk := range []*domain.PasswordResetToken{a, b, other, old} {
		_ = s.Create(ctx, tk)
	}

	if err := s.InvalidateForUser(ctx, "u-1", now); err != nil {
		t.Fatal(err)
	}
	for _, tk := range []*domain.PasswordResetToken{a, b} {
		if ok, _ := s.Consume(ctx, tk.ID, now); ok {
			t.Errorf("token %s still consumable after InvalidateForUser", tk.TokenHash)
		}
	}
	if ok, _ := s.Consume(ctx, other.ID, now); !ok {
		t.Error("another user's token was invalidated")
	}

	n, err := s.DeleteExpired(ctx, now.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v; want 1", n, err)
	}
	if _, err := s.FindByHash(ctx, "d"); !errors.Is(err, store.ErrNotFound) {
		t.Error("expired token not deleted")
	}
}
