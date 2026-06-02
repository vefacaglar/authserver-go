package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

// TestAuthCode_MarkConsumed_SingleWinner launches many goroutines all racing
// to consume the same authorization code. Exactly one must observe the
// nil→set transition; everyone else must get false. This is the security
// guarantee the spec demands of every MarkConsumed implementation.
func TestAuthCode_MarkConsumed_SingleWinner(t *testing.T) {
	const goroutines = 50
	ctx := context.Background()
	store := NewAuthorizationCodeStore()

	id := uuid.New()
	if err := store.Store(ctx, &domain.AuthorizationCode{
		ID:        id,
		CodeHash:  "h",
		ClientID:  "c",
		UserID:    "u",
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	var wins int64
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			ok, err := store.MarkConsumed(ctx, id, time.Now())
			if err != nil {
				t.Errorf("MarkConsumed: %v", err)
				return
			}
			if ok {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	start.Done()
	done.Wait()

	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1", wins)
	}

	got, err := store.FindByHash(ctx, "h")
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if got.ConsumedAt == nil {
		t.Errorf("ConsumedAt = nil, want non-nil after winner")
	}
}

// TestAuthCode_MarkConsumed_SecondCallReturnsFalse verifies the basic
// sequential case: a second MarkConsumed after a winner must return false.
func TestAuthCode_MarkConsumed_SecondCallReturnsFalse(t *testing.T) {
	ctx := context.Background()
	store := NewAuthorizationCodeStore()
	id := uuid.New()
	_ = store.Store(ctx, &domain.AuthorizationCode{ID: id, CodeHash: "h", ExpiresAt: time.Now().Add(time.Minute)})

	ok, err := store.MarkConsumed(ctx, id, time.Now())
	if err != nil || !ok {
		t.Fatalf("first MarkConsumed = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = store.MarkConsumed(ctx, id, time.Now())
	if err != nil || ok {
		t.Fatalf("second MarkConsumed = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestAuthCode_MarkConsumed_UnknownID(t *testing.T) {
	ctx := context.Background()
	store := NewAuthorizationCodeStore()
	ok, err := store.MarkConsumed(ctx, uuid.New(), time.Now())
	if err == nil {
		t.Fatalf("MarkConsumed(unknown): expected error, got nil")
	}
	if ok {
		t.Errorf("MarkConsumed(unknown) returned ok=true, want false")
	}
}

func TestRefreshToken_MarkConsumed_SingleWinner(t *testing.T) {
	const goroutines = 50
	ctx := context.Background()
	store := NewRefreshTokenStore()

	id := uuid.New()
	if err := store.Store(ctx, &domain.RefreshToken{
		ID:                id,
		TokenHash:         "h",
		ClientID:          "c",
		UserID:            "u",
		ExpiresAt:         time.Now().Add(time.Hour),
		AbsoluteExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt:         time.Now(),
	}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	var wins int64
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			ok, err := store.MarkConsumed(ctx, id, time.Now())
			if err != nil {
				t.Errorf("MarkConsumed: %v", err)
				return
			}
			if ok {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	start.Done()
	done.Wait()

	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1", wins)
	}
}
