package session

import (
	"context"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/store/memory"

	"github.com/google/uuid"
)

// TestDPKeyRotation_OldCookiesStillDecode proves the key ring makes rotation
// non-disruptive: a cookie signed under the original key still decodes after
// the key is rotated, because the retired key stays in the ring.
func TestDPKeyRotation_OldCookiesStillDecode(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	mgr := NewDPKeyManager(memory.NewDataProtectionKeyStore(), clk)

	cfg := CookieConfig{Name: "sess", Path: "/", MaxAge: time.Hour}

	// Boot 1: bootstrap a key, issue a cookie for a session id.
	keys1, active1, err := mgr.Keyset(ctx)
	if err != nil {
		t.Fatalf("Keyset #1: %v", err)
	}
	cm1 := NewCookieManagerFromKeys(keys1, cfg, clk)
	id := uuid.New()
	cookie, err := cm1.Encode(id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Rotate the data-protection key.
	active2, err := mgr.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if active2.KeyID == active1.KeyID {
		t.Fatalf("Rotate did not change the active key")
	}

	// Boot 2: rebuild the manager's ring (new active + retired old).
	keys2, _, err := mgr.Keyset(ctx)
	if err != nil {
		t.Fatalf("Keyset #2: %v", err)
	}
	if len(keys2) != 2 {
		t.Fatalf("ring size = %d, want 2 (active + retired)", len(keys2))
	}
	cm2 := NewCookieManagerFromKeys(keys2, cfg, clk)

	// The cookie issued under the old key must still decode.
	got, err := cm2.Decode(cookie)
	if err != nil {
		t.Fatalf("Decode old cookie after rotation: %v", err)
	}
	if got != id {
		t.Fatalf("decoded id = %v, want %v", got, id)
	}

	// And a manager holding only the new key must NOT decode it — confirming
	// it is the ring, not chance, that keeps the old cookie valid.
	cmNew := NewCookieManagerFromKeys(keys2[:1], cfg, clk)
	if _, err := cmNew.Decode(cookie); err == nil {
		t.Fatalf("old cookie decoded under new key alone; ring isn't doing the work")
	}
}
