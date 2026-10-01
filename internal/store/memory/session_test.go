package memory

import (
	"context"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

func seedSession(t *testing.T, s *SessionStore, userID string, created time.Time, ttl time.Duration) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := s.Store(context.Background(), &domain.Session{ID: id, UserID: userID, CreatedAt: created, ExpiresAt: created.Add(ttl)}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSession_ListByUserID(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	now := time.Unix(1700000000, 0)

	older := seedSession(t, s, "u-1", now.Add(-2*time.Hour), 8*time.Hour)
	newer := seedSession(t, s, "u-1", now.Add(-time.Hour), 8*time.Hour)
	seedSession(t, s, "u-1", now.Add(-10*time.Hour), time.Hour) // expired
	seedSession(t, s, "u-2", now, time.Hour)                    // other user
	revoked := seedSession(t, s, "u-1", now, time.Hour)
	if err := s.Revoke(ctx, revoked, now); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListByUserID(ctx, "u-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != newer || got[1].ID != older {
		t.Fatalf("ListByUserID = %+v, want [newer, older]", got)
	}
}

func TestSession_RevokeByUserIDExcept(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	now := time.Unix(1700000000, 0)

	keep := seedSession(t, s, "u-1", now, time.Hour)
	a := seedSession(t, s, "u-1", now, time.Hour)
	b := seedSession(t, s, "u-1", now, time.Hour)
	other := seedSession(t, s, "u-2", now, time.Hour)

	revoked, err := s.RevokeByUserIDExcept(ctx, "u-1", keep, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked %d sessions, want 2", len(revoked))
	}
	for id, wantRevoked := range map[uuid.UUID]bool{keep: false, a: true, b: true, other: false} {
		sess, _ := s.Find(ctx, id)
		if (sess.RevokedAt != nil) != wantRevoked {
			t.Errorf("session %s revoked=%v, want %v", id, sess.RevokedAt != nil, wantRevoked)
		}
	}

	// Second call is a no-op: already-revoked sessions are not reported again.
	again, err := s.RevokeByUserIDExcept(ctx, "u-1", keep, now)
	if err != nil || len(again) != 0 {
		t.Fatalf("second call = %v, %v; want empty", again, err)
	}

	// uuid.Nil keeps nothing.
	all, err := s.RevokeByUserIDExcept(ctx, "u-1", uuid.Nil, now)
	if err != nil || len(all) != 1 {
		t.Fatalf("revoke-all = %v, %v; want only the kept session", all, err)
	}
}
