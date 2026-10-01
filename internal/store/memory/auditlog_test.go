package memory

import (
	"context"
	"testing"
	"time"

	"go-authserver/internal/domain"

	"github.com/google/uuid"
)

func TestAuditLog_ListByActor(t *testing.T) {
	ctx := context.Background()
	s := NewAuditLogStore()
	base := time.Unix(1700000000, 0)
	add := func(actor, action string, offset time.Duration) {
		if err := s.Store(ctx, &domain.AuditLog{ID: uuid.New(), Action: action, ActorUserID: actor, Timestamp: base.Add(offset)}); err != nil {
			t.Fatal(err)
		}
	}
	add("u-1", domain.AuditLoginSucceeded, 0)
	add("u-1", domain.AuditLoginSucceeded, 2*time.Minute)
	add("u-1", domain.AuditLoginSucceeded, time.Minute)
	add("u-1", "other_action", 5*time.Minute)
	add("u-2", domain.AuditLoginSucceeded, 9*time.Minute)

	got, err := s.ListByActor(ctx, "u-1", domain.AuditLoginSucceeded, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Timestamp.Equal(base.Add(2*time.Minute)) || !got[1].Timestamp.Equal(base.Add(time.Minute)) {
		t.Fatalf("ListByActor = %+v, want the two newest u-1 logins, newest first", got)
	}
}
