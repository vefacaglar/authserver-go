package memory

import (
	"context"
	"sort"
	"testing"

	"go-authserver/internal/domain"
)

func TestScopeStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	s := NewScopeStore()

	sc := &domain.Scope{
		Name:        "openid",
		DisplayName: "OpenID",
		Description: "Verify your identity",
		Required:    true,
		Emphasize:   true,
	}
	if err := s.Store(ctx, sc); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := s.FindByName(ctx, "openid")
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if got.DisplayName != "OpenID" || !got.Required || !got.Emphasize {
		t.Errorf("FindByName returned %+v, want Required+Emphasize OpenID", got)
	}

	if _, err := s.FindByName(ctx, "missing"); err == nil {
		t.Errorf("FindByName(missing) expected error, got nil")
	}
}

func TestScopeStore_GetAll_PreservesInsertionOrder(t *testing.T) {
	ctx := context.Background()
	s := NewScopeStore()
	names := []string{"openid", "profile", "email", "offline_access"}
	for _, n := range names {
		_ = s.Store(ctx, &domain.Scope{Name: n})
	}
	all, err := s.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	gotNames := make([]string, 0, len(all))
	for _, sc := range all {
		gotNames = append(gotNames, sc.Name)
	}
	want := append([]string(nil), names...)
	sort.Strings(want)
	sort.Strings(gotNames)
	for i := range want {
		if want[i] != gotNames[i] {
			t.Errorf("GetAll order: got %v, want sorted %v", gotNames, want)
			break
		}
	}
}

func TestScopeStore_Delete(t *testing.T) {
	ctx := context.Background()
	s := NewScopeStore()
	_ = s.Store(ctx, &domain.Scope{Name: "openid"})

	if err := s.Delete(ctx, "openid"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.FindByName(ctx, "openid"); err == nil {
		t.Errorf("FindByName after Delete: expected error, got nil")
	}
	if err := s.Delete(ctx, "openid"); err == nil {
		t.Errorf("Delete(missing) expected error, got nil")
	}
}
