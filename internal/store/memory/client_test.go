package memory

import (
	"context"
	"testing"
	"time"

	"go-authserver/internal/domain"
)

func TestClientStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	s := NewClientStore()

	c := &domain.Client{
		ClientID:                   "client-a",
		DisplayName:                "Example Client",
		RedirectURIs:               []string{"https://app.example/cb"},
		AllowedScopes:              []string{"openid", "profile"},
		RequirePKCE:                true,
		AllowRefreshTokens:         true,
		TokenEndpointAuthMethod:    domain.TokenEndpointAuthMethodNone,
		AccessTokenLifetimeSeconds: 3600,
		Properties:                 map[string]string{"tier": "free"},
	}
	if err := s.Store(ctx, c); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := s.FindByClientID(ctx, "client-a")
	if err != nil {
		t.Fatalf("FindByClientID: %v", err)
	}
	if got.ClientID != c.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, c.ClientID)
	}
	if got.DisplayName != c.DisplayName {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, c.DisplayName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != c.RedirectURIs[0] {
		t.Errorf("RedirectURIs = %v, want %v", got.RedirectURIs, c.RedirectURIs)
	}
	if !got.RequirePKCE {
		t.Errorf("RequirePKCE = false, want true")
	}
	if !got.AllowRefreshTokens {
		t.Errorf("AllowRefreshTokens = false, want true")
	}
	if got.Properties["tier"] != "free" {
		t.Errorf("Properties[tier] = %q, want %q", got.Properties["tier"], "free")
	}

	// Mutating the returned pointer must not affect the store.
	got.DisplayName = "mutated"
	got2, _ := s.FindByClientID(ctx, "client-a")
	if got2.DisplayName == "mutated" {
		t.Errorf("FindByClientID returned a pointer aliased to the internal map")
	}

	if _, err := s.FindByClientID(ctx, "missing"); err == nil {
		t.Errorf("FindByClientID(missing) expected error, got nil")
	}
}

func TestClientStore_GetPaged(t *testing.T) {
	ctx := context.Background()
	s := NewClientStore()
	for i := 0; i < 5; i++ {
		_ = s.Store(ctx, &domain.Client{ClientID: idFromInt(i)})
	}

	page, err := s.GetPaged(ctx, domain.PagedRequest{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("GetPaged: %v", err)
	}
	if page.TotalCount != 5 {
		t.Errorf("TotalCount = %d, want 5", page.TotalCount)
	}
	if len(page.Items) != 2 {
		t.Errorf("len(Items) = %d, want 2", len(page.Items))
	}
}

func TestClientStore_Delete(t *testing.T) {
	ctx := context.Background()
	s := NewClientStore()
	_ = s.Store(ctx, &domain.Client{ClientID: "x"})
	if err := s.Delete(ctx, "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.FindByClientID(ctx, "x"); err == nil {
		t.Errorf("FindByClientID after Delete: expected error, got nil")
	}
	if err := s.Delete(ctx, "x"); err == nil {
		t.Errorf("Delete(missing) expected error, got nil")
	}
}

func idFromInt(i int) string {
	return "client-" + time.Unix(int64(i), 0).Format("150405")
}
