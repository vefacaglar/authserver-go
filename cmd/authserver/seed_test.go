package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/store/gormstore"
	"go-authserver/internal/store/memory"
)

func TestSeedDisabledPreservesProductionData(t *testing.T) {
	ctx := context.Background()
	b := &storeBundle{
		Clients: memory.NewClientStore(),
		Scopes:  memory.NewScopeStore(),
		Users:   memory.NewUserStore(),
		Roles:   memory.NewRoleStore(),
	}
	client := &domain.Client{ClientID: "demo-public", DisplayName: "Customized client"}
	if err := b.Clients.Store(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := seedBundle(b, false); err != nil {
		t.Fatal(err)
	}
	got, err := b.Clients.FindByClientID(ctx, client.ClientID)
	if err != nil || got.DisplayName != client.DisplayName {
		t.Fatalf("existing client was changed: %v", err)
	}
	if _, err := b.Clients.FindByClientID(ctx, "demo-confidential"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unexpected demo client: %v", err)
	}
	if _, err := b.Users.FindByID(ctx, "u-demo"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unexpected demo user: %v", err)
	}
}

func newSeedTestBundle(t *testing.T, backend string) *storeBundle {
	t.Helper()
	if backend == "memory" {
		return &storeBundle{
			Clients: memory.NewClientStore(), Scopes: memory.NewScopeStore(),
			Users: memory.NewUserStore(), Roles: memory.NewRoleStore(),
		}
	}
	db, err := gormstore.Open("sqlite", filepath.Join(t.TempDir(), "seed.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := gormstore.Migrate(db); err != nil {
		t.Fatal(err)
	}
	return newGormBundle(db, clock.SystemClock{}.Now)
}

// Use maps so store pagination order cannot hide or invent a seed mutation.
func seedSnapshot(t *testing.T, b *storeBundle) map[string]any {
	t.Helper()
	ctx := context.Background()
	page := domain.PagedRequest{Page: 1, PageSize: 100}
	users, err := b.Users.GetPagedUsers(ctx, page)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := b.Clients.GetPaged(ctx, page)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := b.Scopes.GetAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	roles, err := b.Roles.GetAllRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]any)
	for _, user := range users.Items {
		result["user:"+user.ID] = user
	}
	for _, client := range clients.Items {
		result["client:"+client.ClientID] = client
	}
	for _, scope := range scopes {
		result["scope:"+scope.Name] = scope
	}
	for _, role := range roles {
		result["role:"+role.ID] = role
	}
	return result
}

func TestSeedSkipsAnyExistingData(t *testing.T) {
	ctx := context.Background()
	fixtures := map[string]func(*storeBundle) error{
		"user only": func(b *storeBundle) error {
			return b.Users.CreateUser(ctx, &domain.User{ID: "existing-user", Username: "operator", Email: "operator@example.test"}, "existing-password")
		},
		"client only": func(b *storeBundle) error {
			return b.Clients.Store(ctx, &domain.Client{ClientID: "existing-client", DisplayName: "Existing client"})
		},
		"scope only": func(b *storeBundle) error {
			return b.Scopes.Store(ctx, &domain.Scope{Name: "existing-scope"})
		},
		"role only": func(b *storeBundle) error {
			return b.Roles.CreateRole(ctx, &domain.Role{ID: "existing-role", Name: "operator"})
		},
	}
	for _, backend := range []string{"memory", "gorm"} {
		for name, create := range fixtures {
			t.Run(backend+"/"+name, func(t *testing.T) {
				b := newSeedTestBundle(t, backend)
				if err := create(b); err != nil {
					t.Fatal(err)
				}
				before := seedSnapshot(t, b)
				if err := seedBundle(b, true); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, seedSnapshot(t, b)) {
					t.Fatal("seed changed a populated database")
				}
			})
		}
	}
}

func TestSeedRestartPreservesEditsAndDeletedDemoUser(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{"memory", "gorm"} {
		t.Run(backend, func(t *testing.T) {
			b := newSeedTestBundle(t, backend)
			if err := seedBundle(b, true); err != nil {
				t.Fatal(err)
			}
			if err := b.Users.DeleteUser(ctx, "u-demo"); err != nil {
				t.Fatal(err)
			}
			if err := b.Clients.Store(ctx, &domain.Client{ClientID: "demo-public", DisplayName: "Operator customization"}); err != nil {
				t.Fatal(err)
			}
			before := seedSnapshot(t, b)
			if err := seedBundle(b, true); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, seedSnapshot(t, b)) {
				t.Fatal("restart changed demo keys, overwrote edits, or recreated deleted fixtures")
			}
		})
	}
}

func TestSeedEnabledSkipsWhenDataExists(t *testing.T) {
	ctx := context.Background()
	b := &storeBundle{
		Clients: memory.NewClientStore(),
		Scopes:  memory.NewScopeStore(),
		Users:   memory.NewUserStore(),
		Roles:   memory.NewRoleStore(),
	}
	client := &domain.Client{ClientID: "demo-public", DisplayName: "Customized client"}
	if err := b.Clients.Store(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := seedBundle(b, true); err != nil {
		t.Fatal(err)
	}
	got, err := b.Clients.FindByClientID(ctx, client.ClientID)
	if err != nil || got.DisplayName != client.DisplayName {
		t.Fatalf("existing client was changed: %v", err)
	}
	if _, err := b.Clients.FindByClientID(ctx, "demo-confidential"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unexpected demo client: %v", err)
	}
	if _, err := b.Users.FindByID(ctx, "u-demo"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unexpected demo user: %v", err)
	}
	if _, err := b.Scopes.FindByName(ctx, "openid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unexpected seeded scope: %v", err)
	}
}

func TestSeedEnabledCreatesDemoFixtures(t *testing.T) {
	b := &storeBundle{
		Clients: memory.NewClientStore(),
		Scopes:  memory.NewScopeStore(),
		Users:   memory.NewUserStore(),
		Roles:   memory.NewRoleStore(),
	}
	if err := seedBundle(b, true); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.Users.FindByID(ctx, "u-demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Clients.FindByClientID(ctx, "demo-public"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Scopes.FindByName(ctx, "openid"); err != nil {
		t.Fatal(err)
	}
}
