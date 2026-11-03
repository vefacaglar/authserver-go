package main

import (
	"context"
	"errors"
	"testing"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"
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
