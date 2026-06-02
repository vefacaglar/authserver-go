package store

import (
	"context"

	"go-authserver/internal/domain"
)

// DataProtectionKeyStore persists the cookie data-protection key ring.
// Mirrors SigningKeyStore: GetActive returns the single key flagged active,
// GetAll returns every key (active + retired) so cookies signed under an
// older key still decode, and Store upserts by KeyID.
type DataProtectionKeyStore interface {
	GetActive(ctx context.Context) (*domain.DataProtectionKey, error)
	GetAll(ctx context.Context) ([]domain.DataProtectionKey, error)
	Store(ctx context.Context, k *domain.DataProtectionKey) error
}
