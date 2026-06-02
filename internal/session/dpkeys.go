package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// dpKeyBytes is the length of each generated key. 32 bytes gives a strong
// HMAC key, an AES-256 block key, and a 256-bit CSRF key.
const dpKeyBytes = 32

// DPKeyManager generates, persists, and serves the cookie data-protection
// key ring. It is the cookie-side analogue of token.KeyManager: the key
// material lives in the store (shared across instances, durable across
// restarts) instead of in static configuration.
type DPKeyManager struct {
	Keys  store.DataProtectionKeyStore
	Clock clock.Clock
}

func NewDPKeyManager(keys store.DataProtectionKeyStore, clk clock.Clock) *DPKeyManager {
	return &DPKeyManager{Keys: keys, Clock: clk}
}

// EnsureActiveKey returns the active key, bootstrapping a fresh one if the
// ring is empty. Safe to call on every boot; only writes when there is no
// active key.
func (m *DPKeyManager) EnsureActiveKey(ctx context.Context) (*domain.DataProtectionKey, error) {
	active, err := m.Keys.GetActive(ctx)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("dpkeys: get active: %w", err)
	}
	return m.generateActive(ctx)
}

// Rotate generates a fresh active key and retires the current one. Retired
// keys stay in the ring so cookies signed under them keep decoding until
// they expire; only new cookies use the new key. Run periodically via the
// `rotate-dp-keys` command.
func (m *DPKeyManager) Rotate(ctx context.Context) (*domain.DataProtectionKey, error) {
	active, err := m.Keys.GetActive(ctx)
	switch {
	case err == nil:
		now := m.Clock.Now().UTC()
		active.IsActive = false
		active.RetiredAt = &now
		if err := m.Keys.Store(ctx, active); err != nil {
			return nil, fmt.Errorf("dpkeys: retire active: %w", err)
		}
	case errors.Is(err, store.ErrNotFound):
		// Nothing to retire; this becomes the first key.
	default:
		return nil, fmt.Errorf("dpkeys: get active: %w", err)
	}
	return m.generateActive(ctx)
}

// Keyset returns the ring ordered newest-first (active first) for building a
// CookieManager, along with the active key (whose CSRFKey drives CSRF).
func (m *DPKeyManager) Keyset(ctx context.Context) ([]DPKey, *domain.DataProtectionKey, error) {
	active, err := m.EnsureActiveKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	all, err := m.Keys.GetAll(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dpkeys: get all: %w", err)
	}
	// Active key first, then the rest in store order (newest-first).
	keys := []DPKey{{Hash: active.HashKey, Block: active.BlockKey}}
	for i := range all {
		if all[i].KeyID == active.KeyID {
			continue
		}
		keys = append(keys, DPKey{Hash: all[i].HashKey, Block: all[i].BlockKey})
	}
	return keys, active, nil
}

func (m *DPKeyManager) generateActive(ctx context.Context) (*domain.DataProtectionKey, error) {
	hash, err := randomBytes(dpKeyBytes)
	if err != nil {
		return nil, err
	}
	block, err := randomBytes(dpKeyBytes)
	if err != nil {
		return nil, err
	}
	csrf, err := randomBytes(dpKeyBytes)
	if err != nil {
		return nil, err
	}
	k := &domain.DataProtectionKey{
		KeyID:     uuid.NewString(),
		HashKey:   hash,
		BlockKey:  block,
		CSRFKey:   csrf,
		CreatedAt: m.Clock.Now().UTC(),
		IsActive:  true,
	}
	if err := m.Keys.Store(ctx, k); err != nil {
		return nil, fmt.Errorf("dpkeys: store: %w", err)
	}
	return k, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("dpkeys: rand: %w", err)
	}
	return b, nil
}
