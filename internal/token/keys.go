package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	// RSAKeyBits is the only supported key size for v1.
	RSAKeyBits = 2048
	// DefaultAlgorithm is the only signing algorithm exposed in v1.
	DefaultAlgorithm = jwa.RS256
)

// KeyManager generates, persists, and converts signing keys.
type KeyManager struct {
	Keys  store.SigningKeyStore
	Clock clock.Clock
}

func NewKeyManager(keys store.SigningKeyStore, clk clock.Clock) *KeyManager {
	return &KeyManager{Keys: keys, Clock: clk}
}

// EnsureActiveKey returns the currently active signing key, bootstrapping
// one with a fresh RSA-2048 keypair if the store has no active key. Safe to
// call on every server start; only writes when no active key exists.
func (m *KeyManager) EnsureActiveKey(ctx context.Context) (*domain.SigningKey, error) {
	active, err := m.Keys.GetActive(ctx)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("keys: get active: %w", err)
	}
	return m.generateActive(ctx)
}

// Rotate generates a fresh active signing key and retires the current one.
// The retired key stays in the store (and in the published JWKS) so tokens
// signed with it remain verifiable until they expire; only new tokens use
// the new key. Intended to be run periodically by an operator via the
// `rotate-keys` command.
//
// The retire-then-create is two store writes rather than one transaction:
// run it from a single operator process (not concurrently), so the brief
// window is not a concern in practice. New signing happens with whichever
// key GetActive returns.
func (m *KeyManager) Rotate(ctx context.Context) (*domain.SigningKey, error) {
	active, err := m.Keys.GetActive(ctx)
	switch {
	case err == nil:
		now := m.Clock.Now().UTC()
		active.IsActive = false
		active.RetiredAt = &now
		if err := m.Keys.Store(ctx, active); err != nil {
			return nil, fmt.Errorf("keys: retire active: %w", err)
		}
	case errors.Is(err, store.ErrNotFound):
		// Nothing to retire; this becomes the first key.
	default:
		return nil, fmt.Errorf("keys: get active: %w", err)
	}
	return m.generateActive(ctx)
}

// generateActive creates a fresh RSA keypair, stores it as the active key,
// and returns it. Shared by EnsureActiveKey (bootstrap) and Rotate.
func (m *KeyManager) generateActive(ctx context.Context) (*domain.SigningKey, error) {
	priv, err := GenerateRSAKey(RSAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("keys: generate: %w", err)
	}
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: encode private: %w", err)
	}
	pubPEM, err := PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: encode public: %w", err)
	}
	k := &domain.SigningKey{
		KeyID:         uuid.NewString(),
		Algorithm:     string(DefaultAlgorithm),
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		CreatedAt:     m.Clock.Now().UTC(),
		IsActive:      true,
	}
	if err := m.Keys.Store(ctx, k); err != nil {
		return nil, fmt.Errorf("keys: store: %w", err)
	}
	return k, nil
}

// PrivateJWK returns the active signing key as a private jwk.Key with kid
// and alg metadata populated, ready for jwt signing.
func (m *KeyManager) PrivateJWK(ctx context.Context) (jwk.Key, *domain.SigningKey, error) {
	k, err := m.EnsureActiveKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	priv, err := PrivateKeyFromPEM(k.PrivateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: decode private: %w", err)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: jwk from raw: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, k.KeyID); err != nil {
		return nil, nil, fmt.Errorf("keys: set kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, k.Algorithm); err != nil {
		return nil, nil, fmt.Errorf("keys: set alg: %w", err)
	}
	return key, k, nil
}

// PublicJWKSet returns a jwk.Set containing the public side of every
// signing key the store knows about (active + retired). Private material
// is never serialised into the set.
func (m *KeyManager) PublicJWKSet(ctx context.Context) (jwk.Set, error) {
	all, err := m.Keys.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("keys: get all: %w", err)
	}
	set := jwk.NewSet()
	for i := range all {
		k := all[i]
		pub, err := PublicKeyFromPEM(k.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("keys: decode public %s: %w", k.KeyID, err)
		}
		key, err := jwk.FromRaw(pub)
		if err != nil {
			return nil, fmt.Errorf("keys: jwk from raw %s: %w", k.KeyID, err)
		}
		if err := key.Set(jwk.KeyIDKey, k.KeyID); err != nil {
			return nil, fmt.Errorf("keys: set kid %s: %w", k.KeyID, err)
		}
		if err := key.Set(jwk.AlgorithmKey, k.Algorithm); err != nil {
			return nil, fmt.Errorf("keys: set alg %s: %w", k.KeyID, err)
		}
		if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return nil, fmt.Errorf("keys: set use %s: %w", k.KeyID, err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("keys: add to set %s: %w", k.KeyID, err)
		}
	}
	return set, nil
}

// GenerateRSAKey returns a freshly generated RSA private key of the given
// size in bits. Uses crypto/rand.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("keys: refusing to generate RSA key smaller than 2048 bits (got %d)", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("keys: rsa generate: %w", err)
	}
	return priv, nil
}

// PrivateKeyToPEM encodes an RSA private key as a PKCS#8 PEM string.
func PrivateKeyToPEM(priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", errors.New("keys: nil private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("keys: marshal private: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// PublicKeyToPEM encodes an RSA public key as a SubjectPublicKeyInfo PEM string.
func PublicKeyToPEM(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("keys: nil public key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("keys: marshal public: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// PrivateKeyFromPEM decodes a PKCS#8 PEM-encoded RSA private key.
func PrivateKeyFromPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private: %w", err)
	}
	priv, ok := raw.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: not an RSA private key (got %T)", raw)
	}
	return priv, nil
}

// PublicKeyFromPEM decodes a SubjectPublicKeyInfo PEM-encoded RSA public key.
func PublicKeyFromPEM(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse public: %w", err)
	}
	pub, ok := raw.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keys: not an RSA public key (got %T)", raw)
	}
	return pub, nil
}
