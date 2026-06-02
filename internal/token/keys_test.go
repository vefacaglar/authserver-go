package token

import (
	"context"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/store/memory"
)

func TestRSAKeyGenerationAndPEMRoundTrip(t *testing.T) {
	priv, err := GenerateRSAKey(RSAKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	if priv.N.BitLen() != RSAKeyBits {
		t.Errorf("modulus bit length = %d, want %d", priv.N.BitLen(), RSAKeyBits)
	}

	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM: %v", err)
	}
	if privPEM == "" {
		t.Fatal("PrivateKeyToPEM returned empty")
	}
	decoded, err := PrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM: %v", err)
	}
	if decoded.N.Cmp(priv.N) != 0 || decoded.E != priv.E {
		t.Errorf("decoded private key does not match original")
	}

	pubPEM, err := PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM: %v", err)
	}
	pubDecoded, err := PublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM: %v", err)
	}
	if pubDecoded.N.Cmp(priv.PublicKey.N) != 0 || pubDecoded.E != priv.PublicKey.E {
		t.Errorf("decoded public key does not match original")
	}
}

func TestGenerateRSAKey_RejectsWeakSize(t *testing.T) {
	if _, err := GenerateRSAKey(1024); err == nil {
		t.Errorf("GenerateRSAKey(1024) succeeded; expected refusal")
	}
}

func TestKeyManager_EnsureActiveKey_Bootstraps(t *testing.T) {
	ctx := context.Background()
	keys := memory.NewSigningKeyStore()
	m := NewKeyManager(keys, clock.NewFakeClock(time.Unix(0, 0)))

	k, err := m.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}
	if !k.IsActive {
		t.Errorf("IsActive = false, want true")
	}
	if k.KeyID == "" {
		t.Errorf("KeyID empty")
	}
	if k.PrivateKeyPEM == "" || k.PublicKeyPEM == "" {
		t.Errorf("PEMs empty")
	}

	// Second call must reuse the same key, not generate a new one.
	k2, err := m.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey #2: %v", err)
	}
	if k2.KeyID != k.KeyID {
		t.Errorf("second EnsureActiveKey returned a different key: %s vs %s", k2.KeyID, k.KeyID)
	}
}

func TestKeyManager_PrivateJWK_HasKid(t *testing.T) {
	ctx := context.Background()
	m := NewKeyManager(memory.NewSigningKeyStore(), clock.NewFakeClock(time.Unix(0, 0)))
	k, err := m.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}

	jwkKey, stored, err := m.PrivateJWK(ctx)
	if err != nil {
		t.Fatalf("PrivateJWK: %v", err)
	}
	if stored.KeyID != k.KeyID {
		t.Errorf("PrivateJWK returned a different key than EnsureActiveKey")
	}
	if jwkKey.KeyID() != k.KeyID {
		t.Errorf("JWK kid = %q, want %q", jwkKey.KeyID(), k.KeyID)
	}
	if jwkKey.Algorithm().String() != string(DefaultAlgorithm) {
		t.Errorf("JWK alg = %q, want %q", jwkKey.Algorithm(), DefaultAlgorithm)
	}
}

func TestKeyManager_PublicJWKSet_ExcludesPrivateMaterial(t *testing.T) {
	ctx := context.Background()
	m := NewKeyManager(memory.NewSigningKeyStore(), clock.NewFakeClock(time.Unix(0, 0)))
	k, err := m.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}

	set, err := m.PublicJWKSet(ctx)
	if err != nil {
		t.Fatalf("PublicJWKSet: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("set length = %d, want 1", set.Len())
	}
	pub, _ := set.LookupKeyID(k.KeyID)
	if pub == nil {
		t.Fatalf("key %q missing from JWKS", k.KeyID)
	}
	if pub.KeyID() != k.KeyID {
		t.Errorf("kid mismatch")
	}
	if _, hasD := pub.Get("d"); hasD {
		t.Errorf("public JWK leaked the private exponent 'd'")
	}
}
