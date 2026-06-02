package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// RFC 7636 §4.6 worked example. The server must accept this exact pair.
const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestVerifyS256_RFC7636Vector(t *testing.T) {
	if err := VerifyS256("S256", rfc7636Verifier, rfc7636Challenge); err != nil {
		t.Fatalf("VerifyS256 with RFC 7636 example: %v", err)
	}
}

func TestVerifyS256_RejectsWrongVerifier(t *testing.T) {
	// Single character changed in the verifier must fail.
	wrong := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"
	if err := VerifyS256("S256", wrong, rfc7636Challenge); err == nil {
		t.Fatalf("VerifyS256 accepted a wrong verifier")
	}
}

func TestVerifyS256_RejectsPlain(t *testing.T) {
	if err := VerifyS256("plain", rfc7636Verifier, rfc7636Challenge); err == nil {
		t.Fatalf("VerifyS256 accepted method=plain")
	}
}

func TestVerifyS256_RejectsOutOfRangeVerifier(t *testing.T) {
	short := strings.Repeat("a", minVerifierLen-1)
	long := strings.Repeat("a", maxVerifierLen+1)
	if err := VerifyS256("S256", short, rfc7636Challenge); err == nil {
		t.Errorf("VerifyS256 accepted short verifier")
	}
	if err := VerifyS256("S256", long, rfc7636Challenge); err == nil {
		t.Errorf("VerifyS256 accepted long verifier")
	}
}

func TestVerifyS256_RejectsEmptyChallenge(t *testing.T) {
	if err := VerifyS256("S256", rfc7636Verifier, ""); err == nil {
		t.Errorf("VerifyS256 accepted empty challenge")
	}
}

func TestVerifyS256_RoundTripFreshChallenge(t *testing.T) {
	// Generate a verifier, compute its challenge independently, and assert
	// VerifyS256 accepts the pair. This catches drift in the encoder
	// (RawURLEncoding vs std) that the RFC vector would not.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := VerifyS256("S256", verifier, challenge); err != nil {
		t.Fatalf("VerifyS256 round-trip: %v", err)
	}
}
