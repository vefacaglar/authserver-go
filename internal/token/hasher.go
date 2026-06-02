// Package token contains the cryptographic primitives used by the auth
// server: opaque token generation, token hashing, PKCE verification, signing
// key lifecycle, and JWT issuance for access and ID tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// OpaqueTokenBytes is the number of random bytes used to mint an opaque
// token. 32 bytes (256 bits) matches the entropy recommended by RFC 6749
// for high-value bearer tokens.
const OpaqueTokenBytes = 32

// HashToken returns the base64url-encoded SHA-256 of the input. Tokens are
// stored on the server only as their hash; the raw value is given to the
// client exactly once and never recoverable from the database.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewOpaqueToken returns a freshly generated opaque token string and its
// SHA-256 hash. The caller hands the raw value to the client and stores the
// hash in the refresh-token / authorization-code store.
func NewOpaqueToken() (raw string, hash string, err error) {
	b := make([]byte, OpaqueTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("token: read random: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw), nil
}

// HashAccessToken returns the at_hash claim value for an access token issued
// with the RS256 family: base64url(leftmost SHA-256(access_token) / 2).
// RFC 7515 §5.1 (and OIDC Core §2) require this exact construction for
// asymmetric algorithms.
func HashAccessToken(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
