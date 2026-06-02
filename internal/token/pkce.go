package token

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// PKCEMethod is the only code_challenge_method accepted by the server. The
// "plain" method is intentionally not implemented and not advertised in
// discovery: it has no security advantage over S256.
const PKCEMethod = "S256"

// PKCE challenge length bounds per RFC 7636 §4.2: 43–128 characters,
// base64url-no-padding alphabet, after decoding 32–96 octets.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

var (
	ErrPKCEInvalidMethod  = errors.New("pkce: unsupported code_challenge_method")
	ErrPKCEInvalidFormat  = errors.New("pkce: code_verifier format invalid")
	ErrPKCEChallengeEmpty = errors.New("pkce: code_challenge empty")
)

// VerifyS256 checks that the code_verifier matches the stored code_challenge
// for the S256 method. The comparison is constant-time. Any error from
// base64 decoding, hashing, or length checks causes a clean false return so
// the caller never has to distinguish "malformed verifier" from "wrong
// verifier" (which would otherwise enable a side channel).
func VerifyS256(method, verifier, challenge string) error {
	if method != PKCEMethod {
		return fmt.Errorf("%w: got %q", ErrPKCEInvalidMethod, method)
	}
	if challenge == "" {
		return ErrPKCEChallengeEmpty
	}
	if l := len(verifier); l < minVerifierLen || l > maxVerifierLen {
		return ErrPKCEInvalidFormat
	}
	sum := sha256.Sum256([]byte(verifier))
	derived := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) != 1 {
		return errors.New("pkce: verifier does not match challenge")
	}
	return nil
}
