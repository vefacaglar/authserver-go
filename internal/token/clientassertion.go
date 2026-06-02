package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-authserver/internal/clock"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ClientAssertionType is the IANA-registered value that
// client_assertion_type MUST take for a private_key_jwt assertion.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAssertionClaims is the projection of the verified assertion
// the rest of the server is allowed to read. We do not surface the
// raw token anywhere; only the fields the token endpoint uses.
type ClientAssertionClaims struct {
	Issuer   string
	Subject  string
	Audience []string
	JTI      string
	Exp      time.Time
	IssuedAt time.Time
}

// ClientAssertionParams carries every input VerifyClientAssertion
// needs. Keeping them in a struct keeps the call site stable as the
// verification rules grow.
type ClientAssertionParams struct {
	// Assertion is the raw JWT string from client_assertion.
	Assertion string
	// JWKSJSON is the public JWK Set registered on the client.
	// v1 only supports inline JWKS; remote jwks_uri fetching is out
	// of scope per BUILD_PROMPT.md.
	JWKSJSON string
	// ExpectedIssuer / ExpectedSubject are the values the assertion's
	// iss/sub MUST match. For private_key_jwt both equal the
	// client_id.
	ExpectedIssuer  string
	ExpectedSubject string
	// Audience is the set of values the assertion's aud claim must
	// contain at least one of. Typically {issuer, token endpoint}.
	Audience []string
	// Skew is the acceptable clock skew applied to exp/nbf checks.
	Skew time.Duration
	// Cache records used jti values so a replayed assertion is
	// rejected even if every other claim is still valid.
	Cache ClientAssertionCache
	// Clock drives time-based checks so tests can use a fake clock.
	Clock clock.Clock
}

// ClientAssertionCache is the abstraction the verifier uses to
// remember jti values. The in-memory implementation in this file is
// the default; production deployments can swap in a distributed cache
// without changing the verifier.
type ClientAssertionCache interface {
	// CheckAndStore returns true if the (clientID, jti) pair has not
	// been seen before. On true, the pair is now recorded with the
	// given expiry so the cache can GC stale entries.
	CheckAndStore(clientID, jti string, exp time.Time) (bool, error)
}

// MemAssertionCache is the default in-memory ClientAssertionCache.
// Keys are "clientID|jwt" so a jti collision across two different
// clients does not generate a false positive. Entries whose exp has
// elapsed are evicted lazily on every CheckAndStore.
type MemAssertionCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemAssertionCache returns a cache clocked by the supplied now
// function (pass clock.Clock.Now in production).
func NewMemAssertionCache(now func() time.Time) *MemAssertionCache {
	return &MemAssertionCache{seen: make(map[string]time.Time), now: now}
}

// CheckAndStore implements ClientAssertionCache.
func (c *MemAssertionCache) CheckAndStore(clientID, jti string, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// Lazy GC: drop expired entries before the lookup.
	for k, t := range c.seen {
		if t.Before(now) {
			delete(c.seen, k)
		}
	}
	key := clientID + "|" + jti
	if _, exists := c.seen[key]; exists {
		return false, nil
	}
	c.seen[key] = exp
	return true, nil
}

// VerifyClientAssertion is the single entry point used by the
// token-endpoint client-auth path. It enforces every rule from
// BUILD_PROMPT.md §"clientassertion.go":
//
//   - asymmetric algorithm only (rejects none / HMAC)
//   - signature verified against the client's inline JWKS
//   - iss == sub == client_id
//   - aud ∈ accepted audiences
//   - exp present and within Skew
//   - jti present and unseen (per (client, jti))
//
// On any failure it returns an opaque error; the caller is expected
// to surface an invalid_client body to the wire and log the precise
// reason server-side only.
func VerifyClientAssertion(ctx context.Context, p ClientAssertionParams) (*ClientAssertionClaims, error) {
	if p.Assertion == "" {
		return nil, errors.New("client assertion: empty")
	}
	if p.JWKSJSON == "" {
		return nil, errors.New("client assertion: client has no registered JWKS")
	}
	if p.ExpectedIssuer == "" || p.ExpectedSubject == "" {
		return nil, errors.New("client assertion: expected issuer/subject required")
	}
	if p.Cache == nil {
		return nil, errors.New("client assertion: replay cache not configured")
	}
	if p.Clock == nil {
		return nil, errors.New("client assertion: clock not configured")
	}

	set, err := jwk.ParseString(p.JWKSJSON)
	if err != nil {
		return nil, fmt.Errorf("client assertion: parse jwks: %w", err)
	}
	if set.Len() == 0 {
		return nil, errors.New("client assertion: jwks is empty")
	}

	// Parse the JWS envelope first so we can inspect the alg header
	// BEFORE the signature is checked. jwx's jwt.Parse with a key
	// set would also reject HMAC against RSA keys, but the error
	// would be a generic "no key found" — not as useful for an
	// admin log. Doing the alg check up front gives us a clear
	// "rejected: alg HS256 is not asymmetric" message.
	msg, err := jws.Parse([]byte(p.Assertion))
	if err != nil {
		return nil, fmt.Errorf("client assertion: parse jws: %w", err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, errors.New("client assertion: no signature")
	}
	sig := msg.Signatures()[0]
	hdr := sig.ProtectedHeaders()
	if hdr == nil {
		return nil, errors.New("client assertion: missing protected headers")
	}
	alg := hdr.Algorithm()
	if alg.String() == "" {
		return nil, errors.New("client assertion: missing alg header")
	}
	if !isAsymmetricAlg(alg) {
		return nil, fmt.Errorf("client assertion: alg %q is not asymmetric", alg)
	}

	// Parse the token with a key set so the signature is verified.
	// We deliberately do NOT pass WithIssuer/WithSubject/WithAudience
	// here: we want the verifier to succeed for shape, and then
	// cross-check the claims ourselves so the error messages can
	// name the specific failure.
	tok, err := jwt.Parse([]byte(p.Assertion),
		jwt.WithKeySet(set),
		jwt.WithClock(clockFunc{p.Clock}),
		jwt.WithAcceptableSkew(p.Skew),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("client assertion: parse: %w", err)
	}

	// Claims: iss, sub, aud, exp, jti.
	if iss := tok.Issuer(); iss != p.ExpectedIssuer {
		return nil, fmt.Errorf("client assertion: iss %q does not match expected %q", iss, p.ExpectedIssuer)
	}
	if sub := tok.Subject(); sub != p.ExpectedSubject {
		return nil, fmt.Errorf("client assertion: sub %q does not match expected %q", sub, p.ExpectedSubject)
	}
	aud := tok.Audience()
	if len(aud) == 0 {
		return nil, errors.New("client assertion: aud claim is empty")
	}
	if !anyAudienceMatch(aud, p.Audience) {
		return nil, fmt.Errorf("client assertion: aud %v does not include any of %v", aud, p.Audience)
	}
	exp := tok.Expiration()
	if exp.IsZero() {
		return nil, errors.New("client assertion: exp claim is required")
	}
	jti := tok.JwtID()
	if jti == "" {
		return nil, errors.New("client assertion: jti claim is required")
	}

	// Replay check is the very last step: only after every other
	// claim has been confirmed do we burn a jti, so a forged
	// assertion with a guessed jti does not pollute the cache.
	fresh, err := p.Cache.CheckAndStore(p.ExpectedIssuer, jti, exp)
	if err != nil {
		return nil, fmt.Errorf("client assertion: cache: %w", err)
	}
	if !fresh {
		return nil, errors.New("client assertion: jti already used")
	}

	return &ClientAssertionClaims{
		Issuer:   tok.Issuer(),
		Subject:  tok.Subject(),
		Audience: aud,
		JTI:      jti,
		Exp:      exp,
		IssuedAt: tok.IssuedAt(),
	}, nil
}

// isAsymmetricAlg returns true for the signature algorithms the
// server is willing to accept. HS* and none are intentionally
// excluded: an HS256 token could be forged if the verifier treated
// the client's public key as an HMAC secret.
func isAsymmetricAlg(alg jwa.SignatureAlgorithm) bool {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.EdDSA:
		return true
	}
	return false
}

// anyAudienceMatch returns true if the token's aud list contains at
// least one value the server accepts. RFC 7519 §4.1.3 says aud may
// be a string or an array; jwx exposes Audience() as []string, which
// collapses both.
func anyAudienceMatch(tokenAud, accepted []string) bool {
	if len(accepted) == 0 {
		return true
	}
	for _, t := range tokenAud {
		for _, a := range accepted {
			if equalAudience(t, a) {
				return true
			}
		}
	}
	return false
}

// equalAudience compares two aud values loosely. The spec is
// case-sensitive on the value, but a defensive lower-case compare
// shields us from a misconfigured client that sends the issuer in a
// different case than the server registered.
func equalAudience(a, b string) bool {
	return strings.EqualFold(a, b)
}
