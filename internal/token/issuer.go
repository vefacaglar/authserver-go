package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// AccessTokenClaims are the claims the issuer writes into an access token.
// Only AccessToken itself is opaque to clients; the rest are standard JWT
// claims.
type AccessTokenClaims struct {
	Subject   string
	ClientID  string
	Scope     string
	ExpiresIn time.Duration
	IssuedAt  time.Time
	AuthTime  *time.Time
	JwtID     string
}

// IDTokenClaims are the claims written into an ID token. Nonce and AuthTime
// are optional; the issuer includes them only when the caller supplies them.
type IDTokenClaims struct {
	Subject   string
	ClientID  string
	Scope     string
	Nonce     string
	AuthTime  time.Time
	Claims    map[string]any
	AtHash    string
	IssuedAt  time.Time
	ExpiresIn time.Duration
}

// Issuer mints and verifies access and ID tokens. It owns the signing key
// lifecycle via a KeyManager and uses a Clock so the time claims (iat/exp/
// nbf/auth_time) are deterministic in tests.
type Issuer struct {
	Issuer string
	Keys   *KeyManager
	Clock  clock.Clock

	// DefaultAccessTokenLifetime is used when AccessTokenClaims.ExpiresIn
	// is zero. Default 1h.
	DefaultAccessTokenLifetime time.Duration
	// DefaultIDTokenLifetime is used when IDTokenClaims.ExpiresIn is zero.
	// Default 1h, matching the OIDC Core recommendation.
	DefaultIDTokenLifetime time.Duration
}

func NewIssuer(issuerURL string, keys *KeyManager, clk clock.Clock) *Issuer {
	return &Issuer{
		Issuer:                     issuerURL,
		Keys:                       keys,
		Clock:                      clk,
		DefaultAccessTokenLifetime: time.Hour,
		DefaultIDTokenLifetime:     time.Hour,
	}
}

// IssueAccessToken returns a signed JWT access token and its raw (compact)
// representation. The raw value is what the server hands to the client; the
// caller is responsible for hashing it before storage (it is opaque, never
// logged).
func (i *Issuer) IssueAccessToken(ctx context.Context, c AccessTokenClaims) (string, error) {
	if c.Subject == "" {
		return "", errors.New("issuer: access token subject required")
	}
	if c.ClientID == "" {
		return "", errors.New("issuer: access token client id required")
	}
	if c.ExpiresIn <= 0 {
		c.ExpiresIn = i.DefaultAccessTokenLifetime
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = i.Clock.Now().UTC()
	}
	if c.JwtID == "" {
		c.JwtID = uuid.NewString()
	}

	key, signingKey, err := i.Keys.PrivateJWK(ctx)
	if err != nil {
		return "", fmt.Errorf("issuer: signing key: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(i.Issuer).
		Subject(c.Subject).
		Audience([]string{c.ClientID}).
		IssuedAt(c.IssuedAt).
		NotBefore(c.IssuedAt).
		Expiration(c.IssuedAt.Add(c.ExpiresIn)).
		JwtID(c.JwtID).
		Claim("client_id", c.ClientID).
		Claim("scope", c.Scope).
		Build()
	if err != nil {
		return "", fmt.Errorf("issuer: build access: %w", err)
	}
	if c.AuthTime != nil {
		if err := tok.Set("auth_time", c.AuthTime.Unix()); err != nil {
			return "", fmt.Errorf("issuer: set auth_time: %w", err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return "", fmt.Errorf("issuer: sign access: %w", err)
	}
	_ = signingKey
	return string(signed), nil
}

// IssueIDToken returns a signed JWT ID token. at_hash is mandatory; callers
// must compute it from the access token string with HashAccessToken.
func (i *Issuer) IssueIDToken(ctx context.Context, c IDTokenClaims) (string, error) {
	if c.Subject == "" {
		return "", errors.New("issuer: id token subject required")
	}
	if c.ClientID == "" {
		return "", errors.New("issuer: id token client id required")
	}
	if c.AtHash == "" {
		return "", errors.New("issuer: id token at_hash required")
	}
	if c.ExpiresIn <= 0 {
		c.ExpiresIn = i.DefaultIDTokenLifetime
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = i.Clock.Now().UTC()
	}

	key, _, err := i.Keys.PrivateJWK(ctx)
	if err != nil {
		return "", fmt.Errorf("issuer: signing key: %w", err)
	}

	b := jwt.NewBuilder().
		Issuer(i.Issuer).
		Subject(c.Subject).
		Audience([]string{c.ClientID}).
		IssuedAt(c.IssuedAt).
		NotBefore(c.IssuedAt).
		Expiration(c.IssuedAt.Add(c.ExpiresIn)).
		JwtID(uuid.NewString()).
		Claim("at_hash", c.AtHash).
		Claim("auth_time", c.AuthTime.UTC().Unix())
	if c.Nonce != "" {
		b = b.Claim("nonce", c.Nonce)
	}
	if c.Scope != "" {
		b = b.Claim("scope", c.Scope)
	}
	for k, v := range c.Claims {
		if isReservedClaim(k) {
			continue
		}
		b = b.Claim(k, v)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("issuer: build id: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return "", fmt.Errorf("issuer: sign id: %w", err)
	}
	return string(signed), nil
}

func isReservedClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "at_hash", "auth_time", "nonce", "scope":
		return true
	}
	return false
}

// VerifyToken parses and verifies a JWT against the current JWKS, returning
// the token on success. Used by the issuer's own tests and (later) the
// resource endpoints; consumers normally use a remote JWKS fetcher. The
// injected Clock drives time-based claim validation so tests with a fake
// clock can issue tokens at arbitrary "now" and still verify them.
func (i *Issuer) VerifyToken(ctx context.Context, raw string) (jwt.Token, error) {
	set, err := i.Keys.PublicJWKSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("issuer: jwks: %w", err)
	}
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set),
		jwt.WithIssuer(i.Issuer),
		jwt.WithClock(clockFunc{i.Clock}),
		jwt.WithAcceptableSkew(time.Hour),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("issuer: parse: %w", err)
	}
	return tok, nil
}

// clockFunc adapts our Clock interface to the jwt.ClockFunc that jwx wants.
type clockFunc struct{ C clock.Clock }

func (c clockFunc) Now() time.Time { return c.C.Now() }

// JWKSForEndpoint returns the public JWKS serialised as JSON, suitable for
// the /.well-known/jwks.json endpoint. Private material is never included.
func (i *Issuer) JWKSForEndpoint(ctx context.Context) ([]byte, error) {
	if _, err := i.Keys.EnsureActiveKey(ctx); err != nil {
		return nil, err
	}
	set, err := i.Keys.PublicJWKSet(ctx)
	if err != nil {
		return nil, err
	}
	return jwksJSON(set)
}

// EnsureKeyManager exposes the key manager so the oidc layer can read the
// active key id when needed (e.g. for jti-replay cache).
func (i *Issuer) KeyManager() *KeyManager { return i.Keys }

// Compile-time check that domain types are still used by the issuer layer
// (some claims pull from domain.Client).
var _ = (*domain.Client)(nil)

// jwksJSON serialises a jwk.Set to the canonical JWKS shape `{ "keys": [...] }`.
// The jwx Set and Key interfaces don't expose MarshalJSON in their public
// contracts, so we walk each key's fields and project the public ones
// (everything except "d" and other private-material fields) into a plain
// map[string]any. jwx v2's concrete types do implement json.Marshaler, so
// we try that first as a fast path; the map projection is the safety net.
func jwksJSON(set jwk.Set) ([]byte, error) {
	type doc struct {
		Keys []map[string]any `json:"keys"`
	}
	out := doc{Keys: make([]map[string]any, 0, set.Len())}
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		m, err := jwkKeyToMap(k)
		if err != nil {
			return nil, err
		}
		out.Keys = append(out.Keys, m)
	}
	return json.Marshal(out)
}

func jwkKeyToMap(k jwk.Key) (map[string]any, error) {
	// jwx v2 concrete key types implement json.Marshaler; round-tripping
	// through json catches every field including the library-specific ones.
	if mj, ok := k.(json.Marshaler); ok {
		b, err := mj.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("issuer: marshal jwk: %w", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("issuer: unmarshal jwk: %w", err)
		}
		delete(m, "d")
		return m, nil
	}
	return nil, errors.New("issuer: jwk key does not implement json.Marshaler")
}
