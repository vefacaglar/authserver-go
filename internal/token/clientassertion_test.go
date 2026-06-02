package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"go-authserver/internal/clock"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// newTestClientKeypair generates an RSA-2048 keypair and returns the
// private JWK (for signing) and the public JWK Set JSON (for the
// client record).
func newTestClientKeypair(t *testing.T, kid string) (jwk.Key, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatalf("add to set: %v", err)
	}
	jwksJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return privJWK, string(jwksJSON)
}

// mintAssertion signs a client assertion with the given private key.
// Returns the compact JWT. The issued-at time is taken from the
// supplied clock so tests using a FakeClock see a coherent timeline.
func mintAssertion(t *testing.T, priv jwk.Key, clientID, audience, jti string, exp time.Time, iat time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{audience}).
		IssuedAt(iat).
		Expiration(exp).
		JwtID(jti).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func newTestAssertionEnv(t *testing.T) (jwk.Key, string, *clock.FakeClock, *MemAssertionCache) {
	t.Helper()
	priv, jwks := newTestClientKeypair(t, "test-kid")
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	cache := NewMemAssertionCache(clk.Now)
	return priv, jwks, clk, cache
}

func TestVerifyClientAssertion_Valid(t *testing.T) {
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	raw := mintAssertion(t, priv, "client-1", "https://auth.example.com", uuid.NewString(), clk.Now().Add(time.Minute), clk.Now())

	claims, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Issuer != "client-1" {
		t.Errorf("iss = %q", claims.Issuer)
	}
	if claims.Subject != "client-1" {
		t.Errorf("sub = %q", claims.Subject)
	}
	if claims.JTI == "" {
		t.Errorf("jti empty")
	}
}

func TestVerifyClientAssertion_ForgedKey(t *testing.T) {
	_, jwks, clk, cache := newTestAssertionEnv(t)
	// Sign with a DIFFERENT key than the one registered in the JWKS.
	otherPriv, _ := newTestClientKeypair(t, "other-kid")
	raw := mintAssertion(t, otherPriv, "client-1", "https://auth.example.com", uuid.NewString(), clk.Now().Add(time.Minute), clk.Now())

	_, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Fatalf("forged key: expected error, got nil")
	}
}

func TestVerifyClientAssertion_ReplayedJTI(t *testing.T) {
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	jti := uuid.NewString()
	raw := mintAssertion(t, priv, "client-1", "https://auth.example.com", jti, clk.Now().Add(time.Minute), clk.Now())

	// First use: ok.
	if _, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Replay: same jti → reject.
	_, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Fatalf("replay: expected error, got nil")
	}
}

func TestVerifyClientAssertion_DifferentClientSameJTIOK(t *testing.T) {
	// The cache key is (clientID, jti). Two different clients using
	// the same jti value should not collide.
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	jti := uuid.NewString()

	// client-1 uses it.
	raw1 := mintAssertion(t, priv, "client-1", "https://auth.example.com", jti, clk.Now().Add(time.Minute), clk.Now())
	if _, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion: raw1, JWKSJSON: jwks, ExpectedIssuer: "client-1", ExpectedSubject: "client-1",
		Audience: []string{"https://auth.example.com"}, Skew: time.Minute, Cache: cache, Clock: clk,
	}); err != nil {
		t.Fatalf("client-1 first: %v", err)
	}

	// client-2 reuses the same jti → different cache key, must succeed.
	raw2 := mintAssertion(t, priv, "client-2", "https://auth.example.com", jti, clk.Now().Add(time.Minute), clk.Now())
	if _, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion: raw2, JWKSJSON: jwks, ExpectedIssuer: "client-2", ExpectedSubject: "client-2",
		Audience: []string{"https://auth.example.com"}, Skew: time.Minute, Cache: cache, Clock: clk,
	}); err != nil {
		t.Fatalf("client-2 with same jti: %v (expected OK because cache key includes clientID)", err)
	}
}

func TestVerifyClientAssertion_WrongIssuer(t *testing.T) {
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	raw := mintAssertion(t, priv, "client-1", "https://auth.example.com", uuid.NewString(), clk.Now().Add(time.Minute), clk.Now())
	_, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "different-client",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Errorf("expected wrong-issuer failure")
	}
}

func TestVerifyClientAssertion_WrongAudience(t *testing.T) {
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	raw := mintAssertion(t, priv, "client-1", "https://other.example.com", uuid.NewString(), clk.Now().Add(time.Minute), clk.Now())
	_, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Errorf("expected wrong-aud failure")
	}
}

func TestVerifyClientAssertion_Expired(t *testing.T) {
	priv, jwks, clk, cache := newTestAssertionEnv(t)
	raw := mintAssertion(t, priv, "client-1", "https://auth.example.com", uuid.NewString(), clk.Now().Add(-time.Minute), clk.Now())
	_, err := VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       raw,
		JWKSJSON:        jwks,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Errorf("expected expired-assertion failure")
	}
}

func TestVerifyClientAssertion_HMACRejected(t *testing.T) {
	// Forge a JWT with alg=HS256 using the public key as the HMAC
	// secret. The key here is that the verifier must REJECT this
	// without ever letting the HMAC code path run.
	_, jwksJSON, clk, cache := newTestAssertionEnv(t)

	// Build a public JWK to use as the HMAC "secret" — this is the
	// classic alg-confusion attack vector.
	pubSet, err := jwk.ParseString(jwksJSON)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	pubKey, _ := pubSet.Key(0)
	var pubRaw any
	if err := pubKey.Raw(&pubRaw); err != nil {
		t.Fatalf("Raw: %v", err)
	}
	// HMAC signers want []byte. Marshal the raw key so the
	// forgery uses its string form as the "secret". This is the
	// classic alg-confusion setup.
	hmacSecret := []byte(fmt.Sprintf("%v", pubRaw))

	tok, err := jwt.NewBuilder().
		Issuer("client-1").
		Subject("client-1").
		Audience([]string{"https://auth.example.com"}).
		IssuedAt(clk.Now()).
		Expiration(clk.Now().Add(time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, hmacSecret))
	if err != nil {
		t.Fatalf("hmac sign: %v", err)
	}

	_, err = VerifyClientAssertion(context.Background(), ClientAssertionParams{
		Assertion:       string(signed),
		JWKSJSON:        jwksJSON,
		ExpectedIssuer:  "client-1",
		ExpectedSubject: "client-1",
		Audience:        []string{"https://auth.example.com"},
		Skew:            time.Minute,
		Cache:           cache,
		Clock:           clk,
	})
	if err == nil {
		t.Errorf("expected alg-confusion rejection")
	}
}

func TestVerifyClientAssertion_EmptyInputs(t *testing.T) {
	_, jwks, clk, cache := newTestAssertionEnv(t)
	tt := []struct {
		name string
		p    ClientAssertionParams
	}{
		{"empty assertion", ClientAssertionParams{JWKSJSON: jwks, ExpectedIssuer: "c", ExpectedSubject: "c", Audience: []string{"a"}, Skew: time.Minute, Cache: cache, Clock: clk}},
		{"empty jwks", ClientAssertionParams{Assertion: "x", ExpectedIssuer: "c", ExpectedSubject: "c", Audience: []string{"a"}, Skew: time.Minute, Cache: cache, Clock: clk}},
		{"empty expected", ClientAssertionParams{Assertion: "x", JWKSJSON: jwks, Audience: []string{"a"}, Skew: time.Minute, Cache: cache, Clock: clk}},
		{"nil cache", ClientAssertionParams{Assertion: "x", JWKSJSON: jwks, ExpectedIssuer: "c", ExpectedSubject: "c", Audience: []string{"a"}, Skew: time.Minute, Clock: clk}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyClientAssertion(context.Background(), tc.p); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// MemAssertionCache direct unit test: lazy GC on expiry.
func TestMemAssertionCache_LazyGC(t *testing.T) {
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	c := NewMemAssertionCache(clk.Now)
	fresh, err := c.CheckAndStore("c1", "j1", clk.Now().Add(time.Minute))
	if err != nil || !fresh {
		t.Fatalf("first store: fresh=%v err=%v", fresh, err)
	}
	// Same jti before expiry: not fresh.
	fresh, _ = c.CheckAndStore("c1", "j1", clk.Now().Add(time.Minute))
	if fresh {
		t.Errorf("replay before expiry: expected not fresh")
	}
	// Advance past expiry, the entry should be GC'd and the same jti is fresh again.
	clk.Advance(2 * time.Minute)
	fresh, _ = c.CheckAndStore("c1", "j1", clk.Now().Add(time.Minute))
	if !fresh {
		t.Errorf("after expiry: expected fresh (lazy GC), got not fresh")
	}
}

// keep the linter quiet about httptest if the file loses its only user.
var _ = httptest.NewRecorder
