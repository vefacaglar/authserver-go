package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/store/memory"
)

func newTestIssuer(t *testing.T) (*Issuer, *clock.FakeClock) {
	t.Helper()
	clk := clock.NewFakeClock(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	keys := NewKeyManager(memory.NewSigningKeyStore(), clk)
	iss := NewIssuer("https://auth.example.com", keys, clk)
	return iss, clk
}

func TestIssueAccessToken_VerifiesAgainstJWKS(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)

	raw, err := iss.IssueAccessToken(ctx, AccessTokenClaims{
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     "openid profile",
		ExpiresIn: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("access token is empty")
	}

	tok, err := iss.VerifyToken(ctx, raw)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if tok.Issuer() != "https://auth.example.com" {
		t.Errorf("iss = %q", tok.Issuer())
	}
	if tok.Subject() != "user-1" {
		t.Errorf("sub = %q", tok.Subject())
	}
	if len(tok.Audience()) != 1 || tok.Audience()[0] != "client-1" {
		t.Errorf("aud = %v, want [client-1]", tok.Audience())
	}
	if scope, _ := tok.Get("scope"); scope != "openid profile" {
		t.Errorf("scope claim = %v, want %q", scope, "openid profile")
	}
}

func TestIssueIDToken_AtHashMatchesAccessToken(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)

	rawAccess, err := iss.IssueAccessToken(ctx, AccessTokenClaims{
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     "openid",
		ExpiresIn: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	rawID, err := iss.IssueIDToken(ctx, IDTokenClaims{
		Subject:  "user-1",
		ClientID: "client-1",
		Scope:    "openid",
		Nonce:    "abc-123",
		AuthTime: time.Date(2025, 1, 1, 11, 0, 0, 0, time.UTC),
		AtHash:   HashAccessToken(rawAccess),
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	tok, err := iss.VerifyToken(ctx, rawID)
	if err != nil {
		t.Fatalf("VerifyToken(id): %v", err)
	}

	// The token must verify against the JWKS.
	if tok.Issuer() != "https://auth.example.com" {
		t.Errorf("iss = %q", tok.Issuer())
	}
	if tok.Subject() != "user-1" {
		t.Errorf("sub = %q", tok.Subject())
	}
	if len(tok.Audience()) != 1 || tok.Audience()[0] != "client-1" {
		t.Errorf("aud = %v, want [client-1]", tok.Audience())
	}

	// at_hash must be present and match a fresh computation from the access token.
	atHash, ok := tok.Get("at_hash")
	if !ok {
		t.Fatalf("id token missing at_hash claim")
	}
	wantAtHash := HashAccessToken(rawAccess)
	if atHash != wantAtHash {
		t.Errorf("at_hash = %v, want %v", atHash, wantAtHash)
	}

	if nonce, _ := tok.Get("nonce"); nonce != "abc-123" {
		t.Errorf("nonce = %v, want abc-123", nonce)
	}

	if authTime, ok := tok.Get("auth_time"); !ok {
		t.Errorf("id token missing auth_time claim")
	} else {
		// jwx v2 returns numeric dates as float64; compare by unix seconds.
		var sec float64
		switch v := authTime.(type) {
		case float64:
			sec = v
		case int64:
			sec = float64(v)
		case json.Number:
			f, err := v.Float64()
			if err != nil {
				t.Errorf("auth_time json.Number: %v", err)
			}
			sec = f
		default:
			t.Errorf("auth_time has unexpected type %T", authTime)
		}
		if sec == 0 {
			t.Errorf("auth_time = %v, want non-zero", authTime)
		}
		wantSec := float64(time.Date(2025, 1, 1, 11, 0, 0, 0, time.UTC).Unix())
		if sec != wantSec {
			t.Errorf("auth_time = %v, want %v", sec, wantSec)
		}
	}
}

func TestIssueIDToken_OmitsNonceWhenEmpty(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)
	rawAccess, _ := iss.IssueAccessToken(ctx, AccessTokenClaims{Subject: "u", ClientID: "c"})

	rawID, err := iss.IssueIDToken(ctx, IDTokenClaims{
		Subject:  "u",
		ClientID: "c",
		AuthTime: time.Now(),
		AtHash:   HashAccessToken(rawAccess),
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	tok, err := iss.VerifyToken(ctx, rawID)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if _, ok := tok.Get("nonce"); ok {
		t.Errorf("id token should not carry a nonce claim when none was supplied")
	}
}

func TestIssueIDToken_RejectsMissingAtHash(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)
	if _, err := iss.IssueIDToken(ctx, IDTokenClaims{
		Subject:  "u",
		ClientID: "c",
		AuthTime: time.Now(),
	}); err == nil {
		t.Errorf("IssueIDToken without at_hash succeeded; expected error")
	}
}

func TestIssueAccessToken_RequiresSubjectAndClient(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)
	if _, err := iss.IssueAccessToken(ctx, AccessTokenClaims{}); err == nil {
		t.Errorf("expected error for empty subject+client")
	}
	if _, err := iss.IssueAccessToken(ctx, AccessTokenClaims{Subject: "u"}); err == nil {
		t.Errorf("expected error for missing client")
	}
}

func TestJWKSForEndpoint_OmitsPrivateFields(t *testing.T) {
	ctx := context.Background()
	iss, _ := newTestIssuer(t)

	body, err := iss.JWKSForEndpoint(ctx)
	if err != nil {
		t.Fatalf("JWKSForEndpoint: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("JWKS body is empty")
	}
	if got := string(body); contains(got, `"d":`) {
		t.Errorf("JWKS leaked private exponent 'd': %s", got)
	}
	if !contains(string(body), `"kty":"RSA"`) {
		t.Errorf("JWKS missing RSA kty: %s", body)
	}
	if !contains(string(body), `"use":"sig"`) {
		t.Errorf("JWKS missing use=sig: %s", body)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
