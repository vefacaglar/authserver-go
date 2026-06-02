package token

import (
	"testing"
)

func TestHashToken_Deterministic(t *testing.T) {
	const in = "opaque-token-value"
	got1 := HashToken(in)
	got2 := HashToken(in)
	if got1 != got2 {
		t.Errorf("HashToken not deterministic: %q vs %q", got1, got2)
	}
	if got1 == "" {
		t.Errorf("HashToken returned empty string")
	}
	if len(got1) != 43 {
		// SHA-256 = 32 bytes, base64url-no-padding = ceil(32*4/3) = 43.
		t.Errorf("HashToken length = %d, want 43", len(got1))
	}
}

func TestNewOpaqueToken_Uniqueness(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		raw, hash, err := NewOpaqueToken()
		if err != nil {
			t.Fatalf("NewOpaqueToken: %v", err)
		}
		if raw == "" || hash == "" {
			t.Fatalf("NewOpaqueToken returned empty values: raw=%q hash=%q", raw, hash)
		}
		if raw == hash {
			t.Errorf("raw equals its own hash (impossible for SHA-256 over 256 bits)")
		}
		if HashToken(raw) != hash {
			t.Errorf("hash from NewOpaqueToken does not match HashToken(raw)")
		}
		if _, dup := seen[raw]; dup {
			t.Fatalf("duplicate opaque token after %d iterations", i)
		}
		seen[raw] = struct{}{}
	}
}

func TestHashAccessToken_RS256Shape(t *testing.T) {
	// 32 bytes -> 16 leftmost bytes -> 22 base64url chars (no padding).
	if got := len(HashAccessToken("anything")); got != 22 {
		t.Errorf("HashAccessToken length = %d, want 22 (RS256 leftmost half)", got)
	}
	if a, b := HashAccessToken("a"), HashAccessToken("a"); a != b {
		t.Errorf("HashAccessToken not deterministic")
	}
	if HashAccessToken("a") == HashAccessToken("b") {
		t.Errorf("HashAccessToken collided on different inputs")
	}
}
