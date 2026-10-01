package oidc

import "testing"

func TestDescribeUserAgent(t *testing.T) {
	tests := []struct{ ua, want string }{
		{"", "unknown device"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "Chrome on macOS"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", "Edge on Windows"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox on Linux"},
		{"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36", "Chrome on Android"},
		{"curl/8.4.0", "curl"},
		{"something-else", "browser"},
	}
	for _, tc := range tests {
		if got := describeUserAgent(tc.ua); got != tc.want {
			t.Errorf("describeUserAgent(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}
