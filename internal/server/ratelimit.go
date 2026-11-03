// Package server wires the HTTP router, middleware chain, and the concrete
// handlers defined in internal/oidc. The package is the composition target
// for cmd/authserver: it builds a fully-wired http.Handler from a Config
// and a set of store implementations.
package server

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LoginRateLimiter is a per-IP rate limiter for the /login POST
// endpoint. It is deliberately not a global limiter because the
// threat model is one noisy client, not aggregate load. A token
// bucket is used so a small burst of legitimate retries is OK but
// sustained hammering is throttled.
type LoginRateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*ipBucket
	rate      rate.Limit
	burst     int
	maxIdle   time.Duration
	lastSweep time.Time
	now       func() time.Time
}

type ipBucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewLoginRateLimiter returns a limiter that allows `rps` requests
// per second per IP with a burst of `burst`. Per-IP buckets idle out
// after maxIdle so the map does not grow unbounded under attack.
func NewLoginRateLimiter(rps int, burst int) *LoginRateLimiter {
	if rps < 1 {
		rps = 10
	}
	if burst < 1 {
		burst = 5
	}
	return &LoginRateLimiter{
		buckets: make(map[string]*ipBucket),
		rate:    rate.Limit(rps),
		burst:   burst,
		maxIdle: 10 * time.Minute,
		now:     time.Now,
	}
}

// allow returns true if the request from ip is permitted under the
// rate limit.
func (l *LoginRateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{lim: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[ip] = b
	}
	b.lastSeen = now
	return b.lim.AllowN(now, 1)
}

// sweep drops buckets idle for at least maxIdle, at most once per
// maxIdle, so the cost stays amortized O(1) per request. Dropping is
// lossless: an idle bucket has long since refilled to its full burst,
// which is exactly what a fresh bucket starts with. Caller holds l.mu.
func (l *LoginRateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.maxIdle {
		return
	}
	l.lastSweep = now
	for ip, b := range l.buckets {
		if now.Sub(b.lastSeen) >= l.maxIdle {
			delete(l.buckets, ip)
		}
	}
}

// Middleware returns the http middleware that enforces the rate
// limit. When over the limit, the response is 429 with a
// Retry-After header.
func (l *LoginRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !l.allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too_many_requests","error_description":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the request's source IP, honouring the
// X-Forwarded-For header set by the chi RealIP middleware. The
// RemoteAddr is the fallback for direct connections.
//
// Exported so handlers outside the server package (e.g. the login
// handler building the per-(username, IP) lockout key) can share the
// same view of "who is this request from" as the rate limiter.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first (left-most) value, which is the original
		// client. Subsequent values are intermediate proxies.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
