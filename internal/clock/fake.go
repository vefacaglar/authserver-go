package clock

import (
	"sync"
	"time"
)

// FakeClock is a deterministic Clock for tests. The clock only moves when
// Advance or Set is called. It is safe for concurrent use.
type FakeClock struct {
	mu sync.Mutex
	t  time.Time
}

var _ Clock = (*FakeClock)(nil)

// NewFakeClock returns a FakeClock initialised to start (normalised to UTC).
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{t: start.UTC()}
}

// Now returns the current fake time.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

// Advance moves the clock forward by d. The clock stays in UTC.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// Set moves the clock to t (normalised to UTC).
func (f *FakeClock) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t.UTC()
}
