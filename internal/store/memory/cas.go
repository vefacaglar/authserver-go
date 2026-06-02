// Package memory provides in-memory implementations of the store interfaces.
//
// These are intended for tests and the initial M3 end-to-end bring-up; the
// production deployment uses the GORM implementation added in M5. They are
// goroutine-safe via a combination of an outer RWMutex (for the map itself)
// and per-entity mutexes (for atomic MarkConsumed operations).
package memory

import "sync"

// casLocks holds a per-entity mutex used to serialise MarkConsumed calls
// for the same id. Entities are inserted on Store and remain in the map for
// the lifetime of the process; this is acceptable for the in-memory store
// (auth codes and refresh tokens are short-lived and bounded in count).
type casLocks[K comparable] struct {
	mu    sync.Mutex
	locks map[K]*sync.Mutex
}

func newCASLocks[K comparable]() *casLocks[K] {
	return &casLocks[K]{locks: make(map[K]*sync.Mutex)}
}

func (c *casLocks[K]) get(key K) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.locks[key]
	if !ok {
		m = &sync.Mutex{}
		c.locks[key] = m
	}
	return m
}
