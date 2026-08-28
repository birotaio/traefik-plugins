package traefik_plugins

import (
	"sync"
	"time"
)

// sweepInterval is the minimum delay between two amortized sweeps in Set.
const sweepInterval = time.Second

type ttlEntry struct {
	value     interface{}
	expiresAt time.Time
}

// TtlMap is a simple thread-safe map with TTL expiry, replacing mailgun/ttlmap.
//
// Expired entries are reclaimed on read in Get and by an amortized sweep in Set. There is
// deliberately no background cleanup goroutine: traefik builds a new middleware instance per
// router and rebuilds the whole tree on every configuration reload, so a goroutine holding the
// map as its receiver would keep every superseded instance reachable and leak for the lifetime
// of the process.
type TtlMap struct {
	mu        sync.Mutex
	entries   map[string]*ttlEntry
	nextSweep time.Time
}

func newTtlMap(_ int) (*TtlMap, error) {
	return &TtlMap{entries: make(map[string]*ttlEntry)}, nil
}

func (m *TtlMap) Get(key string) (interface{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(m.entries, key)
		return nil, false
	}
	return e.value, true
}

func (m *TtlMap) Set(key string, value interface{}, ttlSeconds int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if now.After(m.nextSweep) {
		m.sweep(now)
		m.nextSweep = now.Add(sweepInterval)
	}

	m.entries[key] = &ttlEntry{
		value:     value,
		expiresAt: now.Add(time.Duration(ttlSeconds) * time.Second),
	}
	return nil
}

// len reports the number of entries, expired ones included. Used by tests.
func (m *TtlMap) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// sweep deletes every expired entry. The caller must hold m.mu.
func (m *TtlMap) sweep(now time.Time) {
	for k, e := range m.entries {
		if now.After(e.expiresAt) {
			delete(m.entries, k)
		}
	}
}
