package traefik_plugins

import (
	"sync"
	"time"
)

type ttlEntry struct {
	value     interface{}
	expiresAt time.Time
}

// TtlMap is a simple thread-safe map with TTL expiry, replacing mailgun/ttlmap.
type TtlMap struct {
	mu      sync.Mutex
	entries map[string]*ttlEntry
}

func newTtlMap(_ int) (*TtlMap, error) {
	m := &TtlMap{
		entries: make(map[string]*ttlEntry),
	}
	go m.cleanupLoop()
	return m, nil
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

	m.entries[key] = &ttlEntry{
		value:     value,
		expiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
	return nil
}

func (m *TtlMap) cleanupLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for k, e := range m.entries {
			if now.After(e.expiresAt) {
				delete(m.entries, k)
			}
		}
		m.mu.Unlock()
	}
}
