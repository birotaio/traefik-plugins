package traefik_plugins

import (
	"context"
	"net/http"
	"runtime"
	"testing"
	"time"
)

// Traefik builds a new middleware instance per router and rebuilds the whole tree on every
// configuration reload. Anything New leaves running keeps that instance alive for the lifetime
// of the process, which is how a production pod reached ~195k goroutines and 11 GiB.
func TestNewDoesNotLeakGoroutines(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	cfg := CreateConfig()
	cfg.ValueHeaderName = "X-Rate-Limit"
	cfg.Average = 30
	cfg.Burst = 60

	if _, err := New(ctx, next, cfg, "warmup"); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	const instantiations = 500
	for i := 0; i < instantiations; i++ {
		if _, err := New(ctx, next, cfg, "traefik-plugins"); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()

	if after := runtime.NumGoroutine(); after > before+5 {
		t.Fatalf("New leaked goroutines: %d -> %d over %d instantiations", before, after, instantiations)
	}
}

func TestTtlMapExpiresEntries(t *testing.T) {
	m, err := newTtlMap(maxSources)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Set("a", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("a"); !ok {
		t.Fatal("entry should be present before its ttl elapses")
	}

	time.Sleep(1100 * time.Millisecond)

	if _, ok := m.Get("a"); ok {
		t.Fatal("entry should be gone after its ttl elapsed")
	}
}

// Without a background sweeper, keys that are written once and never read again must still be
// reclaimed, otherwise the map grows with every distinct source.
func TestTtlMapReclaimsUnreadEntries(t *testing.T) {
	m, err := newTtlMap(maxSources)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		if err := m.Set(string(rune('a'+i%26))+string(rune('a'+i/26)), i, 1); err != nil {
			t.Fatal(err)
		}
	}
	if m.len() == 0 {
		t.Fatal("expected entries to be stored")
	}

	time.Sleep(1100 * time.Millisecond)

	// A single write past the sweep interval must reclaim every expired entry.
	if err := m.Set("trigger", 0, 1); err != nil {
		t.Fatal(err)
	}
	if got := m.len(); got != 1 {
		t.Fatalf("expected only the fresh entry to remain, got %d", got)
	}
}
