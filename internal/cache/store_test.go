package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore builds a store with an injectable clock, so expiry is tested
// without sleeping and the suite stays fast and deterministic.
func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	store, err := New(Options{
		Directory: t.TempDir(),
		TTL:       time.Minute,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, &now
}

func TestSetAndGetFresh(t *testing.T) {
	store, _ := newTestStore(t)

	if err := store.Set("asn:1.1.1.1", map[string]any{"asn": 13335}, "ripestat"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	value, stale, found := store.Get("asn:1.1.1.1")
	if !found {
		t.Fatal("a value just written should be found")
	}
	if stale {
		t.Fatal("a value inside its TTL must not be reported as stale")
	}

	var decoded map[string]any
	if err := json.Unmarshal(value, &decoded); err != nil {
		t.Fatalf("stored value is not valid JSON: %v", err)
	}
	if decoded["asn"] != float64(13335) {
		t.Fatalf("asn: got %v, want 13335", decoded["asn"])
	}
}

func TestGetMissingCountsMiss(t *testing.T) {
	store, _ := newTestStore(t)

	if _, _, found := store.Get("asn:nothing"); found {
		t.Fatal("an absent key must not be found")
	}
	if stats := store.Stats(); stats.Misses != 1 {
		t.Fatalf("misses: got %d, want 1", stats.Misses)
	}
}

// TestExpiredEntryIsServedButMarked is the property the whole design exists for:
// a stale answer beats no answer, but only if the caller is told.
//
// Serving an expired value as current would be worse than failing, because the
// caller would report yesterday's routing data as today's.
func TestExpiredEntryIsServedButMarked(t *testing.T) {
	store, now := newTestStore(t)

	if err := store.Set("asn:8.8.8.8", map[string]any{"asn": 15169}, "rdap"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Two minutes pass, and the TTL was one.
	*now = now.Add(2 * time.Minute)

	value, stale, found := store.Get("asn:8.8.8.8")
	if !found {
		t.Fatal("an expired entry should still be found, so a failed source has an answer")
	}
	if !stale {
		t.Fatal("an expired entry must be reported as stale")
	}
	if len(value) == 0 {
		t.Fatal("the stale value should still carry its data")
	}
	if stats := store.Stats(); stats.StaleServed != 1 {
		t.Fatalf("staleServed: got %d, want 1", stats.StaleServed)
	}
}

// TestExpiryUsesTheInjectedClock checks the boundary: at exactly the TTL it is
// still fresh, one nanosecond later it is not.
func TestExpiryUsesTheInjectedClock(t *testing.T) {
	store, now := newTestStore(t)
	if err := store.Set("k", "v", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	*now = now.Add(time.Minute - time.Nanosecond)
	if _, stale, _ := store.Get("k"); stale {
		t.Fatal("one nanosecond before the TTL it is still fresh")
	}

	*now = now.Add(2 * time.Nanosecond)
	if _, stale, _ := store.Get("k"); !stale {
		t.Fatal("just past the TTL it is stale")
	}
}

// TestKeyToPathIsSafe checks that a key containing separators cannot escape the
// cache directory. Lookup keys contain colons and dots, and an unsanitised one
// would either be invalid or a traversal.
func TestKeyToPathIsSafe(t *testing.T) {
	dir := t.TempDir()
	dangerous := "../../etc/passwd"

	path := keyToPath(dir, dangerous)

	if filepath.Dir(path) != dir {
		t.Fatalf("path %q escaped the cache directory %q", path, dir)
	}
	// The key is hashed, so the raw text must not appear in the filename.
	if filepath.Base(path) == dangerous {
		t.Fatal("the key should be hashed rather than used as a filename")
	}
}

// TestKeysWithTheSameSuffixDoNotCollide checks two keys that differ only before a
// separator, which is the case a naive sanitising scheme would merge.
func TestKeysWithTheSameSuffixDoNotCollide(t *testing.T) {
	// Both keys end in the same address and differ only in the namespace prefix,
	// which is exactly the case a sanitising scheme that kept only the last
	// component would merge into one entry.
	store, _ := newTestStore(t)

	if err := store.Set("asn:1.1.1.1", "cloudflare", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set("geo:1.1.1.1", "somewhere", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	first, _, _ := store.Get("asn:1.1.1.1")
	second, _, _ := store.Get("geo:1.1.1.1")
	if string(first) == string(second) {
		t.Fatal("two different keys returned the same value")
	}
}

func TestDiskSurvivesAProcessRestart(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	first, err := New(Options{Directory: dir, TTL: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := first.Set("asn:9.9.9.9", map[string]any{"asn": 19281}, "rdap"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// A second store over the same directory stands in for the next run of the
	// command. The in-memory map is empty, so the value can only come from disk.
	second, err := New(Options{Directory: dir, TTL: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	value, stale, found := second.Get("asn:9.9.9.9")
	if !found {
		t.Fatal("a value written by a previous run should be readable")
	}
	if stale {
		t.Fatal("it is inside its TTL, so it is not stale")
	}
	if !json.Valid(value) {
		t.Fatal("the value read back is not valid JSON")
	}
}

func TestCorruptFileIsIgnoredRatherThanFatal(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	store, err := New(Options{Directory: dir, TTL: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Set("k", "v", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// A truncated write, or a file edited by hand.
	if err := os.WriteFile(keyToPath(dir, "k"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("cannot corrupt the file: %v", err)
	}

	fresh, err := New(Options{Directory: dir, TTL: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A corrupt cache must not stop the program; the lookup is simply made again.
	if _, _, found := fresh.Get("k"); found {
		t.Fatal("a corrupt file should not be returned as data")
	}
}

func TestDeleteRemoves(t *testing.T) {
	store, _ := newTestStore(t)
	if err := store.Set("k", "v", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, found := store.Get("k"); found {
		t.Fatal("a deleted key should be gone")
	}
}

func TestSweepRemovesOldEntriesOnly(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	store, err := New(Options{Directory: dir, TTL: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := store.Set("recent", "v", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// An entry whose file is old on disk, which is what a month-old cache holds.
	oldPath := keyToPath(dir, "ancient")
	if err := os.WriteFile(oldPath, []byte(`{"key":"ancient"}`), 0o644); err != nil {
		t.Fatalf("cannot write the old entry: %v", err)
	}
	old := clock.Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatalf("cannot age the file: %v", err)
	}

	removed, err := store.Sweep(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed: got %d, want 1", removed)
	}
	if _, _, found := store.Get("recent"); !found {
		t.Fatal("sweep must not touch entries inside the max age")
	}
}

func TestClearEmptiesEverything(t *testing.T) {
	store, _ := newTestStore(t)
	for _, key := range []string{"a", "b", "c"} {
		if err := store.Set(key, key, "test"); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	removed, err := store.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed: got %d, want 3", removed)
	}
	for _, key := range []string{"a", "b", "c"} {
		if _, _, found := store.Get(key); found {
			t.Fatalf("%q survived the clear", key)
		}
	}
}

// TestHitRateCountsStaleAsAvoided records the accounting choice: a stale serve
// avoided the network, which is the entire reason the cache exists.
func TestHitRateCountsStaleAsAvoided(t *testing.T) {
	store, now := newTestStore(t)

	if err := store.Set("fresh", "v", "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	store.Get("fresh")

	*now = now.Add(2 * time.Minute)
	store.Get("fresh") // stale, but still a served value

	stats := store.Stats()
	if stats.Hits != 1 {
		t.Errorf("hits: got %d, want 1", stats.Hits)
	}
	if stats.StaleServed != 1 {
		t.Errorf("staleServed: got %d, want 1", stats.StaleServed)
	}
	// One hit plus one stale serve out of two lookups.
	if stats.HitRatePct < 99 || stats.HitRatePct > 100 {
		t.Errorf("hit rate: got %.0f%%, want 100%%", stats.HitRatePct)
	}
}

// TestDefaultDirectoryFollowsXDG checks the location convention, so the cache
// lands where a user would look for it.
func TestDefaultDirectoryFollowsXDG(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-test")

	store, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if store.Directory() != "/tmp/xdg-test/netgraph" {
		t.Fatalf("directory: got %q, want /tmp/xdg-test/netgraph", store.Directory())
	}
}
