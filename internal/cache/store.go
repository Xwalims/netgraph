// Package cache stores lookup results on disk.
//
// # Why this exists
//
// ASN and GeoIP answers come from the network, and the brief requires that a
// lookup never be made without caching. The reasons are practical rather than
// theoretical:
//
//   - A traceroute can produce thirty hops. Asking a public API thirty times in
//     a row is how a tool gets rate-limited, and then it reports nothing.
//   - Routing data changes on the order of days. Re-asking every thirty seconds
//     returns the same answer and wastes the source's quota.
//   - A lookup that fails because an API is down should still answer from
//     yesterday's cache, clearly marked as stale.
//
// # Stale is not the same as fresh
//
// An expired entry is still returned when the source fails, but `Stale` is set
// so the caller can say so. Silently serving old data as current is the failure
// mode this design exists to avoid, so the flag travels with the value.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultTTL is how long an answer is considered current.
const DefaultTTL = 15 * time.Minute

// Entry is one cached value.
type Entry struct {
	// Key identifies what was looked up.
	Key string `json:"key"`

	// Value is the stored payload, opaque to the cache.
	Value json.RawMessage `json:"value"`

	// FetchedAt is when the value was stored.
	FetchedAt time.Time `json:"fetchedAt"`

	// TTL is how long the value was considered current when stored.
	TTL time.Duration `json:"ttl"`

	// Source names where the value came from, so a caller can attribute it.
	Source string `json:"source,omitempty"`
}

// Expired reports whether the entry is past its TTL.
func (e Entry) Expired(now time.Time) bool {
	return now.Sub(e.FetchedAt) > e.TTL
}

// Age returns how long ago the value was fetched.
func (e Entry) Age(now time.Time) time.Duration {
	return now.Sub(e.FetchedAt)
}

// Store is a filesystem cache of JSON values.
//
// It is safe for concurrent use: a traceroute enriches hops from several
// goroutines at once.
type Store struct {
	dir string
	ttl time.Duration
	now func() time.Time

	mu    sync.RWMutex
	cache map[string]Entry

	// Stats are counters for reporting, not for correctness.
	hits, misses, staleServed, writes int
}

// Options configures a Store.
type Options struct {
	// Directory holds the cache files. Created on first write.
	Directory string

	// TTL overrides DefaultTTL.
	TTL time.Duration

	// Now is injectable so tests do not have to sleep.
	Now func() time.Time
}

// New builds a Store.
func New(options Options) (*Store, error) {
	if options.Directory == "" {
		dir, err := defaultDirectory()
		if err != nil {
			return nil, err
		}
		options.Directory = dir
	}
	if options.TTL <= 0 {
		options.TTL = DefaultTTL
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Store{
		dir:   options.Directory,
		ttl:   options.TTL,
		now:   options.Now,
		cache: make(map[string]Entry),
	}, nil
}

// defaultDirectory follows the XDG convention and falls back to a dot directory
// in the user's home when XDG is unset.
func defaultDirectory() (string, error) {
	if base := os.Getenv("XDG_CACHE_HOME"); base != "" {
		return filepath.Join(base, "netgraph"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate a cache directory: %w", err)
	}
	return filepath.Join(home, ".cache", "netgraph"), nil
}

// Directory returns the cache location, which the CLI shows so a user can find
// and delete it.
func (s *Store) Directory() string {
	return s.dir
}

// keyToPath turns a lookup key into a filename.
//
// The key is hashed rather than used directly: keys contain colons, slashes and
// dots, and a key like `AS13335` or `1.1.1.1` would otherwise produce a path
// that is either invalid or, worse, a directory traversal.
func keyToPath(dir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json")
}

// Get returns a cached value.
//
// A fresh entry is returned with stale=false. An expired entry is returned with
// stale=true so the caller can decide whether to use it, which is the point: a
// lookup that would otherwise fail gets an answer, visibly marked as old.
func (s *Store) Get(key string) (value json.RawMessage, stale bool, found bool) {
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()

	if !ok {
		// Fall through to disk: another process may have written it.
		entry, ok = s.loadFromDisk(key)
		if !ok {
			s.mu.Lock()
			s.misses++
			s.mu.Unlock()
			return nil, false, false
		}
	}

	if entry.Expired(s.now()) {
		s.mu.Lock()
		s.staleServed++
		s.mu.Unlock()
		return entry.Value, true, true
	}

	s.mu.Lock()
	s.hits++
	s.mu.Unlock()
	return entry.Value, false, true
}

// Set stores a value with the default TTL.
func (s *Store) Set(key string, value any, source string) error {
	return s.SetWithTTL(key, value, s.ttl, source)
}

// SetWithTTL stores a value with an explicit TTL.
func (s *Store) SetWithTTL(key string, value any, ttl time.Duration, source string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cannot encode the value for %q: %w", key, err)
	}

	entry := Entry{
		Key:       key,
		Value:     encoded,
		FetchedAt: s.now(),
		TTL:       ttl,
		Source:    source,
	}

	s.mu.Lock()
	s.cache[key] = entry
	s.writes++
	s.mu.Unlock()

	// A cache that cannot be written is a slower cache, not a broken one, so a
	// failed write is ignored rather than failing the lookup that succeeded.
	_ = s.writeToDisk(entry)
	return nil
}

// loadFromDisk reads an entry written by an earlier run.
func (s *Store) loadFromDisk(key string) (Entry, bool) {
	data, err := os.ReadFile(keyToPath(s.dir, key))
	if err != nil {
		return Entry{}, false
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		// A corrupt cache file must not stop the program. The lookup will simply
		// be made again.
		return Entry{}, false
	}
	s.mu.Lock()
	s.cache[key] = entry
	s.mu.Unlock()
	return entry, true
}

func (s *Store) writeToDisk(entry Entry) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	// Written to a temporary file and renamed, so a crash mid-write cannot leave
	// a truncated file that fails to parse on the next run.
	temp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		os.Remove(tempName)
		return err
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return err
	}
	return os.Rename(tempName, keyToPath(s.dir, entry.Key))
}

// Delete removes one entry.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	delete(s.cache, key)
	s.mu.Unlock()
	return os.Remove(keyToPath(s.dir, key))
}

// Sweep removes entries older than maxAge and returns how many went.
func (s *Store) Sweep(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := s.now().Add(-maxAge)
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if os.Remove(filepath.Join(s.dir, entry.Name())) == nil {
				removed += 1
			}
		}
	}
	return removed, nil
}

// Clear removes every entry and returns how many went.
func (s *Store) Clear() (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if os.Remove(filepath.Join(s.dir, entry.Name())) == nil {
			removed += 1
		}
	}

	s.mu.Lock()
	s.cache = make(map[string]Entry)
	s.mu.Unlock()
	return removed, nil
}

// Stats is a snapshot of cache counters, for the `netgraph cache` report.
type Stats struct {
	Entries     int           `json:"entries"`
	Directory   string        `json:"directory"`
	Hits        int           `json:"hits"`
	Misses      int           `json:"misses"`
	StaleServed int           `json:"staleServed"`
	Writes      int           `json:"writes"`
	DefaultTTL  time.Duration `json:"defaultTtl"`
	HitRatePct  float64       `json:"hitRatePct"`
}

// Stats returns the current counters.
//
// The hit rate counts a stale serve as a hit, because it avoided the network.
// That is the honest accounting: the whole reason the cache exists is to not
// make the request.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Every Get ends in exactly one of the three outcomes: a fresh hit, a stale
	// serve, or a miss. The denominator has to count all three, or a stale serve
	// lands in the numerator without being in the denominator -- which is how this
	// reported 200% for a cache that served everything it was asked for.
	total := s.hits + s.staleServed + s.misses
	rate := 0.0
	if total > 0 {
		rate = float64(s.hits+s.staleServed) / float64(total) * 100
	}
	return Stats{
		Entries:     len(s.cache),
		Directory:   s.dir,
		Hits:        s.hits,
		Misses:      s.misses,
		StaleServed: s.staleServed,
		Writes:      s.writes,
		DefaultTTL:  s.ttl,
		HitRatePct:  rate,
	}
}
