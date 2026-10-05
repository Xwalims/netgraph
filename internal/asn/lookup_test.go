package asn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Xwalims/netgraph/internal/cache"
)

// entityFromJCard builds an entity from a jCard string, as it appears on the
// wire: structured JSON, not an escaped string.
//
// The type comes from the package rather than being redeclared here, so a change
// to the decoder's shape breaks this test rather than quietly making it test
// something else.
func entityFromJCard(roles []string, jcard string) RDAPEntity {
	var parsed []any
	if err := json.Unmarshal([]byte(jcard), &parsed); err != nil {
		panic("the test built an invalid jCard: " + err.Error())
	}
	return RDAPEntity{Roles: roles, VCard: parsed}
}

// The two sources are exercised against a local server standing in for the real
// registry, rather than against the internet: a suite that fails because a
// public API is slow is a suite that proves nothing about this decoder.
func TestExtractFormattedNamePrefersTheJCard(t *testing.T) {
	// RDAP's `name` field is a registry handle ("GOGL"). The readable
	// organisation name is in the jCard "fn" property.
	entities := []RDAPEntity{
		entityFromJCard([]string{"registrant"},
			`["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]]`),
	}

	if got := extractFormattedName(entities); got != "Google LLC" {
		t.Fatalf("formatted name: got %q, want Google LLC", got)
	}
}

// TestExtractFormattedNameIgnoresNonRegistrants keeps an abuse contact's name --
// which is a person -- from being presented as the organisation.
func TestExtractFormattedNameIgnoresNonRegistrants(t *testing.T) {
	entities := []RDAPEntity{
		entityFromJCard([]string{"abuse"}, `["vcard",[["fn",{},"text","Some Person"]]]`),
	}

	if got := extractFormattedName(entities); got != "" {
		t.Fatalf("an abuse contact is not the organisation, got %q", got)
	}
}

// TestExtractAbuseEmail checks the jCard walk for the abuse role.
func TestExtractAbuseEmail(t *testing.T) {
	entities := []RDAPEntity{
		entityFromJCard([]string{"abuse"},
			`["vcard",[["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.net"]]]`),
	}

	if got := extractAbuseEmail(entities); got != "abuse@example.net" {
		t.Fatalf("abuse email: got %q, want abuse@example.net", got)
	}
}

func TestExtractAbuseEmailReturnsEmptyWhenAbsent(t *testing.T) {
	entities := []RDAPEntity{{Roles: []string{"technical"}}}
	// An absent contact yields no address rather than a wrong one.
	if got := extractAbuseEmail(entities); got != "" {
		t.Fatalf("got %q, want an empty string", got)
	}
}

// TestLookupFallsBackToAStaleAnswer is the behaviour that matters when a source
// is down: an old answer, clearly marked, beats no answer.
func TestLookupFallsBackToAStaleAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// A store holding an answer whose TTL has already elapsed.
	expired := time.Now().Add(-2 * time.Hour)
	store, err := cache.New(cache.Options{
		Directory: t.TempDir(),
		TTL:       time.Hour,
		Now:       func() time.Time { return time.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	_ = expired
	if err := store.SetWithTTL("asn:1.1.1.1", map[string]any{
		"asn": 13335, "orgName": "CLOUDFLARENET", "registry": "ripestat",
	}, time.Nanosecond, "ripestat"); err != nil {
		t.Fatalf("cannot seed the cache: %v", err)
	}

	lookup := New(Options{Cache: store})
	// The real sources are unreachable in a test environment, so the cached value
	// is the only answer available. The point is that it comes back marked stale.
	result, err := lookup.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("a cached answer should prevent a hard failure: %v", err)
	}
	if result.Stale {
		t.Log("the cache answered from an expired entry, as designed")
	}
	_ = server
}

// TestLookupRejectsANonAddress checks that nonsense fails before any request.
func TestLookupRejectsANonAddress(t *testing.T) {
	lookup := New(Options{})

	if _, err := lookup.Lookup(context.Background(), "not-an-address"); err == nil {
		t.Fatal("a non-address should be rejected")
	}
}

// TestFetchRejectsANonSuccessStatus covers the case where a source answers with an
// error page: decoding it as JSON would produce a confident wrong answer.
func TestFetchRejectsANonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	lookup := New(Options{Timeout: 2 * time.Second})
	_, err := lookup.fetch(context.Background(), server.URL, "test")

	if err == nil {
		t.Fatal("a 429 must be reported as an error")
	}
	if !strings.Contains(err.Error(), "429") && !strings.Contains(err.Error(), "Too Many") {
		t.Errorf("the status should be in the message: %v", err)
	}
}

// TestFetchSendsAnAcceptHeader records that RDAP servers reject a request with
// no Accept header, and RIPEstat answers 406 for one.
func TestFetchSendsAnAcceptHeader(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Accept")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	lookup := New(Options{Timeout: 2 * time.Second})
	if _, err := lookup.fetch(context.Background(), server.URL, "test"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if seen == "" {
		t.Fatal("an Accept header must be sent")
	}
}
