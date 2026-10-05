// Command asnprobe exercises the ASN lookup against live sources and reports
// what the cache saved.
//
// It exists because the ASN path has a failure mode no unit test can catch: the
// sources being unreachable, rate-limited, or answering a shape the decoder did
// not expect. Running it against the real registries is the only way to know the
// decoder is right.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Xwalims/netgraph/internal/asn"
	"github.com/Xwalims/netgraph/internal/cache"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A temporary cache directory, so a probe run leaves nothing behind.
	dir, err := os.MkdirTemp("", "netgraph-cache-*")
	if err != nil {
		fmt.Println("cannot create a temporary directory:", err)
		return
	}
	defer os.RemoveAll(dir)

	store, err := cache.New(cache.Options{Directory: dir, TTL: 15 * time.Minute})
	if err != nil {
		fmt.Println("cannot build the cache:", err)
		return
	}

	lookup := asn.New(asn.Options{
		Client:  &http.Client{Timeout: 10 * time.Second},
		Cache:   store,
		Timeout: 10 * time.Second,
	})

	for _, address := range os.Args[1:] {
		start := time.Now()
		result, err := lookup.Lookup(ctx, address)
		elapsed := time.Since(start)

		fmt.Printf("\n%s  (%s)\n", address, elapsed.Round(time.Millisecond))
		if err != nil {
			fmt.Printf("  FAILED: %v\n", err)
			continue
		}
		info := result.Info
		fmt.Printf("  ASN      %d  %s\n", info.ASN, info.OrgName)
		fmt.Printf("  prefix   %s  announced=%v\n", info.Prefix, info.Announced)
		fmt.Printf("  country  %s   rir=%s\n", info.Country, info.RIR)
		if info.AbuseEmail != "" {
			fmt.Printf("  abuse    %s\n", info.AbuseEmail)
		}
		fmt.Printf("  sources  %v  stale=%v\n", result.Sources, result.Stale)
		for _, message := range result.Errors {
			fmt.Printf("  error    %s\n", message)
		}
	}

	fmt.Println("\n=== the same lookups again, now from cache ===")
	for _, address := range os.Args[1:] {
		start := time.Now()
		_, _ = lookup.Lookup(ctx, address)
		fmt.Printf("  %-20s %s\n", address, time.Since(start).Round(time.Microsecond))
	}

	stats := store.Stats()
	fmt.Printf("\ncache: hits=%d misses=%d stale=%d entries=%d\n",
		stats.Hits, stats.Misses, stats.StaleServed, stats.Entries)
}
