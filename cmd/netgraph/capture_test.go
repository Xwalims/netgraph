package main

import (
	"io"
	"os"
	"testing"

	"github.com/Xwalims/netgraph/internal/dns"
)

// capturePrintRecords runs printRecords with stdout redirected, so a rendering
// rule can be asserted on the text a user actually sees instead of on a value
// that has to be re-derived from the same helper the code under test uses.
//
// printRecords writes straight to os.Stdout, so it has to be swapped at the file
// descriptor rather than through an io.Writer; the original is restored by the
// cleanup whether or not the test fails.
func capturePrintRecords(t *testing.T, result *dns.Result, flags dnsFlags) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = original }()

	done := make(chan string, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()

	printRecords(result, flags)

	// Close before reading: the writer end must go away or ReadAll blocks forever
	// waiting for output that will never come.
	w.Close()
	out := <-done
	r.Close()

	return out
}
