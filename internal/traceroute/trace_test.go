package traceroute

import (
	"encoding/binary"
	"testing"
)

// TestQuotedPortIPv4 checks that a probe's destination port is recovered from
// the packet an ICMP error quotes.
//
// This is the join between "what we sent" and "who answered", so a bug here
// makes every reply unattributable and the whole trace empty -- which is what
// happened before the option was fixed.
func TestQuotedPortIPv4(t *testing.T) {
	// A quoted packet: 20-byte IPv4 header, then a UDP header.
	quoted := make([]byte, 28)

	// IHL 5 means a 20-byte header.
	quoted[0] = 0x45
	quoted[8] = 7  // TTL
	quoted[9] = 17 // UDP

	binary.BigEndian.PutUint16(quoted[20+2:20+4], 33441)

	port, ok := quotedPort(quoted, false)
	if !ok {
		t.Fatal("a UDP quote should be recognised")
	}
	if port != 33441 {
		t.Fatalf("port: got %d, want 33441", port)
	}
}

// TestQuotedPortRespectsHeaderLength covers the case where IP options make the
// header longer than 20 bytes. Reading at a fixed offset would read the middle
// of the options instead of the port.
func TestQuotedPortRespectsHeaderLength(t *testing.T) {
	// IHL 6: a 24-byte header, which happens when options are present.
	quoted := make([]byte, 32)
	quoted[0] = 0x46
	quoted[9] = 17

	binary.BigEndian.PutUint16(quoted[24+2:24+4], 40000)

	port, ok := quotedPort(quoted, false)
	if !ok {
		t.Fatal("a quote with IP options should still be recognised")
	}
	if port != 40000 {
		t.Fatalf("port with options: got %d, want 40000", port)
	}
}

// TestQuotedPortICMP verifies that an echo reply -- which has no port -- is
// accepted without one, because it comes from the destination itself.
func TestQuotedPortICMP(t *testing.T) {
	quoted := make([]byte, 28)
	quoted[0] = 0x45
	quoted[9] = 1 // ICMP

	if _, ok := quotedPort(quoted, false); !ok {
		t.Fatal("an ICMP quote should be accepted")
	}
}

// TestQuotedPortRejectsJunk verifies that a malformed or truncated quote is
// discarded rather than misparsed.
//
// A reply misread as belonging to a probe produces a hop at the wrong distance,
// which is worse than a missing hop.
func TestQuotedPortRejectsJunk(t *testing.T) {
	cases := map[string][]byte{
		"empty":       {},
		"too short":   {0x45},
		"header only": make([]byte, 20),
	}

	for name, quoted := range cases {
		if _, ok := quotedPort(quoted, false); ok {
			t.Errorf("%s: a truncated quote should not parse", name)
		}
	}
}

// TestQuotedPortRejectsOtherProtocols makes sure a TCP quote is not mistaken
// for a UDP one. They sit at the same offset, so the protocol check is the only
// thing distinguishing them.
func TestQuotedPortIPv6(t *testing.T) {
	// A quoted IPv6 packet: a fixed 40-byte header, then UDP.
	quoted := make([]byte, 48)
	quoted[6] = 17 // next header: UDP
	quoted[7] = 9  // hop limit

	binary.BigEndian.PutUint16(quoted[42:44], 33442)

	port, ok := quotedPort(quoted, true)
	if !ok {
		t.Fatal("an IPv6 UDP quote should be recognised")
	}
	if port != 33442 {
		t.Fatalf("port: got %d, want 33442", port)
	}
}

// TestBuildHopsUsesMinimumAndCountsLoss checks the aggregation of several
// replies at one hop.
func TestBuildHopsUsesMinimumAndCountsLoss(t *testing.T) {
	results := map[int][]probeResult{
		1: {
			{TTL: 1, Address: "192.168.1.1", RTT: 5_000_000},
			{TTL: 1, Address: "192.168.1.1", RTT: 2_000_000},
			{TTL: 1, Address: "192.168.1.1", RTT: 9_000_000},
		},
	}

	hops := buildHops(results, 3)
	if len(hops) != 1 {
		t.Fatalf("expected one hop, got %d", len(hops))
	}

	hop := hops[0]
	// The minimum is the reported RTT: it is the sample least contaminated by
	// queueing delay elsewhere on the path.
	if hop.RTT != 2_000_000 {
		t.Errorf("rtt: got %d, want 2000000 (the minimum)", hop.RTT)
	}
	// The spread is reported so the minimum is not mistaken for the typical case.
	if hop.RTTSpread != 7_000_000 {
		t.Errorf("spread: got %d, want 7000000", hop.RTTSpread)
	}
	if hop.Received != 3 || hop.Sent != 3 || hop.Loss != 0 {
		t.Errorf("all three answered: got %d/%d loss=%v", hop.Received, hop.Sent, hop.Loss)
	}
}

// TestBuildHopsCountsPartialLoss covers a hop where some probes were dropped.
func TestBuildHopsCountsPartialLoss(t *testing.T) {
	results := map[int][]probeResult{
		1: {
			{TTL: 1, Address: "10.0.0.1", RTT: 1_000_000},
			{TTL: 1, Address: "10.0.0.1", RTT: 1_100_000},
		},
	}

	hops := buildHops(results, 3)
	if len(hops) != 1 {
		t.Fatalf("expected one hop, got %d", len(hops))
	}
	// One probe of three was lost, so a third.
	if hops[0].Loss < 0.33 || hops[0].Loss > 0.34 {
		t.Errorf("loss: got %v, want about 0.333", hops[0].Loss)
	}
}

// TestBuildHopsSortsByTTL checks that hops come back in path order regardless of
// map iteration order, which is randomised in Go.
//
// The TTLs are deliberately non-contiguous. A TTL where nothing answered is
// absent rather than padded with a placeholder, so the numbering has gaps by
// design, and the property that holds is monotonic order -- not contiguity.
func TestBuildHopsSortsByTTL(t *testing.T) {
	results := map[int][]probeResult{
		7: {{TTL: 7, Address: "a", RTT: 1}},
		2: {{TTL: 2, Address: "b", RTT: 1}},
		5: {{TTL: 5, Address: "c", RTT: 1}},
		1: {{TTL: 1, Address: "d", RTT: 1}},
	}

	hops := buildHops(results, 1)
	if len(hops) != 4 {
		t.Fatalf("expected four hops, got %d", len(hops))
	}

	want := []int{1, 2, 5, 7}
	for i, hop := range hops {
		if hop.Number != want[i] {
			t.Fatalf("hop %d: got TTL %d, want %d; hops must be in TTL order",
				i, hop.Number, want[i])
		}
		if i > 0 && hops[i-1].Number >= hop.Number {
			t.Fatalf("TTL order broken: %d then %d", hops[i-1].Number, hop.Number)
		}
	}
}

// TestFirstReached checks that the destination's own reply ends the trace.
func TestFirstReached(t *testing.T) {
	results := map[int][]probeResult{
		1: {{TTL: 1, Address: "gateway", RTT: 1}},
		2: {{TTL: 2, Address: "core", RTT: 5}},
		3: {{TTL: 3, Address: "target", RTT: 9, Reached: true}},
		4: {{TTL: 4, Address: "target", RTT: 10, Reached: true}},
	}

	if got := firstReached(results); got != 3 {
		t.Fatalf("firstReached: got %d, want 3", got)
	}

	// With no hop reached, the trace is incomplete rather than wrong, and the
	// zero has to be distinguishable from hop 1.
	noReach := map[int][]probeResult{1: {{TTL: 1, Address: "gateway", RTT: 1}}}
	if got := firstReached(noReach); got != 0 {
		t.Fatalf("firstReached with no destination: got %d, want 0", got)
	}
}

// TestDestinationAnswered distinguishes the destination from a router.
func TestDestinationAnswered(t *testing.T) {
	router := map[int][]probeResult{1: {{TTL: 1, Address: "gateway", RTT: 1}}}
	if destinationAnswered(router, 1) {
		t.Fatal("a router's Time Exceeded is not the destination")
	}

	target := map[int][]probeResult{1: {{TTL: 1, Address: "target", RTT: 1, Reached: true}}}
	if !destinationAnswered(target, 1) {
		t.Fatal("the destination's own reply should count as reaching it")
	}
}

// TestProbePortsAreUnique is the property the whole matching scheme rests on: if
// two probes in flight share a destination port, their replies cannot be told
// apart and one hop's timing can be attributed to another.
func TestProbePortsAreUnique(t *testing.T) {
	seen := map[int]bool{}
	for ttl := 1; ttl <= DefaultMaxHops; ttl++ {
		for probe := 0; probe < DefaultProbes; probe++ {
			port := firstProbePort + ttl*8 + probe
			if port > 65535 {
				t.Fatalf("port %d for ttl=%d probe=%d exceeds the port range", port, ttl, probe)
			}
			if seen[port] {
				t.Fatalf("port %d is used twice, at ttl=%d probe=%d", port, ttl, probe)
			}
			seen[port] = true
		}
	}
}

// TestRecordAndForgetMatchesReplies covers the send table: a reply is only
// attributed to a probe whose port is still in it.
func TestRecordAndForgetMatchesReplies(t *testing.T) {
	tr := &tracer{sent: map[int]pending{}}
	tr.recordSend(33441, 5)

	if ttl := tr.ttlFor(33441); ttl != 5 {
		t.Fatalf("ttlFor: got %d, want 5", ttl)
	}
	// A port that was never sent has no TTL, which must not resolve to a hop.
	if ttl := tr.ttlFor(99999); ttl != 0 {
		t.Fatalf("ttlFor an unknown port: got %d, want 0", ttl)
	}

	tr.forget([]int{33441})
	if _, known := tr.sent[33441]; known {
		t.Fatal("forget should drop the probe, so a late reply is not attributed")
	}
}

// TestResolveTargetRejectsWrongFamily checks that an address of the wrong family
// is reported rather than traced, since the result would not be what was asked
// for.
func TestResolveTargetRejectsWrongFamily(t *testing.T) {
	if _, err := resolveTarget("1.1.1.1", true); err == nil {
		t.Fatal("an IPv4 address should be rejected when IPv6 was requested")
	}
	if _, err := resolveTarget("2606:4700:4700::1111", false); err == nil {
		t.Fatal("an IPv6 address should be rejected when IPv4 was the default")
	}

	got, err := resolveTarget("1.1.1.1", false)
	if err != nil || got != "1.1.1.1" {
		t.Fatalf("resolveTarget: got %q, %v", got, err)
	}
}
