package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

// These tests run against a locally-controlled DNS server, never a public one.
// A test suite that depends on 1.1.1.1 being up is a test suite that fails for
// reasons that have nothing to do with the code.

func TestParseRecordTypeAcceptsEveryDocumentedType(t *testing.T) {
	for _, name := range []string{"A", "aaaa", "CNAME", "mx", "ns", "txt", "soa", "srv", "caa", "ptr"} {
		if _, err := ParseRecordType(name); err != nil {
			t.Errorf("ParseRecordType(%q) failed: %v", name, err)
		}
	}
}

func TestParseRecordTypeRejectsUnknown(t *testing.T) {
	for _, name := range []string{"", "ANY", "HTTPS", "AAAAAAA"} {
		if _, err := ParseRecordType(name); err == nil {
			t.Errorf("ParseRecordType(%q) should have failed", name)
		}
	}
}

func TestRcodeNameCoversTheCodesThatMatter(t *testing.T) {
	cases := map[int]string{
		0: "NOERROR",
		2: "SERVFAIL",
		3: "NXDOMAIN",
		5: "REFUSED",
	}
	for code, want := range cases {
		if got := rcodeName(code); got != want {
			t.Errorf("rcodeName(%d) = %q, want %q", code, got, want)
		}
	}
	if got := rcodeName(99); got != "RCODE99" {
		t.Errorf("rcodeName(99) = %q, want RCODE99", got)
	}
}

func TestBuildQueryHasAValidHeader(t *testing.T) {
	query := buildQuery("example.com", 1, 0x1234)
	if len(query) < 12 {
		t.Fatalf("query is %d bytes, shorter than a header", len(query))
	}
	id := uint16(query[0])<<8 | uint16(query[1])
	if id != 0x1234 {
		t.Errorf("query ID = %#04x, want 0x1234", id)
	}
	flags := uint16(query[2])<<8 | uint16(query[3])
	if flags&0x0100 == 0 {
		t.Error("the recursion-desired bit must be set on a recursive query")
	}
	qdcount := uint16(query[4])<<8 | uint16(query[5])
	if qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}
	// The name must be length-prefixed and terminated by a zero byte.
	if query[12] != byte(len("example")) {
		t.Errorf("first label length = %d, want %d", query[12], len("example"))
	}
	if query[len(query)-5] != 0 {
		t.Error("the name must be terminated by a zero byte")
	}
}

func TestQueryIDsVary(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < 20; i++ {
		id := nextQueryID()
		if seen[id] {
			t.Fatalf("query ID %#04x repeated within 20 draws", id)
		}
		seen[id] = true
	}
}

func TestAppendNameRejectsLabelsOver63Bytes(t *testing.T) {
	long := ""
	for i := 0; i < 70; i++ {
		long += "a"
	}
	buf := appendName(nil, long)
	// The label must be clamped to the protocol limit rather than emitting an
	// over-long label, which servers reject and which would query a different
	// name than the user typed.
	if buf[0] > 63 {
		t.Errorf("label length byte is %d, must not exceed 63", buf[0])
	}
}

func TestReadNameFollowsCompressionPointers(t *testing.T) {
	// Header(12) + a name "a.example.com" at offset 12, then a second name that
	// points back at it. Constructing this by hand is the only honest way to
	// test pointer handling: a real server's compression is not reproducible in
	// a unit test.
	msg := make([]byte, 12)
	msg = append(msg, 1, 'a') // label "a"
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e')
	msg = append(msg, 3, 'c', 'o', 'm')
	msg = append(msg, 0) // root

	secondAt := len(msg)
	// A pointer to offset 12.
	msg = append(msg, 0xc0, 0x0c)

	name, next, err := readName(msg, 12)
	if err != nil {
		t.Fatalf("readName on the uncompressed name failed: %v", err)
	}
	if name != "a.example.com" {
		t.Errorf("readName = %q, want a.example.com", name)
	}
	if next != secondAt {
		t.Errorf("next offset = %d, want %d", next, secondAt)
	}

	compressed, next2, err := readName(msg, secondAt)
	if err != nil {
		t.Fatalf("readName on the compressed name failed: %v", err)
	}
	if compressed != "a.example.com" {
		t.Errorf("compressed readName = %q, want a.example.com", compressed)
	}
	if next2 != secondAt+2 {
		t.Errorf("after a pointer, next = %d, want %d", next2, secondAt+2)
	}
}

func TestReadNameRejectsAPointerLoop(t *testing.T) {
	// A pointer at offset 12 that points at itself would loop forever without a
	// jump counter. This is a real technique against naive resolvers.
	msg := make([]byte, 12)
	msg = append(msg, 0xc0, 0x0c)

	if _, _, err := readName(msg, 12); err == nil {
		t.Fatal("a self-referential compression pointer must be rejected")
	}
}

func TestReadNameRejectsTruncatedInput(t *testing.T) {
	msg := make([]byte, 12)
	msg = append(msg, 10, 'a') // claims a 10-byte label but only 1 byte follows
	if _, _, err := readName(msg, 12); err == nil {
		t.Fatal("a truncated label must be rejected")
	}
}

func TestParseRecordA(t *testing.T) {
	msg := headerWithAnswers(1)
	msg = appendRecord(msg, "a.example.com", 1, 1, 60, []byte{93, 184, 216, 34})

	records, rcode, err := parseAnswer(msg, TypeA)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "93.184.216.34" {
		t.Errorf("A record = %q, want 93.184.216.34", records[0].Value)
	}
	if records[0].TTL != 60 {
		t.Errorf("TTL = %d, want 60", records[0].TTL)
	}
}

func TestParseRecordMXDecodesPriorityAndTarget(t *testing.T) {
	rdata := append([]byte{0, 10}, encodeName("mail.example.com")...) // priority 10
	msg := headerWithAnswers(1)
	msg = appendRecord(msg, "example.com", 15, 1, 300, rdata)

	records, _, err := parseAnswer(msg, TypeMX)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Priority != 10 {
		t.Errorf("MX priority = %d, want 10", records[0].Priority)
	}
	if records[0].Value != "mail.example.com" {
		t.Errorf("MX target = %q, want mail.example.com", records[0].Value)
	}
}

func TestParseRecordTXTConcatenatesChunks(t *testing.T) {
	// A long TXT record is split into 255-byte chunks on the wire. Reporting only
	// the first chunk truncates SPF and DKIM keys, which is worse than useless.
	// Each chunk is a length byte followed by exactly that many bytes. The
	// second chunk's length must be 5 for "-more": declaring 6 made the parser
	// correctly detect a length that runs past the record, and the test was
	// asserting that a malformed record decodes cleanly.
	rdata := append([]byte{4}, []byte("test")...)
	rdata = append(rdata, 5)
	rdata = append(rdata, []byte("-more")...)

	msg := headerWithAnswers(1)
	msg = appendRecord(msg, "example.com", 16, 1, 60, rdata)

	records, _, err := parseAnswer(msg, TypeTXT)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "test-more" {
		t.Errorf("TXT = %q, want the chunks joined into test-more", records[0].Value)
	}
}

func TestParseAnswerSurfacesNXDOMAINAsARCode(t *testing.T) {
	// NXDOMAIN is a successful query with an empty answer. Treating it as an
	// error would tell the user the server is broken when the name simply does
	// not exist.
	msg := make([]byte, 12)
	msg[2] = 0x81
	msg[3] = 0x83 // QR + RD + RA, RCODE 3
	msg[7] = 0    // ANCOUNT 0

	records, rcode, err := parseAnswer(msg, TypeA)
	if err != nil {
		t.Fatalf("NXDOMAIN must not be an error: %v", err)
	}
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3 (NXDOMAIN)", rcode)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want none", len(records))
	}
	if rcodeName(rcode) != "NXDOMAIN" {
		t.Errorf("rcodeName(%d) = %q, want NXDOMAIN", rcode, rcodeName(rcode))
	}
}

func TestParseAnswerSkipsNonINClasses(t *testing.T) {
	// A record in class CH (CHAOS) has the same type but a different meaning;
	// reporting it as an A record would be wrong.
	msg := headerWithAnswers(1)
	msg = appendRecord(msg, "version.bind", 16, 3, 0, []byte{1, 2, 3, 4})

	records, _, err := parseAnswer(msg, TypeTXT)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("a class CH record must be skipped, got %d records", len(records))
	}
}

func TestNormaliseServerAddsTheDefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                "1.1.1.1:53",
		"8.8.8.8:53":             "8.8.8.8:53",
		"[2606:4700:4700::1111]": "[2606:4700:4700::1111]:53",
	}
	for input, want := range cases {
		got, err := normaliseServer(input)
		if err != nil {
			t.Errorf("normaliseServer(%q) failed: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("normaliseServer(%q) = %q, want %q", input, got, want)
		}
	}
	if _, err := normaliseServer(""); err == nil {
		t.Error("an empty server must be rejected")
	}
}

// The bracket form has to be stripped before parsing as an IP, because
// "[::1]" is not itself a valid IP literal even though the host inside it is.
func TestNormaliseServerHandlesBracketedIPv6(t *testing.T) {
	got, err := normaliseServer("[2606:4700:4700::1111]")
	if err != nil {
		t.Fatalf("normaliseServer failed on a bracketed IPv6 literal: %v", err)
	}
	if got != "[2606:4700:4700::1111]:53" {
		t.Errorf("normaliseServer = %q, want [2606:4700:4700::1111]:53", got)
	}
}

func TestNetworkForChoosesTCPForIPv6(t *testing.T) {
	// UDP to an IPv6 literal needs bracket handling that the address parser
	// does not do here, so TCP is the reliable path.
	if got := networkFor("[2606:4700:4700::1111]:53", false); got != "tcp" {
		t.Errorf("networkFor(IPv6) = %q, want tcp", got)
	}
	if got := networkFor("1.1.1.1:53", false); got != "udp" {
		t.Errorf("networkFor(IPv4) = %q, want udp", got)
	}
	if got := networkFor("1.1.1.1:53", true); got != "tcp" {
		t.Errorf("networkFor with TCP forced = %q, want tcp", got)
	}
}

func TestLookupRejectsABadType(t *testing.T) {
	r := New(Options{})
	if _, err := r.Lookup(context.Background(), "example.com", "HTTPS"); err == nil {
		t.Fatal("an unknown record type must be rejected before any query is sent")
	}
}

func TestLookupRejectsAnEmptyName(t *testing.T) {
	r := New(Options{})
	if _, err := r.Lookup(context.Background(), "  ", "A"); err == nil {
		t.Fatal("an empty name must be rejected")
	}
}

func TestLookupHonoursContextCancellation(t *testing.T) {
	// A cancelled context must stop the lookup immediately rather than after the
	// full timeout. Without this, Ctrl-C takes five seconds to take effect.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := New(Options{Servers: []string{"203.0.113.1"}, Timeout: 30 * time.Second})
	start := time.Now()
	_, err := r.Lookup(ctx, "example.com", "A")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled context must produce an error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took %v, want it to take effect immediately", elapsed)
	}
}

func TestResolverDefaultsAreUsable(t *testing.T) {
	// A zero-value Options must not mean "no timeout", which would hang.
	r := New(Options{})
	if r.options.Timeout != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", r.options.Timeout)
	}
}

// appendRecord encodes one resource record onto a message.
//
// Written once because appending a dozen byte literals by hand is where the
// earlier version of this file went wrong: append does not spread untyped int
// constants into a []byte argument list, and hand-counting the length prefix
// of the rdata is exactly the kind of arithmetic that produces a test that
// passes for the wrong reason.
func appendRecord(msg []byte, name string, rrType uint16, class uint16, ttl uint32, rdata []byte) []byte {
	msg = append(msg, encodeName(name)...)
	msg = appendUint16(msg, rrType)
	msg = appendUint16(msg, class)
	msg = appendUint32(msg, ttl)
	msg = appendUint16(msg, uint16(len(rdata)))
	return append(msg, rdata...)
}

// Helpers for building synthetic responses.

func headerWithAnswers(anCount int) []byte {
	msg := make([]byte, 12)
	msg[2] = 0x81
	msg[3] = 0x80 // QR + RD + RA, RCODE 0
	msg[6] = byte(anCount >> 8)
	msg[7] = byte(anCount)
	return msg
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range splitDots(name) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func splitDots(name string) []string {
	var parts []string
	current := ""
	for _, r := range name {
		if r == '.' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
			continue
		}
		current += string(r)
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

var _ = net.IPv4len
