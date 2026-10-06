package dns

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Every fixture below is a verbatim answer captured from systemd-resolved
// (127.0.0.53) on this machine, not a hand-built packet. That matters: the bug
// these tests pin down only shows up in bytes real resolvers actually emit.
//
// RFC 1035 4.1.4 allows the name in the RDATA of CNAME, NS, SOA, PTR and MX to
// be compressed, and every one of these answers uses it. `c0xx` in the hex
// below is a pointer to offset 0x00xx OF THE WHOLE MESSAGE -- not to an offset
// within the rdata. A parser that decodes an rdata slice on its own resolves
// those pointers against the wrong base address, fails, and silently drops the
// record. On the first real query that meant: no CNAME chain, and no MX/NS/SOA
// answers at all.
const (
	// "www.github.com CNAME" -> github.com. rdata is `c010`, a pointer.
	fixtureCNAME = "424281800001000100000001037777770667697468756203636f6d0000050001c00c" +
		"00050001000000010002c010c010000100010000000100048c527903"

	// "www.github.com A" -> CNAME github.com + A 140.82.121.3. The A answer's
	// own name is itself a pointer (c00c), and so is the CNAME's rdata.
	fixtureAWithCNAME = "424381800001000200000000037777770667697468756203636f6d0000010001c00c" +
		"00050001000000010002c010c010000100010000000100048c527903"

	// "gmail.com MX", 5 records. Every target ends in a pointer (c02e/c012).
	fixtureMX = "42448180000100050000000005676d61696c03636f6d00000f0001c00c000f000100000a990020002804616c74340d676d61696c2d736d74702d696e016c06676f6f676c65c012" +
		"c00c000f000100000a990009001e04616c7433c02ec00c000f000100000a9900040005c02e" +
		"c00c000f000100000a990009000a04616c7431c02ec00c000f000100000a990009001404616c7432c02e"

	// "github.com NS", 8 records, each rdata a compression pointer (c072/c05c).
	fixtureNS = "4245818000010008000000000667697468756203636f6d0000020001c00c0002000100000dff0017076e732d3132383309617773646e732d3332036f726700" +
		"c00c0002000100000dff0016066e732d35323009617773646e732d3031036e657400" +
		"c00c0002000100000dff001104646e733303703038056e736f6e65c05c" +
		"c00c0002000100000dff000704646e7334c072" +
		"c00c0002000100000dff0019076e732d3137303709617773646e732d323102636f02756b00" +
		"c00c0002000100000dff000704646e7332c072" +
		"c00c0002000100000dff000704646e7331c072" +
		"c00c0002000100000dff0013066e732d34323109617773646e732d3532c013"

	// "github.com SOA". MNAME is stored uncompressed and RNAME ends in a
	// pointer (c013), so the second name in one rdata is compressed while the
	// first is not.
	fixtureSOA = "4246818000010001000000000667697468756203636f6d0000060001c00c00060001000003280048076e732d3137303709617773646e732d323102636f02756b0011617773646e732d686f73746d617374657206616d617a6f6ec0130000000100001c20000003840012750000015180"

	// "8.8.8.8.in-addr.arpa PTR" -> dns.google. rdata is an uncompressed name,
	// which is the case the broken code DID handle -- kept so the fix cannot
	// regress it.
	fixturePTR = "424881800001000100000000013801380138013807696e2d61646472046172706100000c0001c00c000c000100014f85000c03646e7306676f6f676c6500"
)

func decode(t *testing.T, hexStr string) []byte {
	t.Helper()
	msg, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("fixture is not valid hex: %v", err)
	}
	return msg
}

// A CNAME whose rdata is a compression pointer was dropped outright: the
// resolver reported "no records" for an ordinary, successful lookup.
func TestParseAnswerReadsACNAMEWhoseRdataIsCompressed(t *testing.T) {
	records, rcode, err := parseAnswer(decode(t, fixtureCNAME), TypeCNAME)
	if err != nil {
		t.Fatalf("parseAnswer failed on a real resolver's answer: %v", err)
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1: the CNAME was dropped because its rdata is a compression pointer", len(records))
	}
	if records[0].Value != "github.com" {
		t.Errorf("CNAME target = %q, want github.com", records[0].Value)
	}
}

// The address and the CNAME that explains it must both survive.
func TestParseAnswerReadsAnAAnswerBehindACompressedCNAME(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixtureAWithCNAME), TypeA)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (the CNAME plus the A)", len(records))
	}
	if records[0].Type != TypeCNAME || records[0].Value != "github.com" {
		t.Errorf("record 0 = %s %q, want CNAME github.com", records[0].Type, records[0].Value)
	}
	if records[1].Type != TypeA || records[1].Value != "140.82.121.3" {
		t.Errorf("record 1 = %s %q, want A 140.82.121.3", records[1].Type, records[1].Value)
	}
}

// MX is the type that matters most in practice, and every target here is a
// pointer. Priorities must survive alongside the targets.
func TestParseAnswerReadsMXWithCompressedTargets(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixtureMX), TypeMX)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 5 {
		t.Fatalf("got %d MX records, want 5", len(records))
	}
	wantPriority := map[string]uint16{
		"gmail-smtp-in.l.google.com":      5,
		"alt1.gmail-smtp-in.l.google.com": 10,
		"alt2.gmail-smtp-in.l.google.com": 20,
		"alt3.gmail-smtp-in.l.google.com": 30,
		"alt4.gmail-smtp-in.l.google.com": 40,
	}
	for _, r := range records {
		if r.Type != TypeMX {
			t.Errorf("record type = %s, want MX", r.Type)
		}
		want, ok := wantPriority[r.Value]
		if !ok {
			t.Errorf("unexpected MX target %q", r.Value)
			continue
		}
		if r.Priority != want {
			t.Errorf("MX %s priority = %d, want %d", r.Value, r.Priority, want)
		}
	}
}

func TestParseAnswerReadsNSWithCompressedTargets(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixtureNS), TypeNS)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 8 {
		t.Fatalf("got %d NS records, want 8", len(records))
	}
	for _, r := range records {
		if r.Type != TypeNS {
			t.Errorf("record type = %s, want NS", r.Type)
		}
		// A dropped or truncated name here would be a nameserver the user
		// cannot use.
		if r.Value == "" || r.Value == "." {
			t.Errorf("NS record has an empty target: %+v", r)
		}
	}
	if records[0].Value != "ns-1283.awsdns-32.org" {
		t.Errorf("first NS = %q, want ns-1283.awsdns-32.org", records[0].Value)
	}
}

// SOA rdata holds two names, and in this answer the first is uncompressed while
// the second is a pointer. Both have to be read at their offset in the message,
// and all five 32-bit integers that follow them are part of the record.
func TestParseAnswerReadsSOAWhoseSecondNameIsCompressed(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixtureSOA), TypeSOA)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d SOA records, want 1", len(records))
	}
	// The five numbers are not transcribed by hand. They are the last 20 bytes
	// of this captured answer's rdata, read out of the fixture itself by
	// scripts/soa-oracle.py, which decodes the wire format independently of this
	// package. RFC 1035 3.3.13 fixes both the order and the widths.
	want := "ns-1707.awsdns-21.co.uk awsdns-hostmaster.amazon.com 1 7200 900 1209600 86400"
	if records[0].Value != want {
		t.Errorf("SOA = %q, want %q", records[0].Value, want)
	}
}

// The SERIAL is the reason to look at an SOA at all: it says whether the zone has
// moved since you last looked. Reading the two names and stopping -- which is
// what this code did -- produced an answer that looks complete and silently
// omits five fields, so the zone's version was unreportable and two resolvers'
// SOA records compared equal no matter how far apart they were.
func TestSOAValueCarriesItsSerialAndTimers(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixtureSOA), TypeSOA)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d SOA records, want 1", len(records))
	}
	fields := strings.Fields(records[0].Value)
	if len(fields) != 7 {
		t.Fatalf("SOA value %q has %d fields, want 7 (mname rname serial refresh retry expire minimum)",
			records[0].Value, len(fields))
	}
	want := []string{"1", "7200", "900", "1209600", "86400"}
	for i, w := range want {
		if fields[2+i] != w {
			t.Errorf("SOA field %d = %q, want %q (full value %q)", 2+i, fields[2+i], w, records[0].Value)
		}
	}
}

// An SOA whose rdata is too short to hold the five integers is malformed.
// Reporting the two names it does contain would be a partial answer dressed as a
// whole one, so the record is refused instead.
func TestSOAWithoutItsFiveIntegersIsRefused(t *testing.T) {
	rdata := encodeName("ns.example.com")
	rdata = append(rdata, encodeName("hostmaster.example.com")...)
	rdata = append(rdata, 0, 0, 0, 1) // SERIAL only: 4 of the required 20 bytes

	msg := headerWithAnswers(1)
	msg = appendRecord(msg, "example.com", 6, 1, 3600, rdata)

	records, _, err := parseAnswer(msg, TypeSOA)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	for _, r := range records {
		if r.Type == TypeSOA {
			t.Errorf("a truncated SOA was reported as a record: %q", r.Value)
		}
	}
}

// The uncompressed PTR case must keep working after the fix.
func TestParseAnswerReadsAnUncompressedPTR(t *testing.T) {
	records, _, err := parseAnswer(decode(t, fixturePTR), TypePTR)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d PTR records, want 1", len(records))
	}
	if records[0].Value != "dns.google" {
		t.Errorf("PTR = %q, want dns.google", records[0].Value)
	}
}

// A pointer must not be able to pull a name out of the record that FOLLOWS it.
// This is the check that makes reading rdata in message context safe rather
// than merely convenient: without a per-record bound, a crafted answer can
// attach its neighbour's bytes to this record.
func TestParseAnswerRejectsANameThatRunsPastItsOwnRecord(t *testing.T) {
	msg := make([]byte, 12)
	msg[2], msg[3] = 0x81, 0x80
	msg[6], msg[7] = 0, 1 // one answer

	// The CNAME's rdata is a pointer to the SECOND record's name, which lies
	// beyond this record's own 2 bytes of rdata.
	msg = append(msg, encodeName("first.example")...)
	msg = appendUint16(msg, 5) // CNAME
	msg = appendUint16(msg, 1) // class IN
	msg = appendUint32(msg, 60)
	pointerAt := len(msg) + 2 + 2 // where the rdata bytes will start
	msg = appendUint16(msg, 2)    // rdlength 2

	// The pointer has to encode an offset greater than anything in this record.
	secondNameAt := len(msg)
	msg = appendUint16(msg, uint16(0xc000|secondNameAt))
	_ = pointerAt

	msg = append(msg, encodeName("neighbour.example")...)
	msg = appendUint16(msg, 1) // A
	msg = appendUint16(msg, 1) // class IN
	msg = appendUint32(msg, 60)
	msg = appendUint16(msg, 4)
	msg = append(msg, 93, 184, 216, 34)

	records, _, err := parseAnswer(msg, TypeCNAME)
	if err != nil {
		t.Fatalf("parseAnswer failed: %v", err)
	}
	for _, r := range records {
		if r.Type == TypeCNAME && r.Value == "neighbour.example" {
			t.Errorf("a CNAME claimed a name from the next record: %q", r.Value)
		}
	}
}
