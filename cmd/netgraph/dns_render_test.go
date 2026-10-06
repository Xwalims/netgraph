package main

import (
	"strings"
	"testing"

	"github.com/Xwalims/netgraph/internal/dns"
)

// A zero priority is the BEST priority, not a missing one. youtube.com's only
// MX record is "0 smtp.google.com", and the renderer printed it as a bare
// hostname with no priority at all -- indistinguishable from a record whose
// priority it had simply chosen not to show. Reading the digits with a
// "if priority != 0" test conflates "this field does not apply to this type" with
// "this field applies and is zero", so the one MX record that matters most came
// out looking like the least important field on the line was absent.
func TestMXAlwaysPrintsItsPriorityEvenWhenZero(t *testing.T) {
	records := []dns.Record{{
		Type:     dns.TypeMX,
		Value:    "smtp.google.com",
		Priority: 0,
		TTL:      44,
		TTLKnown: true,
	}}

	out := capturePrintRecords(t, &dns.Result{
		Name:     "youtube.com",
		Type:     dns.TypeMX,
		Response: "NOERROR",
		Records:  records,
	}, dnsFlags{})

	if !strings.Contains(out, "priority=0") {
		t.Errorf("a zero-priority MX was printed without its priority:\n%s", out)
	}
	if !strings.Contains(out, "smtp.google.com") {
		t.Errorf("the target went missing:\n%s", out)
	}
}

// The RFC 2782 "this service is not available here" record is "0 0 0 .". Every
// one of those numbers is zero, so all three were dropped and the line came out
// as a bare "." -- which reads like a usable target rather than the explicit
// statement that no port is offered. This is the case that makes the bug
// dangerous rather than merely untidy: the record exists precisely to say "there
// is nothing here", and the output said nothing at all.
func TestSRVAlwaysPrintsPriorityWeightAndPortEvenWhenZero(t *testing.T) {
	records := []dns.Record{{
		Type:     dns.TypeSRV,
		Value:    ".",
		Priority: 0,
		Weight:   0,
		Port:     0,
		TTL:      43200,
		TTLKnown: true,
	}}

	out := capturePrintRecords(t, &dns.Result{
		Name:     "_imap._tcp.gmail.com",
		Type:     dns.TypeSRV,
		Response: "NOERROR",
		Records:  records,
	}, dnsFlags{})

	for _, want := range []string{"priority=0", "weight=0", "port=0"} {
		if !strings.Contains(out, want) {
			t.Errorf("a zero-valued SRV field was dropped (%q missing):\n%s", want, out)
		}
	}
}

// An SRV with real numbers must keep showing all three, and an MX with a real
// priority must keep showing it. The fix narrows when the fields print, so this
// is what stops it from over-correcting into silence.
func TestNonZeroSRVAndMXNumbersStillPrint(t *testing.T) {
	srvOut := capturePrintRecords(t, &dns.Result{
		Name: "_sip._udp.sip.voice.google.com",
		Type: dns.TypeSRV,
		Records: []dns.Record{{
			Type: dns.TypeSRV, Value: "sip-anycast-1.voice.google.com",
			Priority: 10, Weight: 1, Port: 5060, TTL: 300, TTLKnown: true,
		}},
	}, dnsFlags{})
	for _, want := range []string{"priority=10", "weight=1", "port=5060"} {
		if !strings.Contains(srvOut, want) {
			t.Errorf("%q missing from SRV line:\n%s", want, srvOut)
		}
	}

	mxOut := capturePrintRecords(t, &dns.Result{
		Name: "reddit.com",
		Type: dns.TypeMX,
		Records: []dns.Record{{
			Type: dns.TypeMX, Value: "aspmx.l.google.com",
			Priority: 1, TTL: 45, TTLKnown: true,
		}},
	}, dnsFlags{})
	if !strings.Contains(mxOut, "priority=1") {
		t.Errorf("a non-zero MX priority went missing:\n%s", mxOut)
	}
}

// A and AAAA records have no priority, weight or port. Printing a fictional
// zero for them would be a different lie in the opposite direction.
func TestAddressRecordsGainNoInventedFields(t *testing.T) {
	out := capturePrintRecords(t, &dns.Result{
		Name:     "example.com",
		Type:     dns.TypeA,
		Response: "NOERROR",
		Records: []dns.Record{{
			Type: dns.TypeA, Value: "8.6.112.5", TTL: 299, TTLKnown: true,
		}},
	}, dnsFlags{})

	for _, unwanted := range []string{"priority=", "weight=", "port="} {
		if strings.Contains(out, unwanted) {
			t.Errorf("an A record grew a field it does not have (%q):\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "8.6.112.5") {
		t.Errorf("the address went missing:\n%s", out)
	}
}

// The SOA value carries five 32-bit integers after the two names. Rendering it
// without them produced output that looks like a complete SOA and is not one,
// so this pins the full seven-field value reaching the renderer intact.
func TestSOAReachesTheRendererWithAllSevenFields(t *testing.T) {
	out := capturePrintRecords(t, &dns.Result{
		Name:     "debian.org",
		Type:     dns.TypeSOA,
		Response: "NOERROR",
		Records: []dns.Record{{
			Type: dns.TypeSOA,
			Value: "denis.debian.org hostmaster.debian.org 2026100611 1800 600 1814400 600",
			TTL: 458, TTLKnown: true,
		}},
	}, dnsFlags{})

	for _, want := range []string{"denis.debian.org", "hostmaster.debian.org", "2026100611", "1814400"} {
		if !strings.Contains(out, want) {
			t.Errorf("SOA field %q did not reach the output:\n%s", want, out)
		}
	}
}

// dnsJSONValue is what --json publishes. It dropped MX priority and the whole of
// the SRV triple, so a script consuming the JSON had no way to tell a primary
// mail exchanger from a fallback, or which port an SRV names.
func TestJSONValueCarriesTheNumbersThatMakeAMXUsable(t *testing.T) {
	got := dnsJSONValue(dns.Record{Type: dns.TypeMX, Value: "smtp.google.com", Priority: 0})
	if got != "0 smtp.google.com" {
		t.Errorf("MX JSON value = %q, want \"0 smtp.google.com\"", got)
	}

	got = dnsJSONValue(dns.Record{
		Type: dns.TypeSRV, Value: "sip-anycast-1.voice.google.com",
		Priority: 10, Weight: 1, Port: 5060,
	})
	if got != "10 1 5060 sip-anycast-1.voice.google.com" {
		t.Errorf("SRV JSON value = %q, want \"10 1 5060 sip-anycast-1.voice.google.com\"", got)
	}
}

// An address record has no numbers, so the JSON value stays exactly the address.
// Changing this would break every consumer of the common case to fix the rare one.
func TestJSONValueLeavesAnAddressAlone(t *testing.T) {
	got := dnsJSONValue(dns.Record{Type: dns.TypeA, Value: "8.6.112.5"})
	if got != "8.6.112.5" {
		t.Errorf("A JSON value = %q, want 8.6.112.5 unchanged", got)
	}
}
